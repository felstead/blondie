//! blondie is a rust library to do callstack sampling of a process on windows.
//!
//! You can use [`trace_command`] to execute and sample an [`std::process::Command`].
//!
//! Or you can use [`trace_child`] to start tracing an [`std::process::Child`].
//! You can also trace an arbitrary process using [`trace_pid`].

#![allow(clippy::field_reassign_with_default)]

// Module declarations
mod event_trace_props;
mod trace_context;
mod results;

// Std imports
use std::ffi::OsString;
use std::io::{Read, Write};
use std::mem::size_of;
use std::path::PathBuf;
use std::ptr::{addr_of, addr_of_mut};

// External imports
use object::Object;
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_SUCCESS, HANDLE, WIN32_ERROR};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES,
};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageA, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows::Win32::System::Diagnostics::Etw::{
    TraceSampledProfileIntervalInfo, TraceSetInformation, KERNEL_LOGGER_NAMEA,
    TRACE_PROFILE_INTERVAL,
};
use windows::Win32::System::SystemInformation::{GetVersionExA, OSVERSIONINFOA};
use windows::Win32::System::SystemServices::SE_SYSTEM_PROFILE_NAME;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, SetThreadPriority, WaitForSingleObject,
    CREATE_SUSPENDED, PROCESS_ALL_ACCESS,
};

use pdb_addr2line::{pdb::PDB, ContextPdbData};

// Local imports
use crate::event_trace_props::*;

// Local imports that we want to export
pub use crate::trace_context::*;
pub use crate::results::*;

// Constants
pub const KERNEL_LOGGER_NAMEA_LEN: usize = unsafe {
    let mut ptr = KERNEL_LOGGER_NAMEA.0;
    let mut len = 0;
    while *ptr != 0 {
        len += 1;
        ptr = ptr.add(1);
    }
    len
};

// msdn says 192 but I got some that were bigger
//const MAX_STACK_DEPTH: usize = 192;
const MAX_STACK_DEPTH: usize = 200;

#[derive(Debug)]
pub enum Error {
    /// Blondie requires administrator privileges
    NotAnAdmin,
    /// Error writing to the provided Writer
    Write(std::io::Error),
    /// Error spawning a suspended process
    SpawnErr(std::io::Error),
    /// Error waiting for child, abandoned
    WaitOnChildErrAbandoned,
    /// Error waiting for child, timed out
    WaitOnChildErrTimeout,
    /// A call to a windows API function returned an error and we didn't know how to handle it
    Other(WIN32_ERROR, String, &'static str),
    /// We require Windows 7 or greater
    UnsupportedOsVersion,
    /// This should never happen
    UnknownError,
}
type Result<T> = std::result::Result<T, Error>;
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Write(err)
    }
}

pub(crate) fn get_last_error(extra: &'static str) -> Error {
    const BUF_LEN: usize = 1024;
    let mut buf = [0u8; BUF_LEN];
    let code = unsafe { GetLastError() };
    let chars_written = unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            code.0,
            0,
            PSTR(buf.as_mut_ptr()),
            BUF_LEN as u32,
            None,
        )
    };
    assert!(chars_written != 0);
    let code_str = unsafe {
        std::ffi::CStr::from_ptr(buf.as_ptr().cast())
            .to_str()
            .unwrap_or("Invalid utf8 in error")
    };
    Error::Other(code, code_str.to_string(), extra)
}

/// A wrapper around `OpenProcess` that returns a handle with all access rights
unsafe fn handle_from_process_id(process_id: u32) -> Result<HANDLE> {
    match OpenProcess(PROCESS_ALL_ACCESS, false, process_id) {
        Ok(handle) => Ok(handle),
        Err(_) => Err(get_last_error("handle_from_process_id")),
    }
}

unsafe fn wait_for_process_by_handle(handle: HANDLE) -> Result<()> {
    let ret = WaitForSingleObject(handle, 0xFFFFFFFF);
    match ret.0 {
        0 => Ok(()),
        0x00000080 => Err(Error::WaitOnChildErrAbandoned),
        0x00000102 => Err(Error::WaitOnChildErrTimeout),
        _ => Err(get_last_error("wait_for_process_by_handle")),
    }
}

fn acquire_privileges() -> Result<()> {
    let mut privs = TOKEN_PRIVILEGES::default();
    privs.PrivilegeCount = 1;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if unsafe {
        LookupPrivilegeValueW(None, SE_SYSTEM_PROFILE_NAME, &mut privs.Privileges[0].Luid).0 == 0
    } {
        return Err(get_last_error("acquire_privileges LookupPrivilegeValueA"));
    }
    let mut pt = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut pt).0 == 0 } {
        return Err(get_last_error("OpenProcessToken"));
    }
    let adjust = unsafe { AdjustTokenPrivileges(pt, false, Some(addr_of!(privs)), 0, None, None) };
    if adjust.0 == 0 {
        let err = Err(get_last_error("AdjustTokenPrivileges"));
        unsafe {
            CloseHandle(pt);
        }
        return err;
    }
    let ret = unsafe { CloseHandle(pt) };
    if ret.0 == 0 {
        return Err(get_last_error("acquire_privileges CloseHandle"));
    }
    let status = unsafe { GetLastError() };
    if status != ERROR_SUCCESS {
        return Err(Error::NotAnAdmin);
    }
    Ok(())
}

/// SAFETY: is_suspended must only be true if `target_process` is suspended
unsafe fn trace_from_process_id(
    target_process_id: u32,
    is_suspended: bool,
    kernel_stacks: bool,
) -> Result<TraceContext> {
    let mut winver_info = OSVERSIONINFOA::default();
    winver_info.dwOSVersionInfoSize = size_of::<OSVERSIONINFOA>() as u32;
    let ret = GetVersionExA(&mut winver_info);
    if ret.0 == 0 {
        return Err(get_last_error("TraceSetInformation interval"));
    }
    // If we're not win7 or more, return unsupported
    // https://docs.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
    if winver_info.dwMajorVersion < 6
        || (winver_info.dwMajorVersion == 6 && winver_info.dwMinorVersion == 0)
    {
        return Err(Error::UnsupportedOsVersion);
    }
    acquire_privileges()?;

    // Set the sampling interval
    // Only for Win8 or more
    if winver_info.dwMajorVersion > 6
        || (winver_info.dwMajorVersion == 6 && winver_info.dwMinorVersion >= 2)
    {
        let mut interval = TRACE_PROFILE_INTERVAL::default();
        // TODO: Parameter?
        interval.Interval = (1000000000 / 8000) / 100;
        let ret = TraceSetInformation(
            None,
            // The value is supported on Windows 8, Windows Server 2012, and later.
            TraceSampledProfileIntervalInfo,
            addr_of!(interval).cast(),
            size_of::<TRACE_PROFILE_INTERVAL>() as u32,
        );
        if ret != ERROR_SUCCESS {
            return Err(get_last_error("TraceSetInformation interval"));
        }
    }

    // Create the context and start the trace
    let target_proc_handle = handle_from_process_id(target_process_id)?;

    //TODO: Do we need to Box the context?
    let mut context = TraceContext::new(target_proc_handle, target_process_id, kernel_stacks)?;
    context.start_trace()?;

    // Resume the suspended process
    if is_suspended {
        // TODO: Do something less gross here
        // std Command/Child do not expose the main thread handle or id, so we can't easily call ResumeThread
        // Therefore, we call the undocumented NtResumeProcess. We should probably manually call CreateProcess.
        // Now that https://github.com/rust-lang/rust/issues/96723 is merged, we could use that on nightly
        let ntdll =
            windows::Win32::System::LibraryLoader::GetModuleHandleA(PCSTR("ntdll.dll\0".as_ptr()))
                .expect("Could not find ntdll.dll");
        #[allow(non_snake_case)]
        let NtResumeProcess = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            PCSTR("NtResumeProcess\0".as_ptr()),
        )
        .expect("Could not find NtResumeProcess in ntdll.dll");
        #[allow(non_snake_case)]
        let NtResumeProcess: extern "system" fn(isize) -> i32 =
            std::mem::transmute(NtResumeProcess);
        NtResumeProcess(target_proc_handle.0);
    }

    // Wait for it to end
    wait_for_process_by_handle(target_proc_handle)?;

    // This completes the tracing process and unblocks the processing
    context.stop_trace()?;

    Ok(context)
}

/// Trace an existing child process based only on its process ID (pid).
/// It is recommended that you use `trace_command` instead, since it suspends the process on creation
/// and only resumes it after the trace has started, ensuring that all samples are captured.
pub fn trace_pid(process_id: u32, kernel_stacks: bool) -> Result<CollectionResults> {
    let res = unsafe { trace_from_process_id(process_id, false, kernel_stacks) };
    res.map(CollectionResults)
}
/// Trace an existing child process.
/// It is recommended that you use `trace_command` instead, since it suspends the process on creation
/// and only resumes it after the trace has started, ensuring that all samples are captured.
pub fn trace_child(process: std::process::Child, kernel_stacks: bool) -> Result<CollectionResults> {
    let res = unsafe { trace_from_process_id(process.id(), false, kernel_stacks) };
    res.map(CollectionResults)
}
/// Execute `command` and trace it, periodically collecting call stacks.
/// The trace also tracks dlls and exes loaded by the process and loads the debug info for
/// them, if it can find it. The debug info is used to resolve addresses to symbol names and
/// is unloaded on TraceContext Drop.
pub fn trace_command(
    mut command: std::process::Command,
    kernel_stacks: bool,
) -> Result<CollectionResults> {
    use std::os::windows::process::CommandExt;

    // Create the target process suspended
    // TODO: Preserve existing flags instead of stomping them
    let mut proc = command
        .creation_flags(CREATE_SUSPENDED.0)
        .spawn()
        .map_err(Error::SpawnErr)?;
    let res = unsafe { trace_from_process_id(proc.id(), true, kernel_stacks) };
    if res.is_err() {
        // Kill the suspended process if we had some kind of error
        let _ = proc.kill();
    }
    res.map(CollectionResults)
}

