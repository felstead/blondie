//! blondie is a rust library to do callstack sampling of a process on windows.
//!
//! You can use [`trace_command`] to execute and sample an [`std::process::Command`].
//!
//! Or you can use [`trace_child`] to start tracing an [`std::process::Child`].
//! You can also trace an arbitrary process using [`trace_pid`].

#![allow(clippy::field_reassign_with_default)]

// Module declarations
mod event_trace_props;
mod helpers;
mod results;
mod trace_context;

// Std imports
use std::ffi::OsString;
use std::io::{Read, Write};
use std::mem::size_of;
use std::path::PathBuf;
use std::ptr::{addr_of, addr_of_mut};

// External imports
use object::Object;
use windows::core::PCSTR;
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    TraceSampledProfileIntervalInfo, TraceSetInformation, KERNEL_LOGGER_NAMEA,
    TRACE_PROFILE_INTERVAL,
};
use windows::Win32::System::SystemInformation::{GetVersionExA, OSVERSIONINFOA};
use windows::Win32::System::Threading::{SetThreadPriority, WaitForSingleObject, CREATE_SUSPENDED};

use pdb_addr2line::{pdb::PDB, ContextPdbData};

// Local imports
use crate::event_trace_props::*;
use crate::helpers::*;

// Local imports that we want to export
pub use crate::results::*;
pub use crate::trace_context::*;

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

/// Trace an existing child process based only on its process ID (pid).
/// It is recommended that you use `trace_command` instead, since it suspends the process on creation
/// and only resumes it after the trace has started, ensuring that all samples are captured.
pub fn trace_pid(process_id: u32, kernel_stacks: bool) -> Result<CollectionResults> {
    let mut ctx = trace_from_process_id(process_id, false, kernel_stacks)?;
    ctx.stop_trace_wait()?;
    Ok(CollectionResults(*ctx))
}
/// Trace an existing child process.
/// It is recommended that you use `trace_command` instead, since it suspends the process on creation
/// and only resumes it after the trace has started, ensuring that all samples are captured.
pub fn trace_child(process: std::process::Child, kernel_stacks: bool) -> Result<CollectionResults> {
    let mut ctx = trace_from_process_id(process.id(), false, kernel_stacks)?;
    ctx.stop_trace_wait()?;
    Ok(CollectionResults(*ctx))
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

    let res =
        trace_from_process_id(proc.id(), true, kernel_stacks);

    if res.is_err() {
        // Kill the suspended process if we had some kind of error
        let _ = proc.kill();
        Err(res.err().unwrap())
    } else {
        let mut ctx = res.unwrap();
        ctx.stop_trace_wait()?;
        Ok(CollectionResults(*ctx))
    }
}

/// Initiates a trace against the provided process id.  Note that stop_trace_immediate or stop_trace_wait must be called on the returned context
/// to complete the trace and get the results.
/// SAFETY: is_suspended must only be true if `target_process` is suspended
fn trace_from_process_id(
    target_process_id: u32,
    is_suspended: bool,
    kernel_stacks: bool,
) -> Result<Box<TraceContext>> {
    let mut winver_info = OSVERSIONINFOA::default();
    winver_info.dwOSVersionInfoSize = size_of::<OSVERSIONINFOA>() as u32;
    let ret = unsafe { GetVersionExA(&mut winver_info) };
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
        let ret = unsafe {
            TraceSetInformation(
                None,
                // The value is supported on Windows 8, Windows Server 2012, and later.
                TraceSampledProfileIntervalInfo,
                addr_of!(interval).cast(),
                size_of::<TRACE_PROFILE_INTERVAL>() as u32,
            )
        };
        if ret != ERROR_SUCCESS {
            return Err(get_last_error("TraceSetInformation interval"));
        }
    }

    // Create the context and start the trace
    let target_proc_handle = unsafe { handle_from_process_id(target_process_id)? };
    println!("target_proc_handle: {:?}", target_proc_handle);

    //TODO: Do we need to Box the context?
    let mut context =
        Box::new(unsafe { TraceContext::new(target_proc_handle, target_process_id, kernel_stacks)? });
    context.start_trace()?;

    // Resume the suspended process
    if is_suspended {
        // TODO: Do something less gross here
        // std Command/Child do not expose the main thread handle or id, so we can't easily call ResumeThread
        // Therefore, we call the undocumented NtResumeProcess. We should probably manually call CreateProcess.
        // Now that https://github.com/rust-lang/rust/issues/96723 is merged, we could use that on nightly
        unsafe {
            let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA(PCSTR(
                "ntdll.dll\0".as_ptr(),
            ))
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
    }
    Ok(context)
}
