// Std imports
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

// External imports
use windows::core::{GUID, PSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE};

use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceA, OpenTraceA, ProcessTrace, StartTraceA, TraceSetInformation,
    TraceStackTracingInfo, CLASSIC_EVENT_ID, CONTROLTRACE_HANDLE, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEA, KERNEL_LOGGER_NAMEA,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
    PROCESS_TRACE_MODE_REAL_TIME,
};
use windows::Win32::System::Threading::{GetCurrentThread, THREAD_PRIORITY_TIME_CRITICAL};

// Local imports
use crate::*;

// https://docs.microsoft.com/en-us/windows/win32/etw/image-load
#[allow(non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct ImageLoadEvent {
    ImageBase: usize,
    ImageSize: usize,
    ProcessId: u32,
    ImageCheckSum: u32,
    TimeDateStamp: u32,
    Reserved0: u32,
    DefaultBase: usize,
    Reserved1: u32,
    Reserved2: u32,
    Reserved3: u32,
    Reserved4: u32,
}

/// map[array_of_stacktrace_addrs] = sample_count
type StackMap = rustc_hash::FxHashMap<[u64; MAX_STACK_DEPTH], u64>;
pub struct TraceContext {
    target_process_handle: HANDLE,
    stack_counts_hashmap: StackMap,
    target_proc_pid: u32,
    trace_running: AtomicBool,
    show_kernel_samples: bool,

    /// (image_path, image_base, image_size)
    image_paths: Vec<(OsString, u64, u64)>,

    // ETW stuff
    event_trace_props: EventTraceProps,
    thread_receiver: Option<std::sync::mpsc::Receiver<()>>,
}

impl TraceContext {
    // Getters
    pub fn get_stack_counts_hashmap(&self) -> &StackMap {
        &self.stack_counts_hashmap
    }

    pub fn get_image_paths(&self) -> &[(OsString, u64, u64)] {
        &self.image_paths
    }

    pub fn should_show_kernel_samples(&self) -> bool {
        self.show_kernel_samples
    }

    /// The Context takes ownership of the handle.
    /// # Safety
    ///  - target_process_handle must be a valid process handle.
    ///  - target_proc_id must be the id of the process.
    pub unsafe fn new(
        target_process_handle: HANDLE,
        target_proc_pid: u32,
        kernel_stacks: bool,
    ) -> Result<Self> {
        Ok(Self {
            target_process_handle,
            stack_counts_hashmap: Default::default(),
            target_proc_pid,
            trace_running: AtomicBool::new(false),
            show_kernel_samples: std::env::var("BLONDIE_KERNEL")
                .map(|value| {
                    let upper = value.to_uppercase();
                    ["Y", "YES", "TRUE"].iter().any(|truthy| &upper == truthy)
                })
                .unwrap_or(kernel_stacks),
            image_paths: Vec::with_capacity(1024),
            event_trace_props: EventTraceProps::new(),
            thread_receiver: None,
        })
    }

    /// Used to initiate the trace.  No results will be recorded until `stop_trace` is called.
    pub fn start_trace(&mut self) -> Result<()> {
        self.event_trace_props.stop_existing()?;
        // Start kernel trace session
        let mut trace_session_handle: CONTROLTRACE_HANDLE = Default::default();
        {
            let start_retcode = unsafe {
                StartTraceA(
                    addr_of_mut!(trace_session_handle),
                    KERNEL_LOGGER_NAMEA,
                    addr_of_mut!(self.event_trace_props) as *mut _,
                )
            };
            if start_retcode != ERROR_SUCCESS {
                return Err(get_last_error("StartTraceA"));
            }
        }

        // Enable stack tracing
        {
            let mut stack_event_id = CLASSIC_EVENT_ID::default();
            // GUID from https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
            let perfinfo_guid = GUID {
                data1: 0xce1dbfb4,
                data2: 0x137e,
                data3: 0x4da6,
                data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
            };
            stack_event_id.EventGuid = perfinfo_guid;
            stack_event_id.Type = 46; // Sampled profile event
            let enable_stacks_retcode = unsafe {
                TraceSetInformation(
                    trace_session_handle,
                    TraceStackTracingInfo,
                    addr_of!(stack_event_id).cast(),
                    size_of::<CLASSIC_EVENT_ID>() as u32,
                )
            };
            if enable_stacks_retcode != ERROR_SUCCESS {
                return Err(get_last_error("TraceSetInformation stackwalk"));
            }
        }

        // Set up logging
        let mut log = EVENT_TRACE_LOGFILEA::default();
        log.LoggerName = PSTR(KERNEL_LOGGER_NAMEA.as_ptr() as *mut _);
        log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
            | PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        log.Context = addr_of_mut!(*self) as *mut _;
        log.Anonymous2.EventRecordCallback = Some(TraceContext::event_record_callback);

        // Open the trace
        let trace_processing_handle = unsafe { OpenTraceA(&mut log) };
        if trace_processing_handle.0 == INVALID_HANDLE_VALUE.0 as u64 {
            return Err(get_last_error("OpenTraceA processing"));
        }

        // Start the processing thread and wait for it to start
        let (sender, receiver) = std::sync::mpsc::channel();
        // Store the receiver on the object so we can hear back from it when it's done
        self.thread_receiver = Some(receiver);
        std::thread::spawn(move || {
            let ret = unsafe {
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

                // This blocks until ControlTraceA is called from self.process_trace
                ProcessTrace(&[trace_processing_handle], None, None);
                CloseTrace(trace_processing_handle)
            };

            if ret != ERROR_SUCCESS {
                panic!("Error closing trace");
            }
            sender.send(()).unwrap();
        });

        // Wait until we know for sure the trace is running
        while !self.trace_running.load(Ordering::Relaxed) {
            std::hint::spin_loop();
        }

        // At this point, the trace is running
        Ok(())
    }

    /// Stops the trace and collects the results, irrespective of whether or not the process is exited
    pub fn stop_trace_immediate(&mut self) -> Result<()> {
        // This unblocks ProcessTrace
        let ret = unsafe {
            ControlTraceA(
                <CONTROLTRACE_HANDLE as Default>::default(),
                KERNEL_LOGGER_NAMEA,
                addr_of_mut!(self.event_trace_props) as *mut _,
                EVENT_TRACE_CONTROL_STOP,
            )
        };

        if ret != ERROR_SUCCESS {
            return Err(get_last_error("ControlTraceA STOP ProcessTrace"));
        }
        // Block until processing thread is done
        // (Safeguard to make sure we don't deallocate the context before the other thread finishes using it)
        if self.thread_receiver.as_ref().unwrap().recv().is_err() {
            return Err(Error::UnknownError);
        }

        if self.show_kernel_samples {
            let kernel_module_paths = list_kernel_modules();
            self.image_paths.extend(
                kernel_module_paths
                    .into_iter()
                    .map(|(path, image_base, image_size)| (path, image_base, image_size)),
            );
        }

        Ok(())
    }

    /// Blocks until the process is stopped, then completes the trace
    pub fn stop_trace_wait(&mut self) -> Result<()> {
        println!("WAITING");

        println!("SELF: {:?}", addr_of!(*self));

        println!("target_proc_handle: {:?}", &self.target_process_handle);
        let ret = unsafe { WaitForSingleObject(self.target_process_handle, 0xFFFFFFFF) };
        println!("DONE");
        match ret.0 {
            0 => self.stop_trace_immediate(),
            0x00000080 => Err(Error::WaitOnChildErrAbandoned),
            0x00000102 => Err(Error::WaitOnChildErrTimeout),
            _ => Err(get_last_error("stop_trace_wait")),
        }
    }

    // This is the record collection callback passed into the tracing function
    unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
        let provider_guid_data1 = (*record).EventHeader.ProviderId.data1;
        let event_opcode = (*record).EventHeader.EventDescriptor.Opcode;
        let context = &mut *(*record).UserContext.cast::<TraceContext>();
        context.trace_running.store(true, Ordering::Relaxed);

        println!("ThreadID: {:?}", thread::current().id());

        const EVENT_TRACE_TYPE_LOAD: u8 = 10;
        if event_opcode == EVENT_TRACE_TYPE_LOAD {
            let event = (*record).UserData.cast::<ImageLoadEvent>().read_unaligned();
            if event.ProcessId != context.target_proc_pid {
                // Ignore dlls for other processes
                return;
            }
            let filename_p = (*record)
                .UserData
                .cast::<ImageLoadEvent>()
                .offset(1)
                .cast::<u16>();
            let filename_os_string = OsString::from_wide(std::slice::from_raw_parts(
                filename_p,
                ((*record).UserDataLength as usize - size_of::<ImageLoadEvent>()) / 2,
            ));
            context.image_paths.push((
                filename_os_string,
                event.ImageBase as u64,
                event.ImageSize as u64,
            ));

            return;
        }

        // From https://docs.microsoft.com/en-us/windows/win32/etw/stackwalk
        let stackwalk_guid_data1 = 0xdef2fe46;
        let stackwalk_event_type = 32;
        if event_opcode != stackwalk_event_type || stackwalk_guid_data1 != provider_guid_data1 {
            // Ignore events other than stackwalk or dll load
            return;
        }
        let ud_p = (*record).UserData;
        let _timestamp = ud_p.cast::<u64>().read_unaligned();
        let proc = ud_p.cast::<u32>().offset(2).read_unaligned();
        let _thread = ud_p.cast::<u32>().offset(3).read_unaligned();
        if proc != context.target_proc_pid {
            // Ignore stackwalks for other processes
            return;
        }

        let stack_depth_32 = ((*record).UserDataLength - 16) / 4;
        let stack_depth_64 = stack_depth_32 / 2;
        let stack_depth = if size_of::<usize>() == 8 {
            stack_depth_64
        } else {
            stack_depth_32
        };

        let mut tmp = vec![];
        let mut stack_addrs = if size_of::<usize>() == 8 {
            std::slice::from_raw_parts(ud_p.cast::<u64>().offset(2), stack_depth as usize)
        } else {
            tmp.extend(
                std::slice::from_raw_parts(
                    ud_p.cast::<u64>().offset(2).cast::<u32>(),
                    stack_depth as usize,
                )
                .iter()
                .map(|x| *x as u64),
            );
            &tmp
        };
        if stack_addrs.len() > MAX_STACK_DEPTH {
            stack_addrs = &stack_addrs[(stack_addrs.len() - MAX_STACK_DEPTH)..];
        }

        let mut stack = [0u64; MAX_STACK_DEPTH];
        stack[..(stack_depth as usize).min(MAX_STACK_DEPTH)].copy_from_slice(stack_addrs);

        let entry = context.stack_counts_hashmap.entry(stack);
        *entry.or_insert(0) += 1;

        const DEBUG_OUTPUT_EVENTS: bool = false;
        if DEBUG_OUTPUT_EVENTS {
            #[repr(C)]
            #[derive(Debug)]
            #[allow(non_snake_case)]
            #[allow(non_camel_case_types)]
            struct EVENT_HEADERR {
                Size: u16,
                HeaderType: u16,
                Flags: u16,
                EventProperty: u16,
                ThreadId: u32,
                ProcessId: u32,
                TimeStamp: i64,
                ProviderId: ::windows::core::GUID,
                EventDescriptor: windows::Win32::System::Diagnostics::Etw::EVENT_DESCRIPTOR,
                KernelTime: u32,
                UserTime: u32,
                ProcessorTime: u64,
                ActivityId: ::windows::core::GUID,
            }
            #[repr(C)]
            #[derive(Debug)]
            #[allow(non_snake_case)]
            #[allow(non_camel_case_types)]
            struct EVENT_RECORDD {
                EventHeader: EVENT_HEADERR,
                BufferContextAnonymousProcessorNumber: u8,
                BufferContextAnonymousAlignment: u8,
                BufferContextAnonymousProcessorIndex: u16,
                BufferContextLoggerId: u16,
                ExtendedDataCount: u16,
                UserDataLength: u16,
                ExtendedData:
                    *mut windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXTENDED_DATA_ITEM,
                UserData: *mut ::core::ffi::c_void,
                UserContext: *mut ::core::ffi::c_void,
            }
            eprintln!(
                "record {:?} {:?} proc:{proc} thread:{_thread}",
                (*record.cast::<EVENT_RECORDD>()),
                stack
            );
        }
    }
}
impl Drop for TraceContext {
    fn drop(&mut self) {
        // SAFETY: TraceContext invariants ensure these are valid
        unsafe {
            let ret = CloseHandle(self.target_process_handle);
            if ret.0 == 0 {
                panic!("TraceContext::CloseHandle error:{:?}", get_last_error(""));
            }
        }
    }
}

/// Returns a sequence of (image_file_path, image_base)
fn list_kernel_modules() -> Vec<(OsString, u64, u64)> {
    // kernel module enumeration code based on http://www.rohitab.com/discuss/topic/40696-list-loaded-drivers-with-ntquerysysteminformation/
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            SystemInformationClass: u32,
            SystemInformation: *mut (),
            SystemInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
    }

    const BUF_LEN: usize = 1024 * 1024;
    let mut out_buf = vec![0u8; BUF_LEN];
    let mut out_size = 0u32;
    // 11 = SystemModuleInformation
    let retcode = unsafe {
        NtQuerySystemInformation(
            11,
            out_buf.as_mut_ptr().cast(),
            BUF_LEN as u32,
            &mut out_size,
        )
    };
    if retcode < 0 {
        //println!("Failed to load kernel modules");
        return vec![];
    }
    let number_of_modules = unsafe { out_buf.as_ptr().cast::<u32>().read_unaligned() as usize };
    #[repr(C)]
    #[derive(Debug)]
    #[allow(non_snake_case)]
    #[allow(non_camel_case_types)]
    struct _RTL_PROCESS_MODULE_INFORMATION {
        Section: *mut std::ffi::c_void,
        MappedBase: *mut std::ffi::c_void,
        ImageBase: *mut std::ffi::c_void,
        ImageSize: u32,
        Flags: u32,
        LoadOrderIndex: u16,
        InitOrderIndex: u16,
        LoadCount: u16,
        OffsetToFileName: u16,
        FullPathName: [u8; 256],
    }
    let modules = unsafe {
        let modules_ptr = out_buf
            .as_ptr()
            .cast::<u32>()
            .offset(2)
            .cast::<_RTL_PROCESS_MODULE_INFORMATION>();
        std::slice::from_raw_parts(modules_ptr, number_of_modules)
    };

    let kernel_module_paths = modules
        .iter()
        .filter_map(|module| {
            unsafe { std::ffi::CStr::from_ptr(module.FullPathName.as_ptr().cast()) }
                .to_str()
                .ok()
                .map(|mod_str_filepath| {
                    let verbatim_path_osstring: OsString = mod_str_filepath
                        .replacen("\\SystemRoot\\", "\\\\?\\C:\\Windows\\", 1)
                        .into();
                    (
                        verbatim_path_osstring,
                        module.ImageBase as u64,
                        module.ImageSize as u64,
                    )
                })
        })
        .collect();
    kernel_module_paths
}
