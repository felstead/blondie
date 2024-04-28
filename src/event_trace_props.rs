// Std imports
use std::mem::size_of;
use std::ptr::addr_of_mut;

// External imports
use windows::core::PCSTR;
use windows::Win32::Foundation::{ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND};
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceA, SystemTraceControlGuid, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_IMAGE_LOAD,
    EVENT_TRACE_FLAG_PROFILE, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    KERNEL_LOGGER_NAMEA, WNODE_FLAG_TRACED_GUID,
};

// Local imports
use crate::{get_last_error, Result, KERNEL_LOGGER_NAMEA_LEN};

#[derive(Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
struct EVENT_TRACE_PROPERTIES_WITH_STRING {
    data: EVENT_TRACE_PROPERTIES,
    s: [u8; KERNEL_LOGGER_NAMEA_LEN + 1],
}

trait AsBytesWithNul {
    unsafe fn as_bytes_with_nul(&self) -> &[u8];
}

impl AsBytesWithNul for PCSTR {
    unsafe fn as_bytes_with_nul(&self) -> &[u8] {
        std::slice::from_raw_parts(self.0, self.as_bytes().len() + 1)
    }
}

pub(crate) struct EventTraceProps(EVENT_TRACE_PROPERTIES_WITH_STRING);

impl EventTraceProps {
    pub fn new() -> Self {
        // Build the trace properties, we want EVENT_TRACE_FLAG_PROFILE for the "SampledProfile" event
        // https://docs.microsoft.com/en-us/windows/win32/etw/sampledprofile
        // In https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-classes that event is listed as a "kernel event"
        // And https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants says
        // "The NT Kernel Logger session is the only session that can accept events from kernel event providers."
        // Therefore we must use GUID SystemTraceControlGuid/KERNEL_LOGGER_NAME as the session
        // EVENT_TRACE_REAL_TIME_MODE:
        //  Events are delivered when the buffers are flushed (https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
        // We also use Image_Load events to know which dlls to load debug information from for symbol resolution
        // Which is enabled by the EVENT_TRACE_FLAG_IMAGE_LOAD flag

        const PROPS_SIZE: usize = size_of::<EVENT_TRACE_PROPERTIES>() + KERNEL_LOGGER_NAMEA_LEN + 1;

        let mut event_trace_props = EVENT_TRACE_PROPERTIES_WITH_STRING {
            data: EVENT_TRACE_PROPERTIES::default(),
            s: [0u8; KERNEL_LOGGER_NAMEA_LEN + 1],
        };
        event_trace_props.data.EnableFlags = EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_IMAGE_LOAD;
        event_trace_props.data.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        event_trace_props.data.Wnode.BufferSize = PROPS_SIZE as u32;
        event_trace_props.data.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        event_trace_props.data.Wnode.ClientContext = 3;
        event_trace_props.data.Wnode.Guid = SystemTraceControlGuid;
        event_trace_props.data.BufferSize = 1024;
        let core_count = std::thread::available_parallelism()
            .unwrap_or(std::num::NonZeroUsize::new(1usize).unwrap());
        event_trace_props.data.MinimumBuffers = core_count.get() as u32 * 4;
        event_trace_props.data.MaximumBuffers = core_count.get() as u32 * 6;
        event_trace_props.data.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        event_trace_props
            .s
            .copy_from_slice(unsafe { KERNEL_LOGGER_NAMEA.as_bytes_with_nul() });

        Self(event_trace_props)
    }

    pub fn stop_existing(&self) -> Result<()> {
        // Stop an existing session with the kernel logger, if it exists
        // We use a copy of `event_trace_props` since ControlTrace overwrites it
        let mut event_trace_props_copy = self.0.clone();
        let control_stop_retcode = unsafe {
            ControlTraceA(
                None,
                KERNEL_LOGGER_NAMEA,
                addr_of_mut!(event_trace_props_copy) as *mut _,
                EVENT_TRACE_CONTROL_STOP,
            )
        };

        if control_stop_retcode != ERROR_SUCCESS
            && control_stop_retcode != ERROR_WMI_INSTANCE_NOT_FOUND
        {
            return Err(get_last_error("ControlTraceA STOP"));
        }

        Ok(())
    }
}
