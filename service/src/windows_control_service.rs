use std::ffi::{c_void, OsStr};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW,
    SetServiceStatus,
    StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_STOP,
    SERVICE_RUNNING,
    SERVICE_START_PENDING,
    SERVICE_STATUS,
    SERVICE_STATUS_HANDLE,
    SERVICE_STOPPED,
    SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};

use crate::windows_service;
use crate::windows_wireguard;

pub const SERVICE_NAME: &str = "DeliriuumDirectService";

static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE = null_mut();

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(once(0))
        .collect()
}

unsafe fn report_status(
    state: u32,
    controls: u32,
    win32_exit_code: u32,
    wait_hint: u32,
) {
    if STATUS_HANDLE.is_null() {
        return;
    }

    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: win32_exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint,
    };

    SetServiceStatus(
        STATUS_HANDLE,
        &status,
    );
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP => {
            report_status(
                SERVICE_STOP_PENDING,
                0,
                0,
                3000,
            );

            let _ = windows_wireguard::down();

            report_status(
                SERVICE_STOPPED,
                0,
                0,
                0,
            );

            std::process::exit(0);
        }

        SERVICE_CONTROL_INTERROGATE => {}

        _ => {}
    }

    0
}

unsafe extern "system" fn service_main(
    _argc: u32,
    _argv: *mut *mut u16,
) {
    let name = wide(SERVICE_NAME);

    STATUS_HANDLE = RegisterServiceCtrlHandlerExW(
        name.as_ptr(),
        Some(control_handler),
        null_mut(),
    );

    if STATUS_HANDLE.is_null() {
        return;
    }

    report_status(
        SERVICE_START_PENDING,
        0,
        0,
        3000,
    );

    report_status(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP,
        0,
        0,
    );

    windows_service::run();
}

pub fn run() -> Result<(), String> {
    let mut name = wide(SERVICE_NAME);

    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];

    let ok = unsafe {
        StartServiceCtrlDispatcherW(
            table.as_ptr(),
        )
    };

    if ok == 0 {
        return Err(format!(
            "StartServiceCtrlDispatcherW a échoué : {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}
