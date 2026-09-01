use std::ffi::OsStr;
use std::fs;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};


use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W,
    CloseServiceHandle,
    ControlService,
    CreateServiceW,
    DeleteService,
    OpenSCManagerW,
    OpenServiceW,
    QueryServiceStatusEx,
    StartServiceW,
    SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_CHANGE_CONFIG,
    SERVICE_CONTROL_STOP,
    SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL,
    SERVICE_QUERY_STATUS,
    SERVICE_RUNNING,
    SERVICE_SID_INFO,
    SERVICE_SID_TYPE_UNRESTRICTED,
    SERVICE_START,
    SERVICE_STATUS,
    SERVICE_STATUS_PROCESS,
    SERVICE_STOP,
    SERVICE_WIN32_OWN_PROCESS,
    SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE,
    SC_STATUS_PROCESS_INFO,
};

const SERVICE_NAME: &str = "WireGuardTunnel$Deliriuum";
const DELETE_ACCESS: u32 = 0x00010000;

fn wide(value: &OsStr) -> Vec<u16> {
    value
        .encode_wide()
        .chain(once(0))
        .collect()
}

fn service_name_wide() -> Vec<u16> {
    wide(OsStr::new(SERVICE_NAME))
}

fn config_path() -> Result<PathBuf, String> {
    let program_data = std::env::var_os("PROGRAMDATA")
        .ok_or_else(|| "PROGRAMDATA est introuvable.".to_string())?;

    Ok(PathBuf::from(program_data)
        .join("Deliriuum")
        .join("Deliriuum.conf"))
}

fn write_config(config: &str) -> Result<PathBuf, String> {
    let path = config_path()?;

    let parent = path
        .parent()
        .ok_or_else(|| "Dossier de configuration invalide.".to_string())?;

    fs::create_dir_all(parent)
        .map_err(|e| format!(
            "Impossible de crÃƒÂ©er {} : {e}",
            parent.display()
        ))?;

    fs::write(&path, config.as_bytes())
        .map_err(|e| format!(
            "Impossible d'ÃƒÂ©crire {} : {e}",
            path.display()
        ))?;

    Ok(path)
}

fn binary_command(config: &std::path::Path) -> Result<Vec<u16>, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!(
            "Chemin du service Deliriuum introuvable : {e}"
        ))?;

    let command = format!(
        "\"{}\" /service \"{}\"",
        exe.display(),
        config.display()
    );

    Ok(wide(OsStr::new(&command)))
}

fn dependencies() -> Vec<u16> {
    let mut result = Vec::new();

    result.extend(OsStr::new("Nsi").encode_wide());
    result.push(0);

    result.extend(OsStr::new("TcpIp").encode_wide());
    result.push(0);

    result.push(0);

    result
}

fn install(config: &std::path::Path) -> Result<(), String> {
    let manager = unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    };

    if manager.is_null() {
        return Err(format!(
            "OpenSCManagerW a ÃƒÂ©chouÃƒÂ© : {}",
            std::io::Error::last_os_error()
        ));
    }

    let name = service_name_wide();
    let binary = binary_command(config)?;
    let deps = dependencies();

    let service = unsafe {
        CreateServiceW(
            manager,
            name.as_ptr(),
            name.as_ptr(),
            SERVICE_START
                | SERVICE_STOP
                | SERVICE_QUERY_STATUS
                | SERVICE_CHANGE_CONFIG
                | DELETE_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            null(),
            null_mut(),
            deps.as_ptr(),
            null(),
            null(),
        )
    };

    if service.is_null() {
        unsafe {
            CloseServiceHandle(manager);
        }

        return Err(format!(
            "CreateServiceW a ÃƒÂ©chouÃƒÂ© : {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut sid_info = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };

    let ok = unsafe {
        ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            &mut sid_info as *mut _ as *const _,
        )
    };

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }

    if ok == 0 {
        return Err(format!(
            "Impossible de configurer le SID du service WireGuard : {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

fn open_service(access: u32) -> Result<(*mut core::ffi::c_void, *mut core::ffi::c_void), String> {
    let manager = unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT,
        )
    };

    if manager.is_null() {
        return Err(format!(
            "OpenSCManagerW a ÃƒÂ©chouÃƒÂ© : {}",
            std::io::Error::last_os_error()
        ));
    }

    let name = service_name_wide();

    let service = unsafe {
        OpenServiceW(
            manager,
            name.as_ptr(),
            access,
        )
    };

    if service.is_null() {
        unsafe {
            CloseServiceHandle(manager);
        }

        return Err(format!(
            "OpenServiceW a ÃƒÂ©chouÃƒÂ© : {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok((manager, service))
}

pub fn up(config: &str) -> Result<(), String> {
    let config_path = write_config(config)?;

    if !is_installed() {
        install(&config_path)?;
    }

    let (manager, service) =
        open_service(SERVICE_START | SERVICE_QUERY_STATUS)?;

    let started = unsafe {
        StartServiceW(
            service,
            0,
            null(),
        )
    };

    let error = if started == 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }

    if let Some(error) = error {
        // 1056 = une instance du service est dÃƒÂ©jÃƒÂ  en cours.
        if error.raw_os_error() != Some(1056) {
            return Err(format!(
                "Impossible de dÃƒÂ©marrer le tunnel WireGuard : {error}"
            ));
        }
    }

    Ok(())
}

pub fn down() -> Result<(), String> {
    if !is_installed() {
        return Ok(());
    }

    let (manager, service) =
        open_service(SERVICE_STOP | SERVICE_QUERY_STATUS)?;

    let mut status: SERVICE_STATUS = unsafe {
        std::mem::zeroed()
    };

    let stopped = unsafe {
        ControlService(
            service,
            SERVICE_CONTROL_STOP,
            &mut status,
        )
    };

    let error = if stopped == 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }

    if let Some(error) = error {
        // 1062 = le service n'est pas dÃƒÂ©marrÃƒÂ©.
        if error.raw_os_error() != Some(1062) {
            return Err(format!(
                "Impossible d'arrÃƒÂªter le tunnel WireGuard : {error}"
            ));
        }
    }

    Ok(())
}

pub fn is_up() -> bool {
    if !is_installed() {
        return false;
    }

    let Ok((manager, service)) =
        open_service(SERVICE_QUERY_STATUS)
    else {
        return false;
    };

    let mut status: SERVICE_STATUS_PROCESS = unsafe {
        std::mem::zeroed()
    };

    let mut needed = 0u32;

    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }

    ok != 0 && status.dwCurrentState == SERVICE_RUNNING
}

fn is_installed() -> bool {
    let manager = unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT,
        )
    };

    if manager.is_null() {
        return false;
    }

    let name = service_name_wide();

    let service = unsafe {
        OpenServiceW(
            manager,
            name.as_ptr(),
            SERVICE_QUERY_STATUS,
        )
    };

    let exists = !service.is_null();

    if exists {
        unsafe {
            CloseServiceHandle(service);
        }
    }

    unsafe {
        CloseServiceHandle(manager);
    }

    exists
}

#[allow(dead_code)]
pub fn uninstall() -> Result<(), String> {
    if !is_installed() {
        return Ok(());
    }

    down()?;

    let (manager, service) =
        open_service(DELETE_ACCESS)?;

    let ok = unsafe {
        DeleteService(service)
    };

    let error = if ok == 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }

    if let Some(error) = error {
        return Err(format!(
            "Impossible de supprimer le service WireGuard : {error}"
        ));
    }

    Ok(())
}






