use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use serde_json::{json, Value};

use crate::windows_wireguard;

use windows_sys::Win32::Foundation::{
    CloseHandle,
    ERROR_PIPE_CONNECTED,
    HANDLE,
    INVALID_HANDLE_VALUE,
    LocalFree,
};

use windows_sys::Win32::Security::{
    PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};

use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SDDL_REVISION_1,
};

use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers,
    ReadFile,
    WriteFile,
    PIPE_ACCESS_DUPLEX,
};

use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe,
    CreateNamedPipeW,
    DisconnectNamedPipe,
    PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};

const PIPE_NAME: &str = r"\\.\pipe\deliriuum-direct";


fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(once(0))
        .collect()
}

fn create_pipe() -> Result<HANDLE, String> {
    let name = wide(PIPE_NAME);

    // SY = LocalSystem
    // BA = Built-in Administrators
    // IU = Interactive Users
    //
    // GA = Generic All pour le service / admins
    // GRGW = lecture + écriture pour l'application utilisateur.
    let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)");

    let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();

    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            null_mut(),
        )
    };

    if converted == 0 {
        return Err(format!(
            "Impossible de créer la sécurité du Named Pipe : {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor,
        bInheritHandle: 0,
    };

    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),

            PIPE_ACCESS_DUPLEX,

            PIPE_TYPE_BYTE
                | PIPE_READMODE_BYTE
                | PIPE_WAIT
                | PIPE_REJECT_REMOTE_CLIENTS,

            PIPE_UNLIMITED_INSTANCES,

            4096,
            4096,
            0,

            &mut security_attributes,
        )
    };

    unsafe {
        LocalFree(security_descriptor as *mut _);
    }

    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "Impossible de créer le Named Pipe Windows : {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(handle)
}

fn read_request(handle: HANDLE) -> Result<Value, String> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];

    loop {
        let mut read = 0u32;

        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut read,
                null_mut(),
            )
        };

        if ok == 0 {
            if data.is_empty() {
                return Err(format!(
                    "Lecture du Named Pipe impossible : {}",
                    std::io::Error::last_os_error()
                ));
            }

            break;
        }

        if read == 0 {
            break;
        }

        data.extend_from_slice(&buffer[..read as usize]);

        if data.contains(&b'\n') {
            break;
        }

        if data.len() > 1024 * 1024 {
            return Err("Requête IPC trop volumineuse.".into());
        }
    }

    let text = String::from_utf8(data)
        .map_err(|_| "Requête IPC non UTF-8.".to_string())?;

    let line = text.lines().next().unwrap_or("");

    serde_json::from_str(line)
        .map_err(|_| "Requête JSON invalide.".to_string())
}

fn build_reply(req: &Value) -> Value {
    match req["cmd"].as_str() {
        Some("status") => {
            json!({
                "ok": true,
                "up": windows_wireguard::is_up(),
                "blocked": false,
                "rx": 0,
                "tx": 0
            })
        }

        Some("down") => {
            match windows_wireguard::down() {
                Ok(()) => {
                    println!("[deliriuum] tunnel WireGuard arrêté");

                    json!({
                        "ok": true,
                        "up": false,
                        "rx": 0,
                        "tx": 0
                    })
                }

                Err(error) => {
                    json!({
                        "ok": false,
                        "error": error
                    })
                }
            }
        }

        Some("up") => {
            let Some(config) = req["config"].as_str() else {
                return json!({
                    "ok": false,
                    "error": "Configuration manquante."
                });
            };

            match crate::config::parse(config) {
                Ok(_) => {}

                Err(error) => {
                    return json!({
                        "ok": false,
                        "error": error
                    });
                }
            }

            match windows_wireguard::up(config) {
                Ok(()) => {
                    println!("[deliriuum] tunnel WireGuard démarré");

                    json!({
                        "ok": true,
                        "up": true
                    })
                }

                Err(error) => {
                    json!({
                        "ok": false,
                        "error": error
                    })
                }
            }
        }

        _ => {
            json!({
                "ok": false,
                "error": "Commande inconnue."
            })
        }
    }
}
fn write_reply(
    handle: HANDLE,
    reply: &Value,
) -> Result<(), String> {
    let response = format!("{reply}\n");
    let bytes = response.as_bytes();

    let mut written = 0u32;

    let ok = unsafe {
        WriteFile(
            handle,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            null_mut(),
        )
    };

    if ok == 0 {
        return Err(format!(
            "Écriture du Named Pipe impossible : {}",
            std::io::Error::last_os_error()
        ));
    }

    unsafe {
        FlushFileBuffers(handle);
    }

    Ok(())
}

fn handle_client(handle: HANDLE) {
    let result = read_request(handle)
        .map(|req| build_reply(&req))
        .and_then(|reply| {
            write_reply(handle, &reply)?;
            Ok(reply)
        });

    if let Err(error) = result {
        eprintln!(
            "[deliriuum] IPC Windows : {error}"
        );
    }
}

pub fn run() {
    println!("[deliriuum] service Windows démarré");
    println!("[deliriuum] Named Pipe : {PIPE_NAME}");

    loop {
        let handle = match create_pipe() {
            Ok(handle) => handle,

            Err(error) => {
                eprintln!("[deliriuum] {error}");

                std::thread::sleep(
                    std::time::Duration::from_secs(1)
                );

                continue;
            }
        };

        let connected = unsafe {
            ConnectNamedPipe(handle, null_mut())
        };

        if connected == 0 {
            let error =
                std::io::Error::last_os_error();

            if error.raw_os_error()
                != Some(ERROR_PIPE_CONNECTED as i32)
            {
                eprintln!(
                    "[deliriuum] connexion Named Pipe impossible : {error}"
                );

                unsafe {
                    CloseHandle(handle);
                }

                continue;
            }
        }

        handle_client(handle);

        unsafe {
            DisconnectNamedPipe(handle);
            CloseHandle(handle);
        }
    }
}




