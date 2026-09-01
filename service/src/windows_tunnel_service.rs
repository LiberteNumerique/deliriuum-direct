use std::ffi::CString;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::FreeLibrary;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress,
    LoadLibraryW,
};

type WireGuardTunnelServiceFn =
    unsafe extern "C" fn(*const u16) -> i32;

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

pub fn run(config_file: &Path) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Chemin du service introuvable : {e}"))?;

    let exe_dir = exe
        .parent()
        .ok_or_else(|| "Dossier du service introuvable.".to_string())?;

    let dll_path = exe_dir.join("tunnel.dll");

    if !dll_path.exists() {
        return Err(format!(
            "tunnel.dll est introuvable : {}",
            dll_path.display()
        ));
    }

    let dll_w = wide(dll_path.as_os_str());

    let module = unsafe { LoadLibraryW(dll_w.as_ptr()) };

    if module.is_null() {
        return Err(format!(
            "Impossible de charger {}",
            dll_path.display()
        ));
    }

    let proc_name = CString::new("WireGuardTunnelService")
        .map_err(|_| "Nom d'export invalide.".to_string())?;

    let proc = unsafe {
        GetProcAddress(module, proc_name.as_ptr() as *const u8)
    };

    let Some(proc) = proc else {
        unsafe {
            FreeLibrary(module);
        }

        return Err(
            "Export WireGuardTunnelService introuvable.".to_string()
        );
    };

    let tunnel_service: WireGuardTunnelServiceFn =
        unsafe { std::mem::transmute(proc) };

    let config_w = wide(config_file.as_os_str());

    let ok = unsafe {
        tunnel_service(config_w.as_ptr())
    };

    unsafe {
        FreeLibrary(module);
    }

    if ok == 0 {
        return Err(
            "Le service WireGuard a quitté avec une erreur.".to_string()
        );
    }

    Ok(())
}
