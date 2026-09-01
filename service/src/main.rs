mod config;

#[cfg(unix)]
mod engine;

#[cfg(unix)]
#[path = "net.rs"]
mod netconf;

#[cfg(unix)]
mod utun;

#[cfg(unix)]
mod unix_service;

#[cfg(windows)]
mod windows_service;

#[cfg(windows)]
mod windows_tunnel_service;

#[cfg(windows)]
mod windows_wireguard;

#[cfg(unix)]
fn main() {
    unix_service::run();
}

#[cfg(windows)]
fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();

    if args.len() == 3 && args[1] == "/service" {
        let config_path = std::path::PathBuf::from(&args[2]);

        if let Err(e) = windows_tunnel_service::run(&config_path) {
            eprintln!("[deliriuum] WireGuard tunnel service error: {e}");
            std::process::exit(1);
        }

        return;
    }

    windows_service::run();
}






