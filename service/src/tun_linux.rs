//! Interface TUN Linux pour Deliriuum Direct.
//!
//! Fournit la même interface Rust que l'ancien module utun macOS afin que
//! le moteur WireGuard/BoringTun reste indépendant de la plateforme.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::Command;

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

pub struct Utun {
    file: File,
    pub name: String,
}

impl Utun {
    pub fn open() -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| {
                format!(
                    "Impossible d'ouvrir /dev/net/tun : {e}. \
                     Le service Deliriuum doit fonctionner avec les privilèges réseau."
                )
            })?;

        let mut ifr = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };

        let requested = b"deliriuum%d";

        for (dst, src) in ifr.name.iter_mut().zip(requested.iter()) {
            *dst = *src as libc::c_char;
        }

        let result = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                TUNSETIFF,
                &mut ifr as *mut IfReq,
            )
        };

        if result < 0 {
            return Err(format!(
                "Impossible de créer l'interface TUN : {}",
                std::io::Error::last_os_error()
            ));
        }

        let name_bytes: Vec<u8> = ifr
            .name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();

        let name = String::from_utf8(name_bytes)
            .map_err(|_| "Nom d'interface TUN invalide.".to_string())?;

        Ok(Self { file, name })
    }

    pub fn configure(&self, address: &str, mtu: u32) -> Result<(), String> {
        let mtu_string = mtu.to_string();

        let status = Command::new("ip")
            .args([
                "link",
                "set",
                "dev",
                &self.name,
                "mtu",
                &mtu_string,
                "up",
            ])
            .status()
            .map_err(|e| format!("Commande ip indisponible : {e}"))?;

        if !status.success() {
            return Err("Impossible d'activer l'interface TUN.".into());
        }

        let status = Command::new("ip")
            .args([
                "address",
                "add",
                address,
                "dev",
                &self.name,
            ])
            .status()
            .map_err(|e| format!("Commande ip indisponible : {e}"))?;

        if !status.success() {
            return Err("Impossible d'attribuer l'adresse au tunnel.".into());
        }

        Ok(())
    }

    pub fn try_clone_fd(&self) -> RawFd {
        unsafe { libc::dup(self.file.as_raw_fd()) }
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

pub struct UtunHandle(pub File);

impl UtunHandle {
    pub fn from(fd: RawFd) -> Self {
        Self(unsafe { File::from_raw_fd(fd) })
    }

    pub fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        self.0.write_all(packet)
    }
}
