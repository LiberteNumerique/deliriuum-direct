//! Interface utun (macOS).
//!
//! macOS n'expose pas /dev/net/tun. On ouvre une socket de contrôle noyau
//! PF_SYSTEM, on demande le contrôleur `com.apple.net.utun_control`, et le
//! noyau nous rend une interface utunN.
//!
//! Particularité : chaque paquet est précédé de 4 octets indiquant la famille
//! d'adresses. Il faut les ajouter à l'écriture et les retirer à la lecture,
//! sinon le noyau jette tout en silence.

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const UTUN_OPT_IFNAME: libc::c_int = 2;

pub struct Utun {
    fd: RawFd,
    pub name: String,
}

impl Utun {
    /// Ouvre la première interface utun libre.
    pub fn open() -> Result<Self, String> {
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 {
                return Err("Socket noyau impossible à ouvrir.".into());
            }

            let mut info: libc::ctl_info = std::mem::zeroed();
            std::ptr::copy_nonoverlapping(
                UTUN_CONTROL_NAME.as_ptr(),
                info.ctl_name.as_mut_ptr() as *mut u8,
                UTUN_CONTROL_NAME.len(),
            );

            if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
                libc::close(fd);
                return Err("Contrôleur utun introuvable.".into());
            }

            // sc_unit 0 laisse le noyau choisir ; certaines versions le
            // refusent, on balaie donc les unités une par une.
            for unit in 1..=32u32 {
                let mut addr: libc::sockaddr_ctl = std::mem::zeroed();
                addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
                addr.sc_family = libc::AF_SYSTEM as u8;
                addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
                addr.sc_id = info.ctl_id;
                addr.sc_unit = unit;

                let ok = libc::connect(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
                ) == 0;

                if ok {
                    let mut name = [0u8; 32];
                    let mut len = name.len() as libc::socklen_t;
                    libc::getsockopt(
                        fd,
                        libc::SYSPROTO_CONTROL,
                        UTUN_OPT_IFNAME,
                        name.as_mut_ptr() as *mut libc::c_void,
                        &mut len,
                    );
                    let name = String::from_utf8_lossy(&name[..len.saturating_sub(1) as usize])
                        .to_string();
                    return Ok(Utun { fd, name });
                }
            }

            libc::close(fd);
            Err("Aucune interface utun disponible.".into())
        }
    }

    /// Lit un paquet IP, en retirant l'en-tête de famille d'adresses.
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut raw = vec![0u8; buf.len() + 4];
        let n = unsafe {
            libc::read(
                self.fd,
                raw.as_mut_ptr() as *mut libc::c_void,
                raw.len(),
            )
        };
        if n <= 4 {
            return Err("Lecture utun interrompue.".into());
        }
        let n = n as usize;
        buf[..n - 4].copy_from_slice(&raw[4..n]);
        Ok(n - 4)
    }

    /// Écrit un paquet IP, en préfixant la famille d'adresses.
    pub fn write_packet(&self, packet: &[u8]) -> Result<(), String> {
        if packet.is_empty() {
            return Ok(());
        }
        let family: u32 = if packet[0] >> 4 == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };

        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&family.to_be_bytes());
        framed.extend_from_slice(packet);

        let n = unsafe {
            libc::write(
                self.fd,
                framed.as_ptr() as *const libc::c_void,
                framed.len(),
            )
        };
        if n < 0 {
            Err("Écriture utun refusée.".into())
        } else {
            Ok(())
        }
    }

    /// Attribue l'adresse du tunnel et active l'interface.
    /// Sur une interface point à point, macOS attend l'adresse deux fois.
    pub fn configure(&self, address: &str, mtu: u32) -> Result<(), String> {
        let ip = address.split('/').next().unwrap_or(address);

        let status = std::process::Command::new("ifconfig")
            .args([&self.name, "inet", ip, ip, "mtu", &mtu.to_string(), "up"])
            .status()
            .map_err(|_| "ifconfig introuvable.".to_string())?;

        if status.success() {
            Ok(())
        } else {
            Err("L'adresse du tunnel n'a pas pu être attribuée.".into())
        }
    }

    pub fn try_clone_fd(&self) -> RawFd {
        unsafe { libc::dup(self.fd) }
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Utun {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Enveloppe pour lire et écrire depuis plusieurs fils d'exécution.
pub struct UtunHandle(pub std::fs::File);

impl UtunHandle {
    pub fn from(fd: RawFd) -> Self {
        UtunHandle(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    pub fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut raw = vec![0u8; buf.len() + 4];
        let n = self.0.read(&mut raw)?;
        if n <= 4 {
            return Ok(0);
        }
        buf[..n - 4].copy_from_slice(&raw[4..n]);
        Ok(n - 4)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        if packet.is_empty() {
            return Ok(());
        }
        let family: u32 = if packet[0] >> 4 == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&family.to_be_bytes());
        framed.extend_from_slice(packet);
        self.0.write_all(&framed)
    }
}
