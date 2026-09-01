//! Moteur WireGuard, sans dépendance externe.
//!
//! Trois fils d'exécution :
//!   - tunnel vers réseau : lit les paquets IP de utun, les chiffre, les envoie ;
//!   - réseau vers tunnel : reçoit l'UDP, déchiffre, réinjecte dans utun ;
//!   - horloge : relance les poignées de main et les keepalive.
//!
//! Étape 1 : la poignée de main et le chiffrement fonctionnent, mais rien
//! n'est encore routé vers le tunnel. `stats()` sert à le vérifier.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Config;
use crate::utun::{Utun, UtunHandle};

const MAX_PACKET: usize = 65536;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Engine {
    pub iface: String,
    stop: Arc<AtomicBool>,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    handshake: Arc<AtomicBool>,
    /// Horodatage du dernier paquet reçu du serveur. C'est le seul signe fiable
    /// que le tunnel vit encore : un changement de réseau ne provoque aucune
    /// erreur, la conversation cesse simplement.
    last_seen: Arc<AtomicU64>,
}

impl Engine {
    pub fn start(cfg: &Config) -> Result<Self, String> {
        let utun = Utun::open()?;
        let iface = utun.name.clone();
        utun.configure(&cfg.address, 1420)?;

        let peer: SocketAddr = cfg
            .endpoint
            .to_socket_addrs()
            .map_err(|_| "Adresse du serveur introuvable.".to_string())?
            .next()
            .ok_or("Adresse du serveur introuvable.")?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|_| "Socket réseau impossible à ouvrir.".to_string())?;
        socket
            .connect(peer)
            .map_err(|_| "Serveur injoignable.".to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .ok();

        let tunn = Tunn::new(
            StaticSecret::from(cfg.private_key),
            PublicKey::from(cfg.peer_public_key),
            None,
            Some(cfg.keepalive),
            0,
            None,
        )
        .map_err(|e| format!("Moteur WireGuard refusé : {e}"))?;

        let tunn = Arc::new(Mutex::new(tunn));
        let socket = Arc::new(socket);
        let stop = Arc::new(AtomicBool::new(false));
        let rx = Arc::new(AtomicU64::new(0));
        let tx = Arc::new(AtomicU64::new(0));
        let handshake = Arc::new(AtomicBool::new(false));
        let last_seen = Arc::new(AtomicU64::new(now()));

        let read_fd = utun.try_clone_fd();
        let write_fd = utun.try_clone_fd();
        drop(utun); // les descripteurs dupliqués gardent l'interface ouverte

        spawn_tunnel_to_net(
            read_fd,
            tunn.clone(),
            socket.clone(),
            stop.clone(),
            tx.clone(),
        );
        spawn_net_to_tunnel(
            write_fd,
            tunn.clone(),
            socket.clone(),
            stop.clone(),
            rx.clone(),
            handshake.clone(),
            last_seen.clone(),
        );
        spawn_timers(tunn, socket, stop.clone());

        Ok(Engine {
            iface,
            stop,
            rx,
            tx,
            handshake,
            last_seen,
        })
    }

    /// (poignée de main établie, octets reçus, octets envoyés)
    pub fn stats(&self) -> (bool, u64, u64) {
        (
            self.handshake.load(Ordering::Relaxed),
            self.rx.load(Ordering::Relaxed),
            self.tx.load(Ordering::Relaxed),
        )
    }

    /// Le tunnel est-il encore vivant ?
    ///
    /// Tant qu'il fonctionne, le keepalive garantit un paquet toutes les
    /// 25 secondes. Au-delà d'une minute de silence, la liaison est perdue :
    /// veille, changement de réseau, serveur injoignable.
    pub fn healthy(&self) -> bool {
        if !self.handshake.load(Ordering::Relaxed) {
            // Pas encore de première poignée de main : on laisse le temps
            // d'établir la connexion avant de conclure à l'échec.
            return now().saturating_sub(self.last_seen.load(Ordering::Relaxed)) < 20;
        }
        now().saturating_sub(self.last_seen.load(Ordering::Relaxed)) < 60
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------- fils

fn spawn_tunnel_to_net(
    fd: std::os::unix::io::RawFd,
    tunn: Arc<Mutex<Tunn>>,
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    tx: Arc<AtomicU64>,
) {
    std::thread::spawn(move || {
        let mut utun = UtunHandle::from(fd);
        let mut src = vec![0u8; MAX_PACKET];
        let mut dst = vec![0u8; MAX_PACKET];

        while !stop.load(Ordering::Relaxed) {
            let n = match utun.read_packet(&mut src) {
                Ok(0) => continue,
                Ok(n) => n,
                Err(_) => break,
            };

            let mut t = tunn.lock().unwrap();
            match t.encapsulate(&src[..n], &mut dst) {
                TunnResult::WriteToNetwork(packet) => {
                    let _ = socket.send(packet);
                    tx.fetch_add(n as u64, Ordering::Relaxed);
                }
                TunnResult::Err(e) => eprintln!("[deliriuum] chiffrement : {e:?}"),
                _ => {}
            }
        }
    });
}

fn spawn_net_to_tunnel(
    fd: std::os::unix::io::RawFd,
    tunn: Arc<Mutex<Tunn>>,
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    rx: Arc<AtomicU64>,
    handshake: Arc<AtomicBool>,
    last_seen: Arc<AtomicU64>,
) {
    std::thread::spawn(move || {
        let mut utun = UtunHandle::from(fd);
        let mut src = vec![0u8; MAX_PACKET];
        let mut dst = vec![0u8; MAX_PACKET];

        while !stop.load(Ordering::Relaxed) {
            let n = match socket.recv(&mut src) {
                Ok(n) => n,
                Err(_) => continue, // délai d'attente, on repasse par la condition d'arrêt
            };

            // Tout paquet venu du serveur prouve que la liaison tient.
            last_seen.store(now(), Ordering::Relaxed);

            let mut t = tunn.lock().unwrap();
            let mut result = t.decapsulate(None, &src[..n], &mut dst);

            loop {
                match result {
                    // Réponse de poignée de main : à renvoyer immédiatement.
                    TunnResult::WriteToNetwork(packet) => {
                        let _ = socket.send(packet);
                        handshake.store(true, Ordering::Relaxed);
                        // Vider la file interne de boringtun.
                        result = t.decapsulate(None, &[], &mut dst);
                    }
                    TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                        rx.fetch_add(packet.len() as u64, Ordering::Relaxed);
                        handshake.store(true, Ordering::Relaxed);
                        let _ = utun.write_packet(packet);
                        break;
                    }
                    TunnResult::Err(e) => {
                        eprintln!("[deliriuum] déchiffrement : {e:?}");
                        break;
                    }
                    TunnResult::Done => break,
                }
            }
        }
    });
}

fn spawn_timers(tunn: Arc<Mutex<Tunn>>, socket: Arc<UdpSocket>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; MAX_PACKET];
        while !stop.load(Ordering::Relaxed) {
            {
                let mut t = tunn.lock().unwrap();
                match t.update_timers(&mut buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        let _ = socket.send(packet);
                    }
                    TunnResult::Err(e) => eprintln!("[deliriuum] horloge : {e:?}"),
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
}
