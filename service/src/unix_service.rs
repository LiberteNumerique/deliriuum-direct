//! Deliriuum Direct â€” service privilÃ©giÃ©.
//!
//! Tourne en root, dÃ©tient le tunnel, et survit Ã  la fermeture du client.
//! Le client n'a aucun privilÃ¨ge : il envoie une configuration, le service
//! la monte. C'est la seule faÃ§on d'Ã©viter de lancer une interface graphique
//! en root, ce qu'un logiciel de vie privÃ©e ne doit jamais faire.
//!
//! Ã‰tape 1 : le tunnel est montÃ© par `wg-quick`, Ã  installer avec
//! `brew install wireguard-tools`. Ã‰tape 2 : boringtun embarquÃ© ici, plus
//! aucune dÃ©pendance externe.
//!
//! Protocole : une ligne JSON par requÃªte, une ligne JSON en rÃ©ponse.
//!   {"cmd":"up","config":"<contenu du .conf>"}
//!   {"cmd":"down"}
//!   {"cmd":"status"}

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};

use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};


use crate::engine::Engine;

/// Moteur embarquÃ© par dÃ©faut. `wg-quick` reste en repli le temps que
/// boringtun se stabilise : DELIRIUUM_ENGINE=wg-quick force l'ancien chemin.
fn use_boringtun() -> bool {
    std::env::var("DELIRIUUM_ENGINE").unwrap_or_default() != "wg-quick"
}

static ENGINE: std::sync::Mutex<Option<Engine>> = std::sync::Mutex::new(None);

/// DerniÃ¨re configuration acceptÃ©e, pour pouvoir remonter le tunnel seul.
/// Elle contient la clÃ© privÃ©e : conservÃ©e en 0600, comme le fait wg-quick.
static LAST_CONFIG: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

const SAVED_CONF: &str = "/etc/wireguard/deliriuum-last.conf";

const SOCKET: &str = "/var/run/deliriuum-direct.sock";
const IFACE: &str = "deliriuum";
const CONF: &str = "/etc/wireguard/deliriuum.conf";

// ------------------------------------------------------------------ tunnel

fn wg_quick(action: &str) -> Result<(), String> {
    let out = Command::new("wg-quick")
        .args([action, CONF])
        .output()
        .map_err(|e| {
            format!("wg-quick introuvable ({e}). Installe wireguard-tools.")
        })?;

    if out.status.success() {
        return Ok(());
    }

    let err = String::from_utf8_lossy(&out.stderr);
    // Le dÃ©tail technique va dans le journal, pas dans l'interface.
    eprintln!("[deliriuum] wg-quick {action} a Ã©chouÃ© : {err}");
    Err("Le tunnel n'a pas pu Ãªtre Ã©tabli.".into())
}

/// Sur macOS, wg-quick crÃ©e une interface utunN et note le nom rÃ©el ici.
///
/// Ce fichier survit Ã  un arrÃªt brutal : sa seule prÃ©sence ne prouve donc
/// rien. On vÃ©rifie que l'interface qu'il dÃ©signe existe vraiment, sinon le
/// service annoncerait une protection qui n'existe plus.
fn resolved_iface() -> Option<String> {
    let name_file = format!("/var/run/wireguard/{IFACE}.name");

    let candidate = std::fs::read_to_string(&name_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if let Some(name) = candidate {
        // L'interface existe-t-elle encore ? Sinon, le fichier est un rÃ©sidu.
        let alive = Command::new("ifconfig")
            .arg(&name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if alive {
            return Some(name);
        }
        let _ = std::fs::remove_file(&name_file);
        return None;
    }

    // Linux : l'interface porte directement notre nom.
    Command::new("wg")
        .args(["show", IFACE, "transfer"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| IFACE.to_string())
}

fn wg_is_up() -> bool {
    resolved_iface().is_some()
}


/// Compteurs du tunnel, pour que le client puisse les remonter au master.
fn wg_transfer() -> (u64, u64) {
    let Some(iface) = resolved_iface() else {
        return (0, 0);
    };
    let Ok(out) = Command::new("wg").args(["show", &iface, "transfer"]).output() else {
        return (0, 0);
    };

    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            let rx = cols.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
            let tx = cols.get(2).and_then(|v| v.parse().ok()).unwrap_or(0);
            (rx, tx)
        })
        .unwrap_or((0, 0))
}

fn up(config: &str) -> Result<(), String> {
    down_all();

    if use_boringtun() {
        let cfg = crate::config::parse(config)?;
        let engine = Engine::start(&cfg)?;
        let iface = engine.iface.clone();
        eprintln!("[deliriuum] interface {iface} montÃ©e (boringtun)");

        // Le routage vient aprÃ¨s le moteur : une interface sans moteur
        // couperait le rÃ©seau de la machine.
        if let Err(e) = crate::netconf::apply(&iface, &cfg.endpoint, &cfg.dns) {
            engine.stop();
            crate::netconf::revert();
            return Err(e);
        }
        eprintln!("[deliriuum] trafic routÃ© via {iface}, DNS {:?}", cfg.dns);

        *ENGINE.lock().unwrap() = Some(engine);
        remember(config);
        return Ok(());
    }


    let dir = Path::new(CONF).parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|_| "Dossier de configuration inaccessible.")?;
    std::fs::write(CONF, config).map_err(|_| "Configuration non Ã©crite.")?;

    // La clÃ© privÃ©e est dans ce fichier : lisible par root seul.
    let _ = std::fs::set_permissions(CONF, std::fs::Permissions::from_mode(0o600));

    let result = wg_quick("up");
    if result.is_err() {
        let _ = std::fs::remove_file(CONF);
    }
    result
}

/// Coupe les deux moteurs, quel que soit celui qui tournait.
fn down_all() {
    let had_engine = {
        let mut guard = ENGINE.lock().unwrap();
        match guard.take() {
            Some(e) => {
                e.stop();
                true
            }
            None => false,
        }
    };

    // Une coupure volontaire efface la configuration : le chien de garde ne
    // doit pas remonter un tunnel que l'utilisateur vient d'arrÃªter.
    *LAST_CONFIG.lock().unwrap() = None;
    let _ = std::fs::remove_file(SAVED_CONF);

    // Le routage se dÃ©fait dans tous les cas : un rÃ©sidu couperait le rÃ©seau.
    crate::netconf::revert();

    // wg-quick n'est sollicitÃ© que s'il tournait rÃ©ellement, sinon son Ã©chec
    // remonterait une fausse erreur au client.
    if !had_engine && wg_is_up() {
        let _ = wg_quick("down");
    }
    let _ = std::fs::remove_file(CONF);
}

fn down() -> Result<(), String> {
    down_all();
    Ok(())
}

/// Ã‰tat rÃ©el du tunnel, pour que le client n'affiche jamais une protection
/// qui n'existe pas.
fn tunnel_state() -> (bool, u64, u64) {
    if let Some(e) = ENGINE.lock().unwrap().as_ref() {
        // Un moteur qui vient de repartir n'a pas encore de poignÃ©e de main :
        // il est en cours de reprise, pas en Ã©chec.
        let (handshake, rx, tx) = e.stats();
        return (handshake && e.healthy(), rx, tx);
    }
    if wg_is_up() {
        let (rx, tx) = wg_transfer();
        return (true, rx, tx);
    }
    (false, 0, 0)
}

fn remember(config: &str) {
    *LAST_CONFIG.lock().unwrap() = Some(config.to_string());
    let _ = std::fs::create_dir_all("/etc/wireguard");
    if std::fs::write(SAVED_CONF, config).is_ok() {
        let _ = std::fs::set_permissions(SAVED_CONF, std::fs::Permissions::from_mode(0o600));
    }
}

fn recall() -> Option<String> {
    if let Some(c) = LAST_CONFIG.lock().unwrap().clone() {
        return Some(c);
    }
    let c = std::fs::read_to_string(SAVED_CONF).ok()?;
    *LAST_CONFIG.lock().unwrap() = Some(c.clone());
    Some(c)
}

/// Remonte le tunnel sans jamais dÃ©sarmer le pare-feu.
fn reconnect(reason: &str) {
    let Some(config) = recall() else { return };
    let Ok(cfg) = crate::config::parse(&config) else { return };

    // Sans rÃ©seau physique, inutile d'essayer : on attend le prochain passage.
    if crate::netconf::current_gateway().is_none() {
        return;
    }

    if let Some(old) = ENGINE.lock().unwrap().take() {
        old.stop();
    }

    match Engine::start(&cfg) {
        Ok(engine) => {
            let iface = engine.iface.clone();
            match crate::netconf::rebind(&iface, &cfg.endpoint) {
                Ok(()) => {
                    eprintln!("[deliriuum] {reason} : tunnel rÃ©tabli sur {iface}");
                    *ENGINE.lock().unwrap() = Some(engine);
                }
                Err(e) => {
                    engine.stop();
                    eprintln!("[deliriuum] {reason} : routage refusÃ© ({e}), nouvelle tentative");
                }
            }
        }
        Err(e) => eprintln!("[deliriuum] {reason} : moteur refusÃ© ({e}), nouvelle tentative"),
    }
}

/// Surveille le tunnel et le rÃ©tablit tout seul.
///
/// Trois cas le font tomber sans erreur visible : la sortie de veille, le
/// passage du wifi Ã  la 4G, et une coupure rÃ©seau passagÃ¨re. Dans les trois,
/// le pare-feu reste armÃ© pendant toute la reprise : l'utilisateur perd
/// quelques secondes de rÃ©seau, jamais sa confidentialitÃ©.
fn spawn_watchdog() {
    std::thread::spawn(|| {
        let mut last_gateway = crate::netconf::current_gateway();

        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));

            if !crate::netconf::is_armed() {
                last_gateway = crate::netconf::current_gateway();
                continue;
            }

            let gateway = crate::netconf::current_gateway();
            if gateway.is_some() && gateway != last_gateway {
                last_gateway = gateway;
                reconnect("changement de rÃ©seau");
                continue;
            }
            last_gateway = gateway;

            let dead = {
                let guard = ENGINE.lock().unwrap();
                match guard.as_ref() {
                    Some(e) => !e.healthy(),
                    // ArmÃ© sans moteur : le service vient de redÃ©marrer aprÃ¨s
                    // un arrÃªt inattendu, le blocage tient toujours.
                    None => true,
                }
            };

            if dead {
                reconnect("liaison perdue");
            }
        }
    });
}

// ------------------------------------------------------------------ service

/// Seuls les administrateurs de la machine peuvent piloter le tunnel.
/// L'Ã©tape suivante ajoutera la vÃ©rification de la signature de l'appelant.
#[cfg(target_os = "macos")]
fn peer_is_allowed(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;

    unsafe {
        libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0
    }
}

#[cfg(target_os = "linux")]
fn peer_is_allowed(stream: &UnixStream) -> bool {
    use std::mem;
    use std::os::unix::io::AsRawFd;

    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0
    }
}

fn handle(stream: UnixStream) {
    if !peer_is_allowed(&stream) {
        return;
    }

    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut out = stream;

    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }

    let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
    let reply = match req["cmd"].as_str() {
        Some("up") => match req["config"].as_str() {
            Some(cfg) => match up(cfg) {
                Ok(()) => json!({ "ok": true, "up": true }),
                Err(e) => json!({ "ok": false, "error": e }),
            },
            None => json!({ "ok": false, "error": "Configuration manquante." }),
        },

        Some("down") => {
            let (_, rx, tx) = tunnel_state();
            match down() {
                Ok(()) => json!({ "ok": true, "up": false, "rx": rx, "tx": tx }),
                Err(e) => json!({ "ok": false, "error": e }),
            }
        }

        Some("status") => {
            let (up, rx, tx) = tunnel_state();
            // ArmÃ© sans tunnel : la protection a sautÃ©, le trafic est bloquÃ©.
            let blocked = !up && crate::netconf::is_armed();
            json!({ "ok": true, "up": up, "blocked": blocked, "rx": rx, "tx": tx })
        }

        _ => json!({ "ok": false, "error": "Commande inconnue." }),
    };

    let _ = writeln!(out, "{reply}");
}

pub fn run() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("[deliriuum] ce service doit tourner en root.");
        std::process::exit(1);
    }

    // AprÃ¨s un arrÃªt inattendu, le blocage est MAINTENU : c'est tout l'intÃ©rÃªt
    // d'un kill switch. Le lever ici rendrait le trafic en clair au moment
    // prÃ©cis oÃ¹ l'utilisateur croit Ãªtre protÃ©gÃ©.
    //
    // Le tunnel, lui, est mort : la machine reste donc sans rÃ©seau jusqu'Ã  ce
    // que le client se reconnecte ou demande explicitement la coupure. C'est
    // le compromis assumÃ©, celui de Mullvad.
    if crate::netconf::is_armed() {
        eprintln!(
            "[deliriuum] arrÃªt inattendu dÃ©tectÃ© : le trafic reste bloquÃ©. \
             Reconnecte-toi, ou coupe la protection depuis le client."
        );
    }

    let _ = std::fs::remove_file(SOCKET);
    let listener = match UnixListener::bind(SOCKET) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[deliriuum] socket impossible Ã  crÃ©er : {e}");
            std::process::exit(1);
        }
    };

    // Accessible aux utilisateurs de la machine, pas au monde entier.
    let _ = std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o660));
    let _ = Command::new("chgrp").args(["admin", SOCKET]).status();

    spawn_watchdog();
    eprintln!("[deliriuum] service dÃ©marrÃ©, socket {SOCKET}");

    for stream in listener.incoming().flatten() {
        // Une requÃªte Ã  la fois : le tunnel est une ressource unique.
        handle(stream);
    }
}

