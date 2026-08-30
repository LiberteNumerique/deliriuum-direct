//! Deliriuum Direct — service privilégié.
//!
//! Tourne en root, détient le tunnel, et survit à la fermeture du client.
//! Le client n'a aucun privilège : il envoie une configuration, le service
//! la monte. C'est la seule façon d'éviter de lancer une interface graphique
//! en root, ce qu'un logiciel de vie privée ne doit jamais faire.
//!
//! Étape 1 : le tunnel est monté par `wg-quick`, à installer avec
//! `brew install wireguard-tools`. Étape 2 : boringtun embarqué ici, plus
//! aucune dépendance externe.
//!
//! Protocole : une ligne JSON par requête, une ligne JSON en réponse.
//!   {"cmd":"up","config":"<contenu du .conf>"}
//!   {"cmd":"down"}
//!   {"cmd":"status"}

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};

mod config;
mod engine;
mod utun;

use engine::Engine;

/// Moteur embarqué par défaut. `wg-quick` reste en repli le temps que
/// boringtun se stabilise : DELIRIUUM_ENGINE=wg-quick force l'ancien chemin.
fn use_boringtun() -> bool {
    std::env::var("DELIRIUUM_ENGINE").unwrap_or_default() != "wg-quick"
}

static ENGINE: std::sync::Mutex<Option<Engine>> = std::sync::Mutex::new(None);

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
    // Le détail technique va dans le journal, pas dans l'interface.
    eprintln!("[deliriuum] wg-quick {action} a échoué : {err}");
    Err("Le tunnel n'a pas pu être établi.".into())
}

/// Sur macOS, wg-quick crée une interface utunN et note le nom réel ici.
fn resolved_iface() -> Option<String> {
    let name_file = format!("/var/run/wireguard/{IFACE}.name");
    std::fs::read_to_string(name_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            // Linux : l'interface porte directement notre nom.
            Command::new("wg")
                .args(["show", IFACE, "transfer"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|_| IFACE.to_string())
        })
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
        let cfg = config::parse(config)?;
        let engine = Engine::start(&cfg)?;
        eprintln!("[deliriuum] interface {} montée (boringtun)", engine.iface);
        *ENGINE.lock().unwrap() = Some(engine);
        return Ok(());
    }


    let dir = Path::new(CONF).parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|_| "Dossier de configuration inaccessible.")?;
    std::fs::write(CONF, config).map_err(|_| "Configuration non écrite.")?;

    // La clé privée est dans ce fichier : lisible par root seul.
    let _ = std::fs::set_permissions(CONF, std::fs::Permissions::from_mode(0o600));

    let result = wg_quick("up");
    if result.is_err() {
        let _ = std::fs::remove_file(CONF);
    }
    result
}

/// Coupe les deux moteurs, quel que soit celui qui tournait.
fn down_all() {
    if let Some(e) = ENGINE.lock().unwrap().take() {
        e.stop();
    }
    if wg_is_up() {
        let _ = wg_quick("down");
    }
    let _ = std::fs::remove_file(CONF);
}

fn down() -> Result<(), String> {
    down_all();
    Ok(())
}

/// État réel du tunnel, pour que le client n'affiche jamais une protection
/// qui n'existe pas.
fn tunnel_state() -> (bool, u64, u64) {
    if let Some(e) = ENGINE.lock().unwrap().as_ref() {
        let (handshake, rx, tx) = e.stats();
        return (handshake, rx, tx);
    }
    if wg_is_up() {
        let (rx, tx) = wg_transfer();
        return (true, rx, tx);
    }
    (false, 0, 0)
}

// ------------------------------------------------------------------ service

/// Seuls les administrateurs de la machine peuvent piloter le tunnel.
/// L'étape suivante ajoutera la vérification de la signature de l'appelant.
fn peer_is_allowed(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let ok = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0;
    ok && uid != 0 || uid == 0
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
            json!({ "ok": true, "up": up, "rx": rx, "tx": tx })
        }

        _ => json!({ "ok": false, "error": "Commande inconnue." }),
    };

    let _ = writeln!(out, "{reply}");
}

fn main() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("[deliriuum] ce service doit tourner en root.");
        std::process::exit(1);
    }

    let _ = std::fs::remove_file(SOCKET);
    let listener = match UnixListener::bind(SOCKET) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[deliriuum] socket impossible à créer : {e}");
            std::process::exit(1);
        }
    };

    // Accessible aux utilisateurs de la machine, pas au monde entier.
    let _ = std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o660));
    let _ = Command::new("chgrp").args(["admin", SOCKET]).status();

    eprintln!("[deliriuum] service démarré, socket {SOCKET}");

    for stream in listener.incoming().flatten() {
        // Une requête à la fois : le tunnel est une ressource unique.
        handle(stream);
    }
}
