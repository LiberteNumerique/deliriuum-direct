//! Routage, DNS et IPv6 (macOS).
//!
//! Ce module fait ce que `wg-quick` faisait pour nous. Trois choses, dans un
//! ordre qui ne se discute pas :
//!
//!   1. Une route d'exception vers le serveur, par la passerelle physique.
//!      Sans elle, les paquets du tunnel entreraient dans le tunnel qu'ils
//!      alimentent et tout s'arrête.
//!   2. Deux demi-routes 0.0.0.0/1 et 128.0.0.0/1 vers l'interface. Elles
//!      couvrent tout Internet en étant plus spécifiques que la route par
//!      défaut, qu'on laisse donc intacte : elle se restaure toute seule.
//!   3. Le DNS via scutil, et l'IPv6 coupée. Le node ne fait pas d'IPv6 :
//!      sans cette coupure, tout le trafic v6 d'un abonné Free sortirait en
//!      clair pendant que l'utilisateur se croit protégé.
//!
//! Tout est restauré à la coupure, y compris après un arrêt brutal : l'état
//! d'origine est écrit sur disque avant la moindre modification.

use std::process::Command;

const STATE: &str = "/var/lib/deliriuum-direct/network.json";

fn sh(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd} indisponible : {e}"))?;

    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Passerelle et interface physiques actuelles, avant toute modification.
fn physical_route() -> Result<(String, String), String> {
    let out = sh("route", &["-n", "get", "default"])?;
    let mut gateway = String::new();
    let mut iface = String::new();

    for line in out.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("gateway:") {
            gateway = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("interface:") {
            iface = v.trim().to_string();
        }
    }

    if gateway.is_empty() || iface.is_empty() {
        return Err("Aucune connexion réseau active.".into());
    }
    Ok((gateway, iface))
}

/// Services réseau actifs, tels que les nomme macOS ("Wi-Fi", "Ethernet").
fn network_services() -> Vec<String> {
    sh("networksetup", &["-listallnetworkservices"])
        .unwrap_or_default()
        .lines()
        .skip(1) // ligne d'avertissement de networksetup
        .map(|l| l.trim_start_matches('*').trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

// ============================================================ kill switch

const ANCHOR: &str = "com.deliriuum.direct";
const ANCHOR_FILE: &str = "/etc/pf.anchors/com.deliriuum.direct";
const PF_BACKUP: &str = "/var/lib/deliriuum-direct/pf.conf.backup";

/// Règles de pare-feu : tout est bloqué sauf le tunnel lui-même.
///
/// Si le tunnel tombe, l'interface utun disparaît et plus rien ne passe.
/// L'utilisateur perd Internet au lieu de sortir en clair sans le savoir.
/// C'est le comportement attendu d'un VPN : échouer visiblement plutôt que
/// fuir silencieusement.
fn anchor_rules(iface: &str, endpoint_ip: &str, port: u16) -> String {
    format!(
        "# Généré par Deliriuum Direct — ne pas modifier à la main.\n\
         block drop all\n\
         pass quick on lo0 all\n\
         pass quick on {iface} all\n\
         pass out quick proto udp from any to {endpoint_ip} port {port}\n\
         pass in quick proto udp from {endpoint_ip} port {port} to any\n\
         # DHCP, sinon la machine perd son bail et donc son réseau.\n\
         pass out quick proto udp from any port 68 to any port 67\n\
         pass in quick proto udp from any port 67 to any port 68\n"
    )
}

/// Arme le pare-feu. Renvoie true si pf a été activé par nous, pour savoir
/// s'il faut le désactiver au retour.
fn killswitch_on(iface: &str, endpoint_ip: &str, port: u16) -> Result<bool, String> {
    std::fs::create_dir_all("/etc/pf.anchors").ok();
    std::fs::write(ANCHOR_FILE, anchor_rules(iface, endpoint_ip, port))
        .map_err(|_| "Règles de pare-feu non écrites.".to_string())?;

    let pf_conf = std::fs::read_to_string("/etc/pf.conf")
        .map_err(|_| "Configuration pf illisible.".to_string())?;

    if !pf_conf.contains(ANCHOR) {
        // Sauvegarde avant toute modification : c'est ce qui permet de
        // remettre la machine dans son état d'origine, même après un crash.
        std::fs::create_dir_all("/var/lib/deliriuum-direct").ok();
        if !std::path::Path::new(PF_BACKUP).exists() {
            let _ = std::fs::write(PF_BACKUP, &pf_conf);
        }

        let patched = format!(
            "{pf_conf}\nanchor \"{ANCHOR}\"\nload anchor \"{ANCHOR}\" from \"{ANCHOR_FILE}\"\n"
        );
        std::fs::write("/etc/pf.conf", patched)
            .map_err(|_| "Configuration pf non modifiable.".to_string())?;
    }

    // pfctl -E active pf et renvoie un jeton ; pf est souvent déjà actif sur
    // macOS, auquel cas on ne devra pas le couper au retour.
    let was_enabled = sh("pfctl", &["-s", "info"])
        .map(|o| o.contains("Status: Enabled"))
        .unwrap_or(false);

    sh("pfctl", &["-E"]).ok();
    sh("pfctl", &["-f", "/etc/pf.conf"])
        .map_err(|e| format!("Pare-feu refusé : {e}"))?;

    // Un ancrage chargé mais vide ne bloque rien : on vérifie plutôt que de
    // promettre une protection inexistante.
    let loaded = sh("pfctl", &["-a", ANCHOR, "-s", "rules"]).unwrap_or_default();
    if !loaded.contains("block drop all") {
        return Err("Le pare-feu n'a pas pris les règles de protection.".into());
    }

    Ok(!was_enabled)
}

fn killswitch_off(we_enabled_pf: bool) {
    let _ = sh("pfctl", &["-a", ANCHOR, "-F", "all"]);

    if let Ok(backup) = std::fs::read_to_string(PF_BACKUP) {
        let _ = std::fs::write("/etc/pf.conf", backup);
        let _ = std::fs::remove_file(PF_BACKUP);
    }
    let _ = std::fs::remove_file(ANCHOR_FILE);
    let _ = sh("pfctl", &["-f", "/etc/pf.conf"]);

    if we_enabled_pf {
        let _ = sh("pfctl", &["-d"]);
    }
}

pub struct Applied {
    pub iface: String,
    pub endpoint_ip: String,
    pub gateway: String,
    /// (service, résolveurs d'origine, état IPv6 d'origine)
    pub services: Vec<(String, Vec<String>, String)>,
    /// true si pf était éteint avant nous, et doit donc être rééteint.
    pub pf_enabled_by_us: bool,
}

impl Applied {
    fn save(&self) {
        let json = serde_json::json!({
            "iface": self.iface,
            "endpoint_ip": self.endpoint_ip,
            "gateway": self.gateway,
            "pf_enabled_by_us": self.pf_enabled_by_us,
            "services": self.services.iter().map(|(n, dns, v6)| {
                serde_json::json!({ "name": n, "dns": dns, "ipv6": v6 })
            }).collect::<Vec<_>>(),
        });
        let _ = std::fs::create_dir_all("/var/lib/deliriuum-direct");
        let _ = std::fs::write(STATE, json.to_string());
    }

    fn load() -> Option<Self> {
        let text = std::fs::read_to_string(STATE).ok()?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        Some(Applied {
            iface: v["iface"].as_str()?.to_string(),
            endpoint_ip: v["endpoint_ip"].as_str()?.to_string(),
            gateway: v["gateway"].as_str()?.to_string(),
            pf_enabled_by_us: v["pf_enabled_by_us"].as_bool().unwrap_or(false),
            services: v["services"]
                .as_array()?
                .iter()
                .map(|s| {
                    (
                        s["name"].as_str().unwrap_or_default().to_string(),
                        s["dns"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        s["ipv6"].as_str().unwrap_or("Automatic").to_string(),
                    )
                })
                .collect(),
        })
    }
}

/// Détourne tout le trafic vers l'interface du tunnel.
pub fn apply(iface: &str, endpoint: &str, dns: &[String]) -> Result<Applied, String> {
    // Un résidu d'une exécution précédente couperait le réseau : on nettoie.
    revert();

    let endpoint_ip = endpoint
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| endpoint.to_string());

    let (gateway, _physical) = physical_route()?;

    // 1. Le serveur reste joignable hors du tunnel.
    sh("route", &["-n", "add", "-host", &endpoint_ip, &gateway])
        .map_err(|e| format!("Route vers le serveur refusée : {e}"))?;

    // 2. Tout Internet passe par le tunnel.
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        if let Err(e) = sh("route", &["-n", "add", "-net", half, "-interface", iface]) {
            let _ = sh("route", &["-n", "delete", "-host", &endpoint_ip]);
            return Err(format!("Routage refusé : {e}"));
        }
    }

    // 3. DNS et IPv6, service par service.
    let mut services = Vec::new();
    for name in network_services() {
        let previous_dns: Vec<String> = sh("networksetup", &["-getdnsservers", &name])
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
            .collect();

        let previous_v6 = sh("networksetup", &["-getinfo", &name])
            .unwrap_or_default()
            .lines()
            .find_map(|l| l.strip_prefix("IPv6:").map(|v| v.trim().to_string()))
            .unwrap_or_else(|| "Automatic".into());

        if !dns.is_empty() {
            let mut args = vec!["-setdnsservers", &name];
            args.extend(dns.iter().map(String::as_str));
            let _ = sh("networksetup", &args);
        }

        // Le node ne route pas l'IPv6 : la laisser active la ferait fuir.
        let _ = sh("networksetup", &["-setv6off", &name]);

        services.push((name, previous_dns, previous_v6));
    }

    // 4. Le pare-feu en dernier : si le tunnel tombe, plus rien ne sort.
    let port: u16 = endpoint
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(51820);

    let pf_enabled_by_us = match killswitch_on(iface, &endpoint_ip, port) {
        Ok(v) => v,
        Err(e) => {
            // Sans kill switch, une coupure ferait fuir le trafic en clair.
            // Mieux vaut refuser la connexion que promettre à tort.
            for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                let _ = sh("route", &["-n", "delete", "-net", half, "-interface", iface]);
            }
            let _ = sh("route", &["-n", "delete", "-host", &endpoint_ip]);
            return Err(e);
        }
    };

    let applied = Applied {
        iface: iface.to_string(),
        endpoint_ip,
        gateway,
        services,
        pf_enabled_by_us,
    };
    applied.save();
    Ok(applied)
}

/// Passerelle physique actuelle, pour détecter un changement de réseau.
pub fn current_gateway() -> Option<String> {
    physical_route().ok().map(|(g, _)| g)
}

/// Rebranche le routage sur une nouvelle interface sans jamais désarmer le
/// pare-feu. C'est ce qui permet de se reconnecter après un changement de
/// réseau ou une sortie de veille sans exposer une seule seconde de trafic.
pub fn rebind(new_iface: &str, endpoint: &str) -> Result<(), String> {
    let Some(old) = Applied::load() else {
        return Err("Aucune protection à rebrancher.".into());
    };

    let endpoint_ip = endpoint
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| endpoint.to_string());
    let port: u16 = endpoint
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(51820);

    // Ancien routage, y compris si l'interface a déjà disparu.
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        let _ = sh("route", &["-n", "delete", "-net", half, "-interface", &old.iface]);
    }
    let _ = sh("route", &["-n", "delete", "-host", &old.endpoint_ip]);

    // La passerelle a pu changer : wifi vers 4G, ou nouveau réseau.
    let (gateway, _) = physical_route()?;

    sh("route", &["-n", "add", "-host", &endpoint_ip, &gateway])
        .map_err(|e| format!("Route vers le serveur refusée : {e}"))?;
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        sh("route", &["-n", "add", "-net", half, "-interface", new_iface])
            .map_err(|e| format!("Routage refusé : {e}"))?;
    }

    // Le pare-feu suit la nouvelle interface. pfctl -f recharge sans jamais
    // lever le blocage : il n'y a pas de fenêtre sans protection.
    std::fs::write(ANCHOR_FILE, anchor_rules(new_iface, &endpoint_ip, port))
        .map_err(|_| "Règles de pare-feu non écrites.".to_string())?;
    let _ = sh("pfctl", &["-f", "/etc/pf.conf"]);

    let applied = Applied {
        iface: new_iface.to_string(),
        endpoint_ip,
        gateway,
        services: old.services,
        pf_enabled_by_us: old.pf_enabled_by_us,
    };
    applied.save();
    Ok(())
}

/// Vrai si une protection a été appliquée et n'a pas été levée : soit le
/// tunnel tourne, soit le service est mort en laissant le blocage en place.
pub fn is_armed() -> bool {
    std::path::Path::new(STATE).exists()
}

/// Remet la machine dans son état d'origine. Sans effet si rien n'a été
/// appliqué, et appelée aussi au démarrage du service pour effacer les
/// résidus d'un arrêt brutal.
pub fn revert() {
    let Some(state) = Applied::load() else {
        return;
    };

    // Le pare-feu part en premier : sinon la machine resterait sans réseau
    // le temps de défaire le reste.
    killswitch_off(state.pf_enabled_by_us);

    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        let _ = sh("route", &["-n", "delete", "-net", half, "-interface", &state.iface]);
    }
    let _ = sh("route", &["-n", "delete", "-host", &state.endpoint_ip]);

    for (name, dns, v6) in &state.services {
        if dns.is_empty() {
            let _ = sh("networksetup", &["-setdnsservers", name, "Empty"]);
        } else {
            let mut args = vec!["-setdnsservers", name];
            args.extend(dns.iter().map(String::as_str));
            let _ = sh("networksetup", &args);
        }

        // "Off" d'origine reste Off : on ne rallume pas ce que l'utilisateur
        // avait lui-même éteint.
        if v6 != "Off" {
            let _ = sh("networksetup", &["-setv6automatic", name]);
        }
    }

    // Le cache DNS garde les réponses obtenues via le tunnel.
    let _ = sh("dscacheutil", &["-flushcache"]);
    let _ = sh("killall", &["-HUP", "mDNSResponder"]);

    let _ = std::fs::remove_file(STATE);
}
