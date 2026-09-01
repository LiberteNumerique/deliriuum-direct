//! Routage et kill-switch Linux pour Deliriuum Direct.
//!
//! Outils utilisés :
//!   - iproute2 (`ip`)
//!   - nftables (`nft`)
//!
//! Le service tourne en root.

use std::process::Command;

const STATE: &str = "/var/lib/deliriuum-direct/network-linux.json";
const NFT_TABLE: &str = "deliriuum_direct";

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

fn endpoint_host(endpoint: &str) -> String {
    if endpoint.starts_with('[') {
        if let Some(end) = endpoint.find(']') {
            return endpoint[1..end].to_string();
        }
    }

    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .unwrap_or_else(|| endpoint.to_string())
}

fn endpoint_port(endpoint: &str) -> u16 {
    endpoint
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(51820)
}

/// Renvoie (gateway, interface physique).
fn physical_route() -> Result<(String, String), String> {
    let out = sh("ip", &["route", "show", "default"])?;

    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();

        if cols.first() != Some(&"default") {
            continue;
        }

        let gateway = cols
            .windows(2)
            .find(|w| w[0] == "via")
            .map(|w| w[1].to_string());

        let iface = cols
            .windows(2)
            .find(|w| w[0] == "dev")
            .map(|w| w[1].to_string());

        if let (Some(gateway), Some(iface)) = (gateway, iface) {
            return Ok((gateway, iface));
        }
    }

    Err("Aucune connexion réseau active.".into())
}

pub fn current_gateway() -> Option<String> {
    physical_route().ok().map(|(gateway, iface)| {
        format!("{gateway}@{iface}")
    })
}

fn nft_delete() {
    let _ = sh("nft", &["delete", "table", "inet", NFT_TABLE]);
}

fn killswitch_on(
    tunnel_iface: &str,
    physical_iface: &str,
    endpoint_ip: &str,
    endpoint_port: u16,
) -> Result<(), String> {
    nft_delete();

    sh("nft", &["add", "table", "inet", NFT_TABLE])
        .map_err(|e| format!("Impossible de créer le pare-feu : {e}"))?;

    sh(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            NFT_TABLE,
            "output",
            "{",
            "type",
            "filter",
            "hook",
            "output",
            "priority",
            "-100",
            ";",
            "policy",
            "drop",
            ";",
            "}",
        ],
    )
    .map_err(|e| {
        nft_delete();
        format!("Impossible d'armer le kill-switch : {e}")
    })?;

    let endpoint_port_string = endpoint_port.to_string();

    let rules = [
        vec![
            "add", "rule", "inet", NFT_TABLE, "output",
            "oifname", "lo", "accept",
        ],
        vec![
            "add", "rule", "inet", NFT_TABLE, "output",
            "oifname", tunnel_iface, "accept",
        ],
        vec![
            "add", "rule", "inet", NFT_TABLE, "output",
            "oifname", physical_iface,
            "ip", "daddr", endpoint_ip,
            "udp", "dport", &endpoint_port_string,
            "accept",
        ],
        vec![
            "add", "rule", "inet", NFT_TABLE, "output",
            "udp", "sport", "68",
            "udp", "dport", "67",
            "accept",
        ],
    ];

    for rule in rules {
        if let Err(e) = sh("nft", &rule) {
            nft_delete();
            return Err(format!("Règle de kill-switch refusée : {e}"));
        }
    }

    Ok(())
}

pub struct Applied {
    pub iface: String,
    pub endpoint_ip: String,
    pub gateway: String,
    pub physical_iface: String,
}

impl Applied {
    fn save(&self) {
        let value = serde_json::json!({
            "iface": self.iface,
            "endpoint_ip": self.endpoint_ip,
            "gateway": self.gateway,
            "physical_iface": self.physical_iface
        });

        let _ = std::fs::create_dir_all("/var/lib/deliriuum-direct");
        let _ = std::fs::write(STATE, value.to_string());
    }

    fn load() -> Option<Self> {
        let text = std::fs::read_to_string(STATE).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;

        Some(Self {
            iface: value["iface"].as_str()?.to_string(),
            endpoint_ip: value["endpoint_ip"].as_str()?.to_string(),
            gateway: value["gateway"].as_str()?.to_string(),
            physical_iface: value["physical_iface"].as_str()?.to_string(),
        })
    }
}

pub fn apply(
    iface: &str,
    endpoint: &str,
    _dns: &[String],
) -> Result<Applied, String> {
    revert();

    let endpoint_ip = endpoint_host(endpoint);
    let endpoint_port = endpoint_port(endpoint);

    let (gateway, physical_iface) = physical_route()?;

    // Le serveur WireGuard doit rester accessible hors tunnel.
    sh(
        "ip",
        &[
            "route",
            "replace",
            &endpoint_ip,
            "via",
            &gateway,
            "dev",
            &physical_iface,
        ],
    )
    .map_err(|e| format!("Route vers le serveur refusée : {e}"))?;

    // Deux demi-routes plus spécifiques que la route par défaut.
    for route in ["0.0.0.0/1", "128.0.0.0/1"] {
        if let Err(e) = sh(
            "ip",
            &[
                "route",
                "replace",
                route,
                "dev",
                iface,
            ],
        ) {
            revert();
            return Err(format!("Routage VPN refusé : {e}"));
        }
    }

    if let Err(e) = killswitch_on(
        iface,
        &physical_iface,
        &endpoint_ip,
        endpoint_port,
    ) {
        revert();
        return Err(e);
    }

    let applied = Applied {
        iface: iface.to_string(),
        endpoint_ip,
        gateway,
        physical_iface,
    };

    applied.save();

    Ok(applied)
}

pub fn revert() {
    if let Some(old) = Applied::load() {
        for route in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = sh(
                "ip",
                &[
                    "route",
                    "delete",
                    route,
                    "dev",
                    &old.iface,
                ],
            );
        }

        let _ = sh(
            "ip",
            &[
                "route",
                "delete",
                &old.endpoint_ip,
                "via",
                &old.gateway,
                "dev",
                &old.physical_iface,
            ],
        );
    }

    nft_delete();

    let _ = std::fs::remove_file(STATE);
}

pub fn is_armed() -> bool {
    sh("nft", &["list", "table", "inet", NFT_TABLE]).is_ok()
}

pub fn rebind(new_iface: &str, endpoint: &str) -> Result<(), String> {
    let old = Applied::load()
        .ok_or_else(|| "Aucune protection à rebrancher.".to_string())?;

    let endpoint_ip = endpoint_host(endpoint);
    let endpoint_port = endpoint_port(endpoint);

    for route in ["0.0.0.0/1", "128.0.0.0/1"] {
        let _ = sh(
            "ip",
            &[
                "route",
                "delete",
                route,
                "dev",
                &old.iface,
            ],
        );
    }

    let _ = sh(
        "ip",
        &[
            "route",
            "delete",
            &old.endpoint_ip,
            "via",
            &old.gateway,
            "dev",
            &old.physical_iface,
        ],
    );

    let (gateway, physical_iface) = physical_route()?;

    sh(
        "ip",
        &[
            "route",
            "replace",
            &endpoint_ip,
            "via",
            &gateway,
            "dev",
            &physical_iface,
        ],
    )
    .map_err(|e| format!("Route vers le serveur refusée : {e}"))?;

    for route in ["0.0.0.0/1", "128.0.0.0/1"] {
        sh(
            "ip",
            &[
                "route",
                "replace",
                route,
                "dev",
                new_iface,
            ],
        )
        .map_err(|e| format!("Routage VPN refusé : {e}"))?;
    }

    killswitch_on(
        new_iface,
        &physical_iface,
        &endpoint_ip,
        endpoint_port,
    )?;

    Applied {
        iface: new_iface.to_string(),
        endpoint_ip,
        gateway,
        physical_iface,
    }
    .save();

    Ok(())
}
