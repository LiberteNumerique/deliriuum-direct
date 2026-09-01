//! Configuration réseau Linux de Deliriuum Direct.
//!
//! Ce module :
//! - conserve une route directe vers le serveur WireGuard,
//! - envoie le trafic IPv4 dans le TUN,
//! - active un kill-switch nftables,
//! - restaure le réseau à la déconnexion.

use std::fs;
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::{Command, Stdio};

const NFT_TABLE: &str = "deliriuum_direct";
const STATE_DIR: &str = "/var/lib/deliriuum-direct";
const STATE_FILE: &str = "/var/lib/deliriuum-direct/network-linux.state";

#[derive(Debug, Clone)]
struct PhysicalRoute {
    gateway: Option<String>,
    iface: String,
}

#[derive(Debug, Clone)]
struct Applied {
    tunnel_iface: String,
    physical_iface: String,
    gateway: Option<String>,
    endpoint_ip: String,
    endpoint_port: u16,
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("Impossible d'exécuter {program}: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "{} {} a échoué : {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn command_status(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("Impossible d'exécuter {program}: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "{} {} a échoué : {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

fn nft_script(script: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Impossible de lancer nft : {e}"))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("Impossible d'écrire les règles nftables : {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Erreur nftables : {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "nftables a refusé les règles : {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

fn endpoint_parts(endpoint: &str) -> Result<(String, u16), String> {
    if endpoint.starts_with('[') {
        let end = endpoint
            .find("]:")
            .ok_or_else(|| format!("Endpoint WireGuard invalide : {endpoint}"))?;

        let host = endpoint[1..end].to_string();
        let port = endpoint[end + 2..]
            .parse::<u16>()
            .map_err(|_| format!("Port WireGuard invalide : {endpoint}"))?;

        return Ok((host, port));
    }

    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| format!("Endpoint WireGuard invalide : {endpoint}"))?;

    let port = port
        .parse::<u16>()
        .map_err(|_| format!("Port WireGuard invalide : {endpoint}"))?;

    Ok((host.to_string(), port))
}

fn resolve_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    let (host, port) = endpoint_parts(endpoint)?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ip) => Ok((ip.to_string(), port)),
            IpAddr::V6(_) => Err(
                "Les endpoints WireGuard IPv6 ne sont pas encore pris en charge sous Linux."
                    .into(),
            ),
        };
    }

    let addresses = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("Impossible de résoudre {host} : {e}"))?;

    for address in addresses {
        if let IpAddr::V4(ip) = address.ip() {
            return Ok((ip.to_string(), port));
        }
    }

    Err(format!(
        "Aucune adresse IPv4 trouvée pour le serveur WireGuard {host}"
    ))
}

fn physical_route() -> Option<PhysicalRoute> {
    let output = command_output("ip", &["-4", "route", "show", "default"]).ok()?;
    let line = output.lines().next()?;

    let fields: Vec<&str> = line.split_whitespace().collect();

    let mut gateway = None;
    let mut iface = None;

    let mut i = 0;
    while i < fields.len() {
        match fields[i] {
            "via" if i + 1 < fields.len() => {
                gateway = Some(fields[i + 1].to_string());
                i += 2;
            }
            "dev" if i + 1 < fields.len() => {
                iface = Some(fields[i + 1].to_string());
                i += 2;
            }
            _ => i += 1,
        }
    }

    Some(PhysicalRoute {
        gateway,
        iface: iface?,
    })
}

pub fn current_gateway() -> Option<String> {
    let route = physical_route()?;

    Some(match route.gateway {
        Some(gateway) => format!("{gateway}@{}", route.iface),
        None => format!("direct@{}", route.iface),
    })
}

fn endpoint_route_add(endpoint_ip: &str, route: &PhysicalRoute) -> Result<(), String> {
    let destination = format!("{endpoint_ip}/32");

    match &route.gateway {
        Some(gateway) => command_status(
            "ip",
            &[
                "-4",
                "route",
                "replace",
                &destination,
                "via",
                gateway,
                "dev",
                &route.iface,
            ],
        ),
        None => command_status(
            "ip",
            &[
                "-4",
                "route",
                "replace",
                &destination,
                "dev",
                &route.iface,
            ],
        ),
    }
}

fn endpoint_route_del(endpoint_ip: &str) {
    let destination = format!("{endpoint_ip}/32");
    let _ = Command::new("ip")
        .args(["-4", "route", "del", &destination])
        .status();
}

fn tunnel_routes_add(iface: &str) -> Result<(), String> {
    command_status(
        "ip",
        &["-4", "route", "replace", "0.0.0.0/1", "dev", iface],
    )?;

    if let Err(e) = command_status(
        "ip",
        &["-4", "route", "replace", "128.0.0.0/1", "dev", iface],
    ) {
        let _ = Command::new("ip")
            .args(["-4", "route", "del", "0.0.0.0/1", "dev", iface])
            .status();

        return Err(e);
    }

    Ok(())
}

fn tunnel_routes_del(iface: &str) {
    let _ = Command::new("ip")
        .args(["-4", "route", "del", "0.0.0.0/1", "dev", iface])
        .status();

    let _ = Command::new("ip")
        .args(["-4", "route", "del", "128.0.0.0/1", "dev", iface])
        .status();
}

fn killswitch_off() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .status();
}

fn killswitch_on(
    tunnel_iface: &str,
    physical_iface: &str,
    endpoint_ip: &str,
    endpoint_port: u16,
) -> Result<(), String> {
    killswitch_off();

    let rules = format!(
        r#"
table inet {table} {{
    chain output {{
        type filter hook output priority 0; policy drop;

        oifname "lo" accept
        oifname "{tunnel}" accept

        oifname "{physical}" ip daddr {endpoint} udp dport {port} accept

        oifname "{physical}" udp sport 68 udp dport 67 accept
        oifname "{physical}" udp sport 546 udp dport 547 accept
    }}
}}
"#,
        table = NFT_TABLE,
        tunnel = tunnel_iface,
        physical = physical_iface,
        endpoint = endpoint_ip,
        port = endpoint_port,
    );

    nft_script(&rules)
}

fn save_state(state: &Applied) -> Result<(), String> {
    fs::create_dir_all(STATE_DIR)
        .map_err(|e| format!("Impossible de créer {STATE_DIR} : {e}"))?;

    let gateway = state.gateway.as_deref().unwrap_or("-");

    let content = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        state.tunnel_iface,
        state.physical_iface,
        gateway,
        state.endpoint_ip,
        state.endpoint_port
    );

    fs::write(STATE_FILE, content)
        .map_err(|e| format!("Impossible d'enregistrer l'état réseau : {e}"))
}

fn load_state() -> Option<Applied> {
    let content = fs::read_to_string(STATE_FILE).ok()?;
    let mut lines = content.lines();

    let tunnel_iface = lines.next()?.to_string();
    let physical_iface = lines.next()?.to_string();

    let gateway_line = lines.next()?.to_string();
    let gateway = if gateway_line == "-" {
        None
    } else {
        Some(gateway_line)
    };

    let endpoint_ip = lines.next()?.to_string();
    let endpoint_port = lines.next()?.parse::<u16>().ok()?;

    Some(Applied {
        tunnel_iface,
        physical_iface,
        gateway,
        endpoint_ip,
        endpoint_port,
    })
}

pub fn is_armed() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub fn apply(iface: &str, endpoint: &str, _dns: &[String]) -> Result<(), String> {
    revert();

    let (endpoint_ip, endpoint_port) = resolve_endpoint(endpoint)?;

    let route = physical_route()
        .ok_or_else(|| "Impossible de déterminer la route réseau physique.".to_string())?;

    endpoint_route_add(&endpoint_ip, &route)?;

    if let Err(e) = tunnel_routes_add(iface) {
        endpoint_route_del(&endpoint_ip);
        return Err(e);
    }

    let state = Applied {
        tunnel_iface: iface.to_string(),
        physical_iface: route.iface.clone(),
        gateway: route.gateway.clone(),
        endpoint_ip: endpoint_ip.clone(),
        endpoint_port,
    };

    // Sauvegarde avant le kill-switch afin de pouvoir restaurer le réseau
    // même si l'installation des règles nftables échoue.
    if let Err(e) = save_state(&state) {
        tunnel_routes_del(iface);
        endpoint_route_del(&endpoint_ip);
        return Err(e);
    }

    if let Err(e) = killswitch_on(
        iface,
        &route.iface,
        &endpoint_ip,
        endpoint_port,
    ) {
        tunnel_routes_del(iface);
        endpoint_route_del(&endpoint_ip);
        let _ = fs::remove_file(STATE_FILE);
        return Err(e);
    }

    Ok(())
}

pub fn revert() {
    if let Some(state) = load_state() {
        tunnel_routes_del(&state.tunnel_iface);
        endpoint_route_del(&state.endpoint_ip);
    }

    killswitch_off();

    let _ = fs::remove_file(STATE_FILE);
}

pub fn rebind(iface: &str, endpoint: &str) -> Result<(), String> {
    let previous = load_state();

    if let Some(state) = &previous {
        tunnel_routes_del(&state.tunnel_iface);
        endpoint_route_del(&state.endpoint_ip);
    }

    let (endpoint_ip, endpoint_port) = resolve_endpoint(endpoint)?;

    let route = physical_route()
        .ok_or_else(|| "Impossible de déterminer la nouvelle route physique.".to_string())?;

    endpoint_route_add(&endpoint_ip, &route)?;

    if let Err(e) = tunnel_routes_add(iface) {
        endpoint_route_del(&endpoint_ip);
        return Err(e);
    }

    let state = Applied {
        tunnel_iface: iface.to_string(),
        physical_iface: route.iface.clone(),
        gateway: route.gateway.clone(),
        endpoint_ip: endpoint_ip.clone(),
        endpoint_port,
    };

    save_state(&state)?;

    killswitch_on(
        iface,
        &route.iface,
        &endpoint_ip,
        endpoint_port,
    )?;

    Ok(())
}
