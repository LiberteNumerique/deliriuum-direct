//! Lecture du .conf transmis par le client.
//!
//! Le client construit le mÃªme fichier que celui compris par wg-quick, ce qui
//! permet de garder les deux moteurs pendant la transition.

use base64::{engine::general_purpose::STANDARD as B64, Engine};

pub struct Config {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub address: String,
    pub dns: Vec<String>,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub keepalive: u16,
}

fn key(value: &str) -> Result<[u8; 32], String> {
    B64.decode(value.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| "ClÃ© WireGuard invalide.".to_string())
}

pub fn parse(text: &str) -> Result<Config, String> {
    let mut private_key = None;
    let mut peer_public_key = None;
    let mut address = String::new();
    let mut dns = Vec::new();
    let mut endpoint = String::new();
    let mut allowed_ips = Vec::new();
    let mut keepalive = 25u16;

    for line in text.lines() {
        let line = line.trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim().to_lowercase(), v.trim().to_string());

        match k.as_str() {
            "privatekey" => private_key = Some(key(&v)?),
            "publickey" => peer_public_key = Some(key(&v)?),
            "address" => address = v.split(',').next().unwrap_or("").trim().to_string(),
            "dns" => dns = v.split(',').map(|s| s.trim().to_string()).collect(),
            "endpoint" => endpoint = v,
            "allowedips" => allowed_ips = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            "persistentkeepalive" => keepalive = v.parse().unwrap_or(25),
            _ => {}
        }
    }

    Ok(Config {
        private_key: private_key.ok_or("ClÃ© privÃ©e absente de la configuration.")?,
        peer_public_key: peer_public_key.ok_or("ClÃ© du serveur absente de la configuration.")?,
        address: {
            if address.is_empty() {
                return Err("Adresse du tunnel absente.".into());
            }
            address
        },
        dns,
        allowed_ips,
        endpoint: {
            if endpoint.is_empty() {
                return Err("Adresse du serveur absente.".into());
            }
            endpoint
        },
        keepalive,
    })
}




