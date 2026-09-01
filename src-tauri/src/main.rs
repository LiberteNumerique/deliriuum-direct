#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Deliriuum Direct â€” client de bureau.
//!
//! CÃ¢blÃ© sur la mÃªme API que l'application Android : master.deliriuum.com,
//! jetons access/refresh, appareils puis sessions.
//!
//! La clÃ© privÃ©e WireGuard est gÃ©nÃ©rÃ©e ici et stockÃ©e dans le trousseau du
//! systÃ¨me. Elle ne part jamais sur le rÃ©seau : seule la publique est envoyÃ©e.
//!
//! Ã‰tat : le parcours complet est cÃ¢blÃ©, le tunnel est simulÃ©.
//! Le seul endroit Ã  remplacer est `tunnel::Backend`.

use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{Manager, State};
use x25519_dalek::{PublicKey, StaticSecret};

const MASTER: &str = "https://master.deliriuum.com";
const SITE: &str = "https://deliriuum.com";
const KEYRING: &str = "com.deliriuum.direct";

/// Les erreurs remontÃ©es au JavaScript sont des phrases affichables telles quelles.
type Result<T> = std::result::Result<T, String>;

// ============================================================ Ã©tat

#[derive(Default)]
struct App {
    tokens: Mutex<Option<Tokens>>,
    tunnel: Mutex<tunnel::Backend>,
    session_id: Mutex<Option<String>>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct Tokens {
    access: String,
    refresh: String,
}

// ============================================================ trousseau

/// Dossier de configuration de l'application, hors trousseau.
/// Ce qui n'est pas un secret n'a rien Ã  faire dans le trousseau : chaque
/// entrÃ©e supplÃ©mentaire est une demande d'autorisation de plus pour l'utilisateur.
fn config_path(name: &str) -> Option<std::path::PathBuf> {
    let dir = if cfg!(target_os = "windows") {
        std::path::PathBuf::from(std::env::var("APPDATA").ok()?)
    } else if cfg!(target_os = "macos") {
        std::path::PathBuf::from(std::env::var("HOME").ok()?)
            .join("Library")
            .join("Application Support")
    } else {
        match std::env::var("XDG_CONFIG_HOME") {
            Ok(x) => std::path::PathBuf::from(x),
            Err(_) => std::path::PathBuf::from(std::env::var("HOME").ok()?).join(".config"),
        }
    }
    .join("Deliriuum Direct");

    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(name))
}

fn cfg_get(name: &str) -> Option<String> {
    let v = std::fs::read_to_string(config_path(name)?).ok()?;
    let v = v.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

fn cfg_set(name: &str, value: &str) {
    if let Some(p) = config_path(name) {
        let _ = std::fs::write(p, value);
    }
}

fn cfg_del(name: &str) {
    if let Some(p) = config_path(name) {
        let _ = std::fs::remove_file(p);
    }
}

fn kr(key: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING, key).map_err(|_| "Trousseau du systÃ¨me inaccessible.".into())
}

fn kr_get(key: &str) -> Option<String> {
    kr(key).ok()?.get_password().ok()
}

fn kr_set(key: &str, value: &str) {
    if let Ok(e) = kr(key) {
        let _ = e.set_password(value);
    }
}

fn kr_del(key: &str) {
    if let Ok(e) = kr(key) {
        let _ = e.delete_credential();
    }
}

// ============================================================ appels HTTP

/// Extrait le champ `detail` renvoyÃ© par le master, sinon un message gÃ©nÃ©rique.
fn detail_of(status: u16, body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["detail"].as_str().map(str::to_string))
        .unwrap_or_else(|| match status {
            401 => "E-mail ou mot de passe incorrect.".into(),
            409 => "Ce compte existe dÃ©jÃ .".into(),
            429 => "Trop de tentatives. RÃ©essaie dans quelques minutes.".into(),
            _ => format!("Erreur du serveur ({status})."),
        })
}

async fn send(
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> Result<(u16, String)> {
    let mut req = reqwest::Client::new().request(method, format!("{MASTER}{path}"));
    if let Some(b) = body {
        req = req.json(&b);
    }
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }

    let res = req
        .send()
        .await
        .map_err(|_| "Serveur injoignable. VÃ©rifie ta connexion.".to_string())?;

    let status = res.status().as_u16();
    let text = res.text().await.unwrap_or_default();
    Ok((status, text))
}

impl App {
    fn access(&self) -> Result<String> {
        self.tokens
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| t.access.clone())
            .ok_or_else(|| "Ta session a expirÃ©. Reconnecte-toi.".into())
    }

    /// Seul le jeton de rafraÃ®chissement est persistÃ©. L'accÃ¨s, de courte durÃ©e,
    /// reste en mÃ©moire : une entrÃ©e de trousseau en moins, sans rien perdre.
    fn store(&self, t: Tokens) {
        kr_set("refresh-token", &t.refresh);
        *self.tokens.lock().unwrap() = Some(t);
    }

    fn clear(&self) {
        kr_del("refresh-token");
        *self.tokens.lock().unwrap() = None;
        *self.session_id.lock().unwrap() = None;
    }

    /// Renouvelle la paire de jetons. Le master en renvoie deux nouveaux.
    async fn refresh(&self) -> Result<()> {
        let refresh = self
            .tokens
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| t.refresh.clone())
            .ok_or_else(|| "Ta session a expirÃ©. Reconnecte-toi.".to_string())?;

        let (status, body) = send(
            reqwest::Method::POST,
            "/auth/refresh",
            Some(json!({ "refresh_token": refresh })),
            None,
        )
        .await?;

        if status == 401 || status == 403 {
            self.clear();
            return Err("Ta session a expirÃ©. Reconnecte-toi.".into());
        }
        if !(200..300).contains(&status) {
            return Err(detail_of(status, &body));
        }

        let v: Value = serde_json::from_str(&body).map_err(|_| "RÃ©ponse illisible.".to_string())?;
        self.store(Tokens {
            access: v["access_token"].as_str().unwrap_or_default().to_string(),
            refresh: v["refresh_token"].as_str().unwrap_or_default().to_string(),
        });
        Ok(())
    }

    /// RequÃªte authentifiÃ©e : sur 401, renouvelle une fois puis rejoue.
    async fn auth_call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let token = self.access()?;
        let (mut status, mut text) =
            send(method.clone(), path, body.clone(), Some(&token)).await?;

        if status == 401 {
            self.refresh().await?;
            let token = self.access()?;
            let retry = send(method, path, body, Some(&token)).await?;
            status = retry.0;
            text = retry.1;
        }

        if !(200..300).contains(&status) {
            return Err(detail_of(status, &text));
        }
        // 204 No Content : corps vide, ce n'est pas une erreur.
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

// ============================================================ clÃ©s et appareil

/// GÃ©nÃ¨re la paire au premier lancement, la conserve ensuite.
fn keypair() -> Result<(StaticSecret, String)> {
    let secret = match kr_get("wireguard-private-key") {
        Some(stored) => {
            let raw = B64
                .decode(stored)
                .map_err(|_| "La clÃ© enregistrÃ©e est illisible.".to_string())?;
            let bytes: [u8; 32] = raw
                .try_into()
                .map_err(|_| "La clÃ© enregistrÃ©e est illisible.".to_string())?;
            StaticSecret::from(bytes)
        }
        None => {
            let s = StaticSecret::random_from_rng(rand::thread_rng());
            kr_set("wireguard-private-key", &B64.encode(s.to_bytes()));
            s
        }
    };
    let public = B64.encode(PublicKey::from(&secret).as_bytes());
    Ok((secret, public))
}

/// Nom lisible dans Â« Mes appareils Â», cÃ´tÃ© master.
fn device_name() -> String {
    let host = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().trim_end_matches(".local").to_string())
        .filter(|s| !s.is_empty());

    let os = match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    };
    match host {
        Some(h) => format!("{h} Â· Direct {os}"),
        None => format!("Deliriuum Direct Â· {os}"),
    }
}

/// GÃ©nÃ¨re une nouvelle paire et remplace celle du trousseau.
fn rotate_keypair() -> Result<(StaticSecret, String)> {
    kr_del("wireguard-private-key");
    keypair()
}

/// RÃ©sout l'appareil de cette machine cÃ´tÃ© master, sans jamais montrer de
/// conflit Ã  l'utilisateur.
///
/// Le master indexe les appareils par clÃ© publique. Si le fichier local
/// d'identifiant est perdu â€” rÃ©installation, nouveau profil, dossier effacÃ© â€”
/// une crÃ©ation naÃ¯ve renverrait Â« clÃ© dÃ©jÃ  utilisÃ©e Â». On cherche donc
/// d'abord l'appareil par sa clÃ©, et on ne crÃ©e qu'en dernier recours.
async fn ensure_device(app: &App) -> Result<(StaticSecret, String)> {
    let (secret, public) = keypair()?;

    let devices = app.auth_call(reqwest::Method::GET, "/devices", None).await?;
    let list = devices.as_array().cloned().unwrap_or_default();

    // 1. L'identifiant local est-il toujours valable ?
    if let Some(id) = cfg_get("device-id") {
        if list.iter().any(|d| d["id"].as_str() == Some(id.as_str())) {
            return Ok((secret, id));
        }
        cfg_del("device-id");
    }

    // 2. Sinon, notre clÃ© publique est peut-Ãªtre dÃ©jÃ  enregistrÃ©e.
    if let Some(found) = list
        .iter()
        .find(|d| d["public_key"].as_str() == Some(public.as_str()))
        .and_then(|d| d["id"].as_str())
    {
        cfg_set("device-id", found);
        return Ok((secret, found.to_string()));
    }

    // 3. CrÃ©ation.
    match app
        .auth_call(
            reqwest::Method::POST,
            "/devices",
            Some(json!({ "name": device_name(), "public_key": public })),
        )
        .await
    {
        Ok(created) => {
            let id = created["id"]
                .as_str()
                .ok_or("Le serveur n'a pas renvoyÃ© d'identifiant d'appareil.")?
                .to_string();
            cfg_set("device-id", &id);
            Ok((secret, id))
        }

        // 4. Refus malgrÃ© tout : la clÃ© appartient Ã  un autre compte, ou Ã  un
        //    appareil que ce compte ne voit pas. On repart d'une clÃ© neuve
        //    plutÃ´t que d'afficher un conflit incomprÃ©hensible.
        Err(_) => {
            let (secret, public) = rotate_keypair()?;
            let created = app
                .auth_call(
                    reqwest::Method::POST,
                    "/devices",
                    Some(json!({ "name": device_name(), "public_key": public })),
                )
                .await?;
            let id = created["id"]
                .as_str()
                .ok_or("Le serveur n'a pas renvoyÃ© d'identifiant d'appareil.")?
                .to_string();
            cfg_set("device-id", &id);
            Ok((secret, id))
        }
    }
}

// ============================================================ commandes

#[derive(Serialize)]
struct Me {
    email: String,
    verified: bool,
}

#[derive(Serialize)]
struct Connected {
    node: String,
    ip: String,
}

#[tauri::command]
async fn login(email: String, password: String, app: State<'_, App>) -> Result<Me> {
    let (status, body) = send(
        reqwest::Method::POST,
        "/auth/login",
        Some(json!({ "email": email, "password": password })),
        None,
    )
    .await?;

    if !(200..300).contains(&status) {
        return Err(detail_of(status, &body));
    }

    let v: Value = serde_json::from_str(&body).map_err(|_| "RÃ©ponse illisible.".to_string())?;
    app.store(Tokens {
        access: v["access_token"].as_str().unwrap_or_default().to_string(),
        refresh: v["refresh_token"].as_str().unwrap_or_default().to_string(),
    });

    let me = app.auth_call(reqwest::Method::GET, "/auth/me", None).await?;
    Ok(Me {
        email: me["email"].as_str().unwrap_or(&email).to_string(),
        verified: me["is_verified"].as_bool().unwrap_or(true),
    })
}

/// L'inscription ne renvoie pas de jeton : le master crÃ©e un compte Ã  vÃ©rifier
/// par e-mail. On tente ensuite une connexion, qui Ã©chouera tant que le compte
/// n'est pas validÃ© â€” c'est ce que l'Ã©cran de vÃ©rification annonce.
#[tauri::command]
async fn register(email: String, password: String, app: State<'_, App>) -> Result<Me> {
    let (status, body) = send(
        reqwest::Method::POST,
        "/auth/register",
        Some(json!({ "email": email, "password": password })),
        None,
    )
    .await?;

    if !(200..300).contains(&status) {
        return Err(detail_of(status, &body));
    }

    match login(email.clone(), password, app).await {
        Ok(me) => Ok(me),
        Err(_) => Ok(Me { email, verified: false }),
    }
}

#[tauri::command]
async fn resend_verification(email: String) -> Result<()> {
    let (status, body) = send(
        reqwest::Method::POST,
        "/auth/resend-verification",
        Some(json!({ "email": email })),
        None,
    )
    .await?;

    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(detail_of(status, &body))
    }
}

/// Envoie le lien de rÃ©initialisation. Le master renvoie un message `detail`
/// volontairement neutre, qui ne dit pas si le compte existe.
#[tauri::command]
async fn forgot_password(email: String) -> Result<String> {
    let (status, body) = send(
        reqwest::Method::POST,
        "/auth/forgot-password",
        Some(json!({ "email": email })),
        None,
    )
    .await?;

    if !(200..300).contains(&status) {
        return Err(detail_of(status, &body));
    }

    Ok(serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v["detail"].as_str().map(str::to_string))
        .unwrap_or_else(|| "Si ce compte existe, un e-mail vient de partir.".into()))
}

#[tauri::command]
async fn session(app: State<'_, App>) -> Result<Option<Me>> {
    if app.tokens.lock().unwrap().is_none() {
        // Au lancement, seul le refresh est disponible : on le troque contre
        // une paire fraÃ®che. Un seul accÃ¨s au trousseau par session.
        match kr_get("refresh-token") {
            Some(refresh) => {
                *app.tokens.lock().unwrap() = Some(Tokens {
                    access: String::new(),
                    refresh,
                });
                if app.refresh().await.is_err() {
                    return Ok(None);
                }
            }
            None => return Ok(None),
        }
    }

    match app.auth_call(reqwest::Method::GET, "/auth/me", None).await {
        Ok(me) => Ok(Some(Me {
            email: me["email"].as_str().unwrap_or_default().to_string(),
            verified: me["is_verified"].as_bool().unwrap_or(true),
        })),
        Err(_) => Ok(None),
    }
}

#[tauri::command]
async fn connect(app: State<'_, App>) -> Result<Connected> {
    let (secret, device_id) = ensure_device(&app).await?;

    // Une session peut rester ouverte cÃ´tÃ© master si le client a Ã©tÃ© tuÃ© sans
    // se dÃ©connecter. On la ferme puis on rejoue, une seule fois.
    let cfg = match app
        .auth_call(
            reqwest::Method::POST,
            "/sessions/connect",
            Some(json!({ "device_id": device_id })),
        )
        .await
    {
        Ok(cfg) => cfg,
        Err(first) => {
            let _ = app
                .auth_call(
                    reqwest::Method::POST,
                    &format!("/sessions/device/{device_id}/disconnect-active"),
                    None,
                )
                .await;

            app.auth_call(
                reqwest::Method::POST,
                "/sessions/connect",
                Some(json!({ "device_id": device_id })),
            )
            .await
            .map_err(|second| {
                // Si le second Ã©chec dit autre chose, c'est lui qui informe.
                if second == first { first } else { second }
            })?
        }
    };

    let endpoint = cfg["server_endpoint"].as_str().unwrap_or_default().to_string();
    let host = endpoint.split(':').next().unwrap_or(&endpoint).to_string();

    let dns = cfg["client_dns"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();

    let allowed = cfg["allowed_ips"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0.0.0.0/0, ::/0".into());

    let conf = format!(
        "[Interface]\n\
         PrivateKey = {priv}\n\
         Address = {addr}\n\
         DNS = {dns}\n\
         \n\
         [Peer]\n\
         PublicKey = {peer}\n\
         AllowedIPs = {allowed}\n\
         Endpoint = {endpoint}\n\
         PersistentKeepalive = {keep}\n",
        priv = B64.encode(secret.to_bytes()),
        addr = cfg["client_address"].as_str().unwrap_or_default(),
        dns = dns,
        peer = cfg["server_public_key"].as_str().unwrap_or_default(),
        allowed = allowed,
        endpoint = endpoint,
        keep = cfg["persistent_keepalive"].as_u64().unwrap_or(25),
    );

    app.tunnel.lock().unwrap().up(conf)?;

    if let Some(id) = cfg["session_id"].as_str() {
        *app.session_id.lock().unwrap() = Some(id.to_string());
        cfg_set("session-id", id);
    }
    cfg_set("node-name", &host);

    // L'IP publique de sortie n'est pas renvoyÃ©e par le master ; l'interface
    // affiche alors le nom du serveur seul.
    Ok(Connected { node: host.clone(), ip: String::new() })
}

#[tauri::command]
async fn disconnect(app: State<'_, App>) -> Result<()> {
    let id = app
        .session_id
        .lock()
        .unwrap()
        .clone()
        .or_else(|| cfg_get("session-id"));

    // Le tunnel tombe d'abord : la session cÃ´tÃ© master est secondaire.
    let (rx, tx) = app.tunnel.lock().unwrap().down()?;

    if let Some(id) = id {
        let _ = app
            .auth_call(
                reqwest::Method::POST,
                &format!("/sessions/{id}/disconnect"),
                Some(json!({ "bytes_in": rx, "bytes_out": tx })),
            )
            .await;
    }
    *app.session_id.lock().unwrap() = None;
    cfg_del("session-id");
    Ok(())
}

#[derive(Serialize)]
struct Protection {
    /// "off" : rien n'est montÃ©. "on" : tunnel actif.
    /// "blocked" : le tunnel est tombÃ© et le pare-feu retient tout le trafic.
    state: &'static str,
    node: String,
}

/// Le tunnel survit Ã  la fermeture de la fenÃªtre : au lancement, le client
/// demande au service ce qui tourne rÃ©ellement plutÃ´t que de repartir de zÃ©ro.
#[tauri::command]
fn tunnel_status(app: State<'_, App>) -> Protection {
    let node = cfg_get("node-name").unwrap_or_else(|| "node1".into());

    let Ok(st) = app.tunnel.lock().unwrap().status() else {
        return Protection { state: "off", node };
    };

    if st.up {
        if let Some(id) = cfg_get("session-id") {
            *app.session_id.lock().unwrap() = Some(id);
        }
        return Protection { state: "on", node };
    }

    if st.blocked {
        return Protection { state: "blocked", node };
    }

    Protection { state: "off", node }
}

#[tauri::command]
async fn logout(app: State<'_, App>) -> Result<()> {
    let _ = app.tunnel.lock().unwrap().down();
    cfg_del("session-id");
    app.clear();
    Ok(())
}

/// Suppression dÃ©finitive, confirmÃ©e par le mot de passe comme dans l'app mobile.
#[tauri::command]
async fn delete_account(password: String, app: State<'_, App>) -> Result<()> {
    app.auth_call(
        reqwest::Method::DELETE,
        "/auth/me",
        Some(json!({ "password": password })),
    )
    .await?;

    let _ = app.tunnel.lock().unwrap().down();
    cfg_del("session-id");
    app.clear();
    // La clÃ© et l'appareil n'ont plus d'existence cÃ´tÃ© serveur.
    kr_del("wireguard-private-key");
    cfg_del("device-id");
    Ok(())
}

#[tauri::command]
fn open_url(path: String, app: tauri::AppHandle) {
    let _ = tauri_plugin_opener::OpenerExt::opener(&app)
        .open_url(format!("{SITE}{path}"), None::<&str>);
}

// ============================================================ tunnel

#[cfg(unix)]
mod tunnel {
    use super::Result;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    const SOCKET: &str = "/var/run/deliriuum-direct.sock";

    pub struct Status {
        pub up: bool,
        /// Le pare-feu bloque tout : le tunnel est tombÃ© sans Ãªtre coupÃ©.
        pub blocked: bool,
        pub rx: u64,
        pub tx: u64,
    }

    /// Une requÃªte, une rÃ©ponse. Le service dÃ©tient le tunnel : ce client
    /// n'a aucun privilÃ¨ge et ne fait que lui parler.
    fn call(req: serde_json::Value) -> Result<serde_json::Value> {
        let stream = UnixStream::connect(SOCKET).map_err(|_| {
            "Le service Deliriuum n'est pas actif. RÃ©installe-le ou redÃ©marre l'ordinateur."
                .to_string()
        })?;

        let mut out = stream
            .try_clone()
            .map_err(|_| "Communication impossible avec le service.".to_string())?;
        writeln!(out, "{req}").map_err(|_| "Communication impossible avec le service.".to_string())?;

        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|_| "Le service n'a pas rÃ©pondu.".to_string())?;

        let v: serde_json::Value =
            serde_json::from_str(&line).map_err(|_| "RÃ©ponse illisible du service.".to_string())?;

        if v["ok"].as_bool() == Some(true) {
            Ok(v)
        } else {
            Err(v["error"]
                .as_str()
                .unwrap_or("Le tunnel n'a pas pu Ãªtre Ã©tabli.")
                .to_string())
        }
    }

    #[derive(Default)]
    pub struct Backend;

    impl Backend {
        pub fn up(&mut self, config: String) -> Result<()> {
            call(serde_json::json!({ "cmd": "up", "config": config })).map(|_| ())
        }

        /// Renvoie les compteurs relevÃ©s juste avant la coupure, que le client
        /// remonte ensuite au master.
        pub fn down(&mut self) -> Result<(u64, u64)> {
            let v = call(serde_json::json!({ "cmd": "down" }))?;
            Ok((v["rx"].as_u64().unwrap_or(0), v["tx"].as_u64().unwrap_or(0)))
        }

        pub fn status(&self) -> Result<Status> {
            let v = call(serde_json::json!({ "cmd": "status" }))?;
            Ok(Status {
                up: v["up"].as_bool().unwrap_or(false),
                blocked: v["blocked"].as_bool().unwrap_or(false),
                rx: v["rx"].as_u64().unwrap_or(0),
                tx: v["tx"].as_u64().unwrap_or(0),
            })
        }
    }
}

// ============================================================ entrÃ©e


#[cfg(windows)]
mod tunnel {
    use super::Result;
    use serde_json::Value;
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader, Write};

    const PIPE: &str = r"\\.\pipe\deliriuum-direct";

    pub struct Status {
        pub up: bool,
        pub blocked: bool,
        pub rx: u64,
        pub tx: u64,
    }

    fn call(req: serde_json::Value) -> Result<Value> {
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(PIPE)
            .map_err(|_| "Le service Deliriuum Direct n'est pas actif.".to_string())?;

        let request = format!("{req}\n");
        pipe.write_all(request.as_bytes())
            .map_err(|_| "Impossible d'envoyer la commande.".to_string())?;
        pipe.flush()
            .map_err(|_| "Impossible d'envoyer la commande.".to_string())?;

        let mut reader = BufReader::new(pipe);
        let mut line = String::new();
        reader.read_line(&mut line)
            .map_err(|_| "Impossible de lire la réponse.".to_string())?;

        let value: Value = serde_json::from_str(&line)
            .map_err(|_| "Réponse invalide du service.".to_string())?;

        if value["ok"].as_bool() == Some(false) {
            return Err(value["error"]
                .as_str()
                .unwrap_or("Erreur du service Deliriuum.")
                .to_string());
        }

        Ok(value)
    }

    #[derive(Default)]
    pub struct Backend;

    impl Backend {
        pub fn up(&mut self, config: String) -> Result<()> {
            call(serde_json::json!({
                "cmd": "up",
                "config": config
            })).map(|_| ())
        }

        pub fn down(&mut self) -> Result<(u64, u64)> {
            let v = call(serde_json::json!({ "cmd": "down" }))?;
            Ok((
                v["rx"].as_u64().unwrap_or(0),
                v["tx"].as_u64().unwrap_or(0),
            ))
        }

        pub fn status(&self) -> Result<Status> {
            let v = call(serde_json::json!({ "cmd": "status" }))?;
            Ok(Status {
                up: v["up"].as_bool().unwrap_or(false),
                blocked: v["blocked"].as_bool().unwrap_or(false),
                rx: v["rx"].as_u64().unwrap_or(0),
                tx: v["tx"].as_u64().unwrap_or(0),
            })
        }
    }
}
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(App::default())
        .invoke_handler(tauri::generate_handler![
            login,
            register,
            resend_verification,
            forgot_password,
            session,
            connect,
            disconnect,
            tunnel_status,
            logout,
            delete_account,
            open_url
        ])
        // Fermer la fenÃªtre ne coupe pas la protection : le service garde le
        // tunnel, comme chez Mullvad ou Proton. Seul un clic sur Â« ProtÃ©gÃ© Â»
        // ou la suppression du compte l'arrÃªtent.
        .run(tauri::generate_context!())
        .expect("Deliriuum Direct n'a pas pu dÃ©marrer");
}





