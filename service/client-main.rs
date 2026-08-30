#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Deliriuum Direct — client de bureau.
//!
//! Câblé sur la même API que l'application Android : master.deliriuum.com,
//! jetons access/refresh, appareils puis sessions.
//!
//! La clé privée WireGuard est générée ici et stockée dans le trousseau du
//! système. Elle ne part jamais sur le réseau : seule la publique est envoyée.
//!
//! État : le parcours complet est câblé, le tunnel est simulé.
//! Le seul endroit à remplacer est `tunnel::Backend`.

use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{Manager, State};
use x25519_dalek::{PublicKey, StaticSecret};

const MASTER: &str = "https://master.deliriuum.com";
const SITE: &str = "https://deliriuum.com";
const KEYRING: &str = "com.deliriuum.direct";

/// Les erreurs remontées au JavaScript sont des phrases affichables telles quelles.
type Result<T> = std::result::Result<T, String>;

// ============================================================ état

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
/// Ce qui n'est pas un secret n'a rien à faire dans le trousseau : chaque
/// entrée supplémentaire est une demande d'autorisation de plus pour l'utilisateur.
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
    keyring::Entry::new(KEYRING, key).map_err(|_| "Trousseau du système inaccessible.".into())
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

/// Extrait le champ `detail` renvoyé par le master, sinon un message générique.
fn detail_of(status: u16, body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["detail"].as_str().map(str::to_string))
        .unwrap_or_else(|| match status {
            401 => "E-mail ou mot de passe incorrect.".into(),
            409 => "Ce compte existe déjà.".into(),
            429 => "Trop de tentatives. Réessaie dans quelques minutes.".into(),
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
        .map_err(|_| "Serveur injoignable. Vérifie ta connexion.".to_string())?;

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
            .ok_or_else(|| "Ta session a expiré. Reconnecte-toi.".into())
    }

    /// Seul le jeton de rafraîchissement est persisté. L'accès, de courte durée,
    /// reste en mémoire : une entrée de trousseau en moins, sans rien perdre.
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
            .ok_or_else(|| "Ta session a expiré. Reconnecte-toi.".to_string())?;

        let (status, body) = send(
            reqwest::Method::POST,
            "/auth/refresh",
            Some(json!({ "refresh_token": refresh })),
            None,
        )
        .await?;

        if status == 401 || status == 403 {
            self.clear();
            return Err("Ta session a expiré. Reconnecte-toi.".into());
        }
        if !(200..300).contains(&status) {
            return Err(detail_of(status, &body));
        }

        let v: Value = serde_json::from_str(&body).map_err(|_| "Réponse illisible.".to_string())?;
        self.store(Tokens {
            access: v["access_token"].as_str().unwrap_or_default().to_string(),
            refresh: v["refresh_token"].as_str().unwrap_or_default().to_string(),
        });
        Ok(())
    }

    /// Requête authentifiée : sur 401, renouvelle une fois puis rejoue.
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

// ============================================================ clés et appareil

/// Génère la paire au premier lancement, la conserve ensuite.
fn keypair() -> Result<(StaticSecret, String)> {
    let secret = match kr_get("wireguard-private-key") {
        Some(stored) => {
            let raw = B64
                .decode(stored)
                .map_err(|_| "La clé enregistrée est illisible.".to_string())?;
            let bytes: [u8; 32] = raw
                .try_into()
                .map_err(|_| "La clé enregistrée est illisible.".to_string())?;
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

/// Nom lisible dans « Mes appareils », côté master.
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
        Some(h) => format!("{h} · Direct {os}"),
        None => format!("Deliriuum Direct · {os}"),
    }
}

/// Génère une nouvelle paire et remplace celle du trousseau.
fn rotate_keypair() -> Result<(StaticSecret, String)> {
    kr_del("wireguard-private-key");
    keypair()
}

/// Résout l'appareil de cette machine côté master, sans jamais montrer de
/// conflit à l'utilisateur.
///
/// Le master indexe les appareils par clé publique. Si le fichier local
/// d'identifiant est perdu — réinstallation, nouveau profil, dossier effacé —
/// une création naïve renverrait « clé déjà utilisée ». On cherche donc
/// d'abord l'appareil par sa clé, et on ne crée qu'en dernier recours.
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

    // 2. Sinon, notre clé publique est peut-être déjà enregistrée.
    if let Some(found) = list
        .iter()
        .find(|d| d["public_key"].as_str() == Some(public.as_str()))
        .and_then(|d| d["id"].as_str())
    {
        cfg_set("device-id", found);
        return Ok((secret, found.to_string()));
    }

    // 3. Création.
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
                .ok_or("Le serveur n'a pas renvoyé d'identifiant d'appareil.")?
                .to_string();
            cfg_set("device-id", &id);
            Ok((secret, id))
        }

        // 4. Refus malgré tout : la clé appartient à un autre compte, ou à un
        //    appareil que ce compte ne voit pas. On repart d'une clé neuve
        //    plutôt que d'afficher un conflit incompréhensible.
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
                .ok_or("Le serveur n'a pas renvoyé d'identifiant d'appareil.")?
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

    let v: Value = serde_json::from_str(&body).map_err(|_| "Réponse illisible.".to_string())?;
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

/// L'inscription ne renvoie pas de jeton : le master crée un compte à vérifier
/// par e-mail. On tente ensuite une connexion, qui échouera tant que le compte
/// n'est pas validé — c'est ce que l'écran de vérification annonce.
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

/// Envoie le lien de réinitialisation. Le master renvoie un message `detail`
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
        // une paire fraîche. Un seul accès au trousseau par session.
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

    // Une session peut rester ouverte côté master si le client a été tué sans
    // se déconnecter. On la ferme puis on rejoue, une seule fois.
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
                // Si le second échec dit autre chose, c'est lui qui informe.
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

    // L'IP publique de sortie n'est pas renvoyée par le master ; l'interface
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

    // Le tunnel tombe d'abord : la session côté master est secondaire.
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

/// Le tunnel survit à la fermeture de la fenêtre : au lancement, le client
/// demande au service ce qui tourne réellement plutôt que de repartir de zéro.
#[tauri::command]
fn tunnel_status(app: State<'_, App>) -> Option<Connected> {
    let st = app.tunnel.lock().unwrap().status().ok()?;
    if !st.up {
        return None;
    }
    if let Some(id) = cfg_get("session-id") {
        *app.session_id.lock().unwrap() = Some(id);
    }
    Some(Connected {
        node: cfg_get("node-name").unwrap_or_else(|| "node1".into()),
        ip: String::new(),
    })
}

#[tauri::command]
async fn logout(app: State<'_, App>) -> Result<()> {
    let _ = app.tunnel.lock().unwrap().down();
    cfg_del("session-id");
    app.clear();
    Ok(())
}

/// Suppression définitive, confirmée par le mot de passe comme dans l'app mobile.
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
    // La clé et l'appareil n'ont plus d'existence côté serveur.
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

mod tunnel {
    use super::Result;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    const SOCKET: &str = "/var/run/deliriuum-direct.sock";

    pub struct Status {
        pub up: bool,
        pub rx: u64,
        pub tx: u64,
    }

    /// Une requête, une réponse. Le service détient le tunnel : ce client
    /// n'a aucun privilège et ne fait que lui parler.
    fn call(req: serde_json::Value) -> Result<serde_json::Value> {
        let stream = UnixStream::connect(SOCKET).map_err(|_| {
            "Le service Deliriuum n'est pas actif. Réinstalle-le ou redémarre l'ordinateur."
                .to_string()
        })?;

        let mut out = stream
            .try_clone()
            .map_err(|_| "Communication impossible avec le service.".to_string())?;
        writeln!(out, "{req}").map_err(|_| "Communication impossible avec le service.".to_string())?;

        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|_| "Le service n'a pas répondu.".to_string())?;

        let v: serde_json::Value =
            serde_json::from_str(&line).map_err(|_| "Réponse illisible du service.".to_string())?;

        if v["ok"].as_bool() == Some(true) {
            Ok(v)
        } else {
            Err(v["error"]
                .as_str()
                .unwrap_or("Le tunnel n'a pas pu être établi.")
                .to_string())
        }
    }

    #[derive(Default)]
    pub struct Backend;

    impl Backend {
        pub fn up(&mut self, config: String) -> Result<()> {
            call(serde_json::json!({ "cmd": "up", "config": config })).map(|_| ())
        }

        /// Renvoie les compteurs relevés juste avant la coupure, que le client
        /// remonte ensuite au master.
        pub fn down(&mut self) -> Result<(u64, u64)> {
            let v = call(serde_json::json!({ "cmd": "down" }))?;
            Ok((v["rx"].as_u64().unwrap_or(0), v["tx"].as_u64().unwrap_or(0)))
        }

        pub fn status(&self) -> Result<Status> {
            let v = call(serde_json::json!({ "cmd": "status" }))?;
            Ok(Status {
                up: v["up"].as_bool().unwrap_or(false),
                rx: v["rx"].as_u64().unwrap_or(0),
                tx: v["tx"].as_u64().unwrap_or(0),
            })
        }
    }
}

// ============================================================ entrée

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
        // Fermer la fenêtre ne coupe pas la protection : le service garde le
        // tunnel, comme chez Mullvad ou Proton. Seul un clic sur « Protégé »
        // ou la suppression du compte l'arrêtent.
        .run(tauri::generate_context!())
        .expect("Deliriuum Direct n'a pas pu démarrer");
}
