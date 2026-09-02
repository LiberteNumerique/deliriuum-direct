# Deliriuum Direct

**Deliriuum Direct** est un VPN gratuit et open source développé par l'**Alliance pour les Libertés Numériques**.

Son objectif est simple : permettre à chacun de protéger son adresse IP vis-à-vis des sites consultés, avec une application aussi simple que possible à utiliser.

L'infrastructure VPN de Deliriuum est hébergée en **Islande**, chez **1984 Hosting**.

## Télécharger

### Windows

Deliriuum Direct est disponible pour :

- Windows x64 / AMD64
- Windows ARM64

Un installateur universel détecte automatiquement l'architecture de Windows.

➡️ [Télécharger la dernière version Windows](https://github.com/LiberteNumerique/deliriuum-direct/releases/latest/download/Deliriuum-Direct-Windows.exe)

Le fichier de contrôle SHA-256 est disponible ici :

➡️ [SHA-256 Windows](https://github.com/LiberteNumerique/deliriuum-direct/releases/latest/download/Deliriuum-Direct-Windows.exe.sha256)

### Linux

Des paquets Debian / Ubuntu sont disponibles pour :

- AMD64 / x86_64
- ARM64

➡️ [Télécharger Linux AMD64](https://github.com/LiberteNumerique/deliriuum-direct/releases/latest/download/Deliriuum-Direct-linux-amd64.deb)

➡️ [Télécharger Linux ARM64](https://github.com/LiberteNumerique/deliriuum-direct/releases/latest/download/Deliriuum-Direct-linux-arm64.deb)

### macOS

La version macOS est actuellement en cours de finalisation.

### Android et iOS

Les versions mobiles sont en cours de préparation et de validation avant publication sur les stores.

## Vérifier un téléchargement

Des sommes de contrôle sont fournies avec les versions publiées.

Sous Windows :

```powershell
Get-FileHash .\Deliriuum-Direct-Windows.exe -Algorithm SHA256
```

Sous Linux :

```bash
sha256sum Deliriuum-Direct-linux-amd64.deb
```

Comparez le résultat obtenu avec le fichier `.sha256` correspondant disponible dans la section Releases.

## Comment fonctionne Deliriuum Direct ?

Lorsqu'il est activé, Deliriuum Direct établit un tunnel VPN entre votre appareil et l'infrastructure Deliriuum.

Les sites Internet que vous consultez voient alors l'adresse IP de sortie du VPN au lieu de votre adresse IP publique habituelle.

Deliriuum Direct protège le trafic réseau de l'appareil sur lequel il est installé.

## Vie privée

Deliriuum Direct est développé autour d'un principe simple : protéger la vie privée de ses utilisateurs.

L'adresse IP de connexion des utilisateurs n'est pas enregistrée par Deliriuum.

Le code source est publié afin de permettre son examen, sa vérification et son audit.

L'infrastructure fera également l'objet d'un audit indépendant.

## Architecture du projet

```text
deliriuum-direct/
├── src/                  Interface utilisateur
├── src-tauri/            Application desktop Tauri / Rust
├── service/              Service VPN système
├── windows-universal/    Installateur Windows universel
├── macos/                Composants macOS / NetworkExtension
├── scripts/              Scripts de build
└── .github/workflows/    Builds automatisés
```

### Windows

Sous Windows, l'application communique avec un service système chargé de gérer le tunnel VPN.

Les architectures actuellement prises en charge sont :

- AMD64 / x86_64
- ARM64

Les composants Windows distribués sont signés numériquement.

### Linux

Sous Linux, Deliriuum Direct s'appuie notamment sur :

- `/dev/net/tun`
- WireGuard / boringtun
- le routage système
- `systemd-resolved`
- `nftables`

Un service privilégié gère le tunnel tandis que l'application utilisateur communique avec lui via un socket Unix.

### macOS

L'architecture macOS repose notamment sur :

- Tauri
- NetworkExtension
- NEVPNManager
- NEPacketTunnelProvider
- WireGuardKit

## Construire le projet

### Prérequis généraux

- Rust
- Cargo
- Tauri 2
- les outils de compilation propres au système cible

Pour ajouter une cible Rust Windows x64 :

```bash
rustup target add x86_64-pc-windows-msvc
```

### Build de l'application Windows x64

```bash
cd src-tauri
cargo build --release --target x86_64-pc-windows-msvc
cargo tauri bundle --target x86_64-pc-windows-msvc
```

### Build du service Windows x64

```bash
cd service
cargo build --release --target x86_64-pc-windows-msvc
```

### Linux

Les builds Linux AMD64 et ARM64 sont également produits via GitHub Actions.

## Sécurité

Si vous découvrez une vulnérabilité de sécurité, merci de ne pas publier immédiatement les détails dans une issue publique.

Contactez l'Alliance pour les Libertés Numériques afin de permettre l'analyse et la correction du problème avant toute divulgation publique.

## Licence

Deliriuum Direct est un logiciel libre distribué sous licence **GNU General Public License v3.0 (GPLv3)**.

## Alliance pour les Libertés Numériques

Deliriuum Direct est développé et maintenu par l'Alliance pour les Libertés Numériques, association engagée dans la défense des libertés fondamentales dans l'environnement numérique.

- Site de l'association : <https://libertenumerique.fr>
- Site Deliriuum : <https://deliriuum.com>
- Page Deliriuum Direct : <https://deliriuum.com/direct.html>

## Soutenir le projet

Deliriuum Direct est proposé gratuitement.

Le développement, l'hébergement de l'infrastructure et les actions de l'Alliance sont financés par les dons.

➡️ <https://deliriuum.com/soutenir.html>
