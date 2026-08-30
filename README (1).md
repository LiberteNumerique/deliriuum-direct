# Deliriuum Direct

Client de bureau. Un compte, un bouton, tout l'appareil protégé.

## Lancer

```bash
npm create tauri-app@latest   # une seule fois, pour installer la chaîne d'outils
cd direct
npm run tauri dev
```

Le parcours complet est jouable dès maintenant : l'écran de compte, le bouton
de protection, l'état connecté. **Le tunnel est simulé** — `tunnel::Backend`
dans `src-tauri/src/main.rs` renvoie un succès sans rien monter.

Pour voir seulement l'interface, ouvrir `src/index.html` dans un navigateur :
un faux backend prend le relais.

## Ce qui est déjà fait

- Les trois écrans, aux couleurs de l'application Android.
- Génération de la clé X25519 au premier lancement, stockée dans le trousseau
  du système. **La clé privée ne part jamais sur le réseau.**
- Appels au master : `/api/auth/login`, `/api/auth/register`,
  `/api/direct/config` (le même endpoint que la page web).
- Session persistée : le mot de passe n'est pas redemandé à chaque lancement.
- Messages d'erreur en français, affichables tels quels.

## Ce qui reste

### 1. Le service privilégié

C'est le gros morceau. Une application graphique ne peut pas créer d'interface
réseau ni modifier le routage. Il faut un service installé une fois, qui tourne
avec les droits administrateur :

- **Windows** : service Windows, dialogue par tube nommé.
- **macOS** : daemon `launchd` dans `/Library/LaunchDaemons`, socket Unix.
- **Linux** : unité systemd, socket Unix.

Le service tient `boringtun`, crée l'interface, pousse la route par défaut,
et détient le kill switch. Vérifier la signature du binaire appelant : sans
cela, n'importe quel programme local peut lui demander de monter un tunnel.

### 2. Le kill switch

À faire dans le service et pas dans l'interface. Si le tunnel tombe ou si
l'application est tuée, le trafic doit être bloqué, pas repartir en clair.
WFP sur Windows, `pf` sur macOS, `nftables` sur Linux.

### 3. La signature

À lancer maintenant, les délais administratifs sont longs.

- **macOS** : compte Apple Developer, 99 $/an, plus la notarisation. Sans
  cela l'application ne s'ouvre pas.
- **Windows** : certificat de signature de code. Un certificat OV coûte
  quelques centaines d'euros par an et met plusieurs semaines à accumuler
  la réputation SmartScreen ; un certificat EV coûte plus cher mais évite
  l'avertissement dès le premier jour.

### 4. Détails

- Icônes : `src-tauri/icons/`, générables avec `npm run tauri icon logo.png`.
- L'IP de sortie affichée vient du master. S'il ne la renvoie pas, la faire
  vérifier par le client après connexion plutôt que de laisser un tiret.
- Reconnexion automatique au réveil de la machine.
- Mise à jour : `tauri-plugin-updater`, à brancher avant la première
  distribution publique.

## Note

Ce code n'a pas été compilé — l'environnement où il a été écrit n'a pas de
réseau, donc pas de dépendances. Attendre quelques ajustements de types au
premier `cargo build`, en particulier sur `keyring` 3 et `tauri` 2, dont les
API ont bougé récemment.
