# Étape 1 — un vrai tunnel

Trois pièces : le client Tauri sans privilège, un service qui tourne en root et
détient le tunnel, une socket Unix entre les deux. Le tunnel survit à la
fermeture de la fenêtre, comme chez Mullvad et Proton.

## Installer

```bash
brew install wireguard-tools

cd service
cargo build --release
sudo ./install.sh
```

Vérifier que le service tourne :

```bash
sudo launchctl print system/com.deliriuum.direct.service | head -5
tail -f /var/log/deliriuum-direct.log
```

## Tester

Note ton adresse IP actuelle, par exemple sur ifconfig.me, puis lance le
client et clique sur **Me protéger**. L'adresse doit changer pour celle du
node islandais.

Ferme complètement la fenêtre : `wg show` doit toujours montrer l'interface.
Rouvre le client : il doit s'afficher **Protégé** sans que tu aies cliqué.

## Si ça ne marche pas

Le journal dit tout :

```bash
tail -50 /var/log/deliriuum-direct.log
```

- `wg-quick introuvable` → wireguard-tools n'est pas installé, ou le PATH du
  plist ne couvre pas ton installation Homebrew.
- `Le service Deliriuum n'est pas actif` côté client → le daemon n'a pas
  démarré, ou la socket n'est pas accessible à ton utilisateur.
- Le tunnel monte mais rien ne passe → vérifie que le node accepte bien la
  clé publique, et que `AllowedIPs` couvre tout le trafic.

Arrêter le tunnel à la main, en cas de besoin :

```bash
sudo wg-quick down /etc/wireguard/deliriuum.conf
```

## Ce qui reste

**Le kill switch.** Aujourd'hui, si le tunnel tombe, le trafic repart en clair
sans prévenir. C'est le manque le plus important, et il se traite avec `pf` sur
macOS, WFP sur Windows, `nftables` sur Linux. À faire avant toute distribution.

**boringtun embarqué**, pour supprimer la dépendance à wireguard-tools. C'est
l'étape 2 : l'utilisateur n'installera plus rien.

**La vérification de l'appelant.** Le service accepte aujourd'hui n'importe
quel processus local d'un utilisateur autorisé. Il devra vérifier la signature
du binaire client.

**Windows et Linux.** Le protocole entre client et service ne change pas, seule
la couche d'accroche au système diffère : service Windows et tube nommé,
unité systemd et socket Unix.

**La reconnexion au réveil** de la machine, et la relance du tunnel au
démarrage si l'utilisateur l'avait laissé actif.
