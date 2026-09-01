#!/bin/bash
# Installe le service privilégié de Deliriuum Direct (macOS).
# Provisoire : l'installeur signé fera ceci à la place de l'utilisateur.
set -e

if [ "$EUID" -ne 0 ]; then
  echo "À lancer avec sudo :  sudo ./install.sh"
  exit 1
fi

command -v wg-quick >/dev/null || {
  echo "wireguard-tools manquant. Installe-le avec :  brew install wireguard-tools"
  exit 1
}

BIN=target/release/deliriuum-direct-service
[ -f "$BIN" ] || { echo "Compile d'abord :  cargo build --release"; exit 1; }

install -d /usr/local/libexec
install -m 755 "$BIN" /usr/local/libexec/deliriuum-direct-service
install -m 644 com.deliriuum.direct.service.plist /Library/LaunchDaemons/

launchctl bootout system/com.deliriuum.direct.service 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.deliriuum.direct.service.plist

echo "Service installé et démarré."
echo "Journal :  tail -f /var/log/deliriuum-direct.log"
