#!/bin/bash
set -e
[ "$EUID" -eq 0 ] || { echo "À lancer avec sudo"; exit 1; }
launchctl bootout system/com.deliriuum.direct.service 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.deliriuum.direct.service.plist
rm -f /usr/local/libexec/deliriuum-direct-service
rm -f /var/run/deliriuum-direct.sock /etc/wireguard/deliriuum.conf
echo "Service retiré."
