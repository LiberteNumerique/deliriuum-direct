#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

XCODE_PROJECT="$ROOT/macos/DeliriuumMac/DeliriuumMac.xcodeproj"
XCODE_SCHEME="DeliriuumMac"

DERIVED_DATA="$ROOT/macos/DeliriuumMac/.derivedData"

TAURI_DIR="$ROOT/src-tauri"
STAGING_DIR="$TAURI_DIR/macos"
STAGING_SYSTEMEXT="$STAGING_DIR/com.deliriuum.direct.PacketTunnel.systemextension"

echo "==> Nettoyage du DerivedData dédié"
rm -rf "$DERIVED_DATA"

echo "==> Build de l'extension macOS"

xcodebuild \
  -project "$XCODE_PROJECT" \
  -scheme "$XCODE_SCHEME" \
  -configuration Release \
  -derivedDataPath "$DERIVED_DATA" \
  CODE_SIGNING_ALLOWED=NO \
  build

APPEX="$DERIVED_DATA/Build/Products/Release/com.deliriuum.direct.PacketTunnel.systemextension"

if [ ! -d "$APPEX" ]; then
  echo "ERREUR : DeliriuumPacketTunnel.appex introuvable."
  exit 1
fi

echo "==> Extension générée :"
echo "$APPEX"

mkdir -p "$STAGING_DIR"

rm -rf "$STAGING_SYSTEMEXT"
cp -R "$APPEX" "$STAGING_SYSTEMEXT"

test -f \
  "$STAGING_SYSTEMEXT/Contents/MacOS/DeliriuumPacketTunnel"

echo "==> Extension copiée dans Tauri"

cd "$TAURI_DIR"

echo "==> Build de l'application Tauri"

cargo tauri build --bundles app

FINAL_APP="$TAURI_DIR/target/release/bundle/macos/Deliriuum Direct.app"
FINAL_SYSTEMEXT="$FINAL_APP/Contents/Library/SystemExtensions/com.deliriuum.direct.PacketTunnel.systemextension"

if [ ! -d "$FINAL_SYSTEMEXT" ]; then
  echo "ERREUR : l'extension n'est pas présente dans l'application Tauri."
  exit 1
fi

echo
echo "=============================================="
echo "Build macOS terminé"
echo
echo "$FINAL_APP"
echo
echo "Extension intégrée :"
echo "$FINAL_SYSTEMEXT"
echo "=============================================="
