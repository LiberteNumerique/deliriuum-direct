#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

XCODE_PROJECT="$ROOT/macos/DeliriuumMac/DeliriuumMac.xcodeproj"
XCODE_SCHEME="DeliriuumMac"

DERIVED_DATA="$ROOT/macos/DeliriuumMac/.derivedData"

TAURI_DIR="$ROOT/src-tauri"
STAGING_DIR="$TAURI_DIR/macos"
STAGING_APPEX="$STAGING_DIR/DeliriuumPacketTunnel.appex"

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

APPEX="$DERIVED_DATA/Build/Products/Release/DeliriuumPacketTunnel.appex"

if [ ! -d "$APPEX" ]; then
  echo "ERREUR : DeliriuumPacketTunnel.appex introuvable."
  exit 1
fi

echo "==> Extension générée :"
echo "$APPEX"

mkdir -p "$STAGING_DIR"

rm -rf "$STAGING_APPEX"
cp -R "$APPEX" "$STAGING_APPEX"

test -f \
  "$STAGING_APPEX/Contents/MacOS/DeliriuumPacketTunnel"

echo "==> Extension copiée dans Tauri"

cd "$TAURI_DIR"

echo "==> Build de l'application Tauri"

cargo tauri build --bundles app

FINAL_APP="$TAURI_DIR/target/release/bundle/macos/Deliriuum Direct.app"
FINAL_APPEX="$FINAL_APP/Contents/PlugIns/DeliriuumPacketTunnel.appex"

if [ ! -d "$FINAL_APPEX" ]; then
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
echo "$FINAL_APPEX"
echo "=============================================="
