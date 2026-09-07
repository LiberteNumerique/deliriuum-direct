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
  -destination "generic/platform=macOS" \
  ARCHS="arm64 x86_64" \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO \
  build

SYSTEMEXT="$DERIVED_DATA/Build/Products/Release/com.deliriuum.direct.PacketTunnel.systemextension"

if [ ! -d "$SYSTEMEXT" ]; then
  echo "ERREUR : com.deliriuum.direct.PacketTunnel.systemextension introuvable."
  exit 1
fi

echo "==> Extension générée :"
echo "$SYSTEMEXT"

mkdir -p "$STAGING_DIR"

rm -rf "$STAGING_SYSTEMEXT"
cp -R "$SYSTEMEXT" "$STAGING_SYSTEMEXT"

test -f \
  "$STAGING_SYSTEMEXT/Contents/MacOS/DeliriuumPacketTunnel"

echo "==> Extension copiée dans Tauri"

cd "$TAURI_DIR"

echo "==> Build de l'application Tauri"

cargo tauri build --target universal-apple-darwin --bundles app

FINAL_APP="$TAURI_DIR/target/universal-apple-darwin/release/bundle/macos/Deliriuum Direct.app"
FINAL_SYSTEMEXT="$FINAL_APP/Contents/Library/SystemExtensions/com.deliriuum.direct.PacketTunnel.systemextension"

echo
echo "=== INTEGRATION SYSTEM EXTENSION DANS L'APP ==="

mkdir -p "$FINAL_APP/Contents/Library/SystemExtensions"
rm -rf "$FINAL_SYSTEMEXT"
ditto "$STAGING_SYSTEMEXT" "$FINAL_SYSTEMEXT"

echo "Extension intégrée :"
echo "$FINAL_SYSTEMEXT"

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
