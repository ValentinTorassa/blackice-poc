#!/bin/bash
# Command Line Tools only. No download, installation, activation or identity signing.
set -euo pipefail
MACOS_SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
    echo 'Build on macOS with the Command Line Tools installed.' >&2
    exit 1
fi
if [[ $# -gt 1 ]]; then
    echo 'usage: macos/build.sh [output-directory]' >&2
    exit 1
fi
BUILD_DIR="${1:-$MACOS_SOURCE_DIR/build}"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
BUILD_ARCH="$(uname -m)"
case "$BUILD_ARCH" in arm64|x86_64) ;; *) echo 'Unsupported build architecture' >&2; exit 1 ;; esac
mkdir -p "$BUILD_DIR"
BUILD_DIR="$(cd -- "$BUILD_DIR" && pwd)"
APP_DIR="$BUILD_DIR/Blackice.app"
EXTENSION_DIR="$APP_DIR/Contents/Library/SystemExtensions/com.valentorassa.blackice.filter.systemextension"
# Do not leave an old signed bundle/provisioning profile under a fresh unsigned build.
if [[ -e "$APP_DIR" ]]; then
    echo 'Output app already exists; choose a fresh build directory.' >&2
    exit 1
fi
mkdir -p "$APP_DIR/Contents/MacOS" "$EXTENSION_DIR/Contents/MacOS" "$BUILD_DIR/module-cache"
COMMON=(-sdk "$SDK_PATH" -target "$BUILD_ARCH-apple-macosx13.0" -swift-version 5
        -warnings-as-errors -O -module-cache-path "$BUILD_DIR/module-cache")
SHARED=("$MACOS_SOURCE_DIR"/Shared/*.swift)
xcrun swiftc "${COMMON[@]}" -module-name BlackiceFilter \
    "${SHARED[@]}" "$MACOS_SOURCE_DIR"/FilterExtension/*.swift \
    -framework Foundation -framework CryptoKit -framework LocalAuthentication -framework Network -framework NetworkExtension -framework Security \
    -o "$EXTENSION_DIR/Contents/MacOS/BlackiceFilter"
xcrun swiftc "${COMMON[@]}" -module-name BlackiceApp \
    "${SHARED[@]}" "$MACOS_SOURCE_DIR/Host/main.swift" \
    -framework Foundation -framework CryptoKit -framework LocalAuthentication -framework NetworkExtension -framework Security -framework SystemExtensions \
    -o "$APP_DIR/Contents/MacOS/BlackiceApp"
cp "$MACOS_SOURCE_DIR/Resources/Host-Info.plist" "$APP_DIR/Contents/Info.plist"
cp "$MACOS_SOURCE_DIR/Resources/Filter-Info.plist" "$EXTENSION_DIR/Contents/Info.plist"
plutil -lint "$APP_DIR/Contents/Info.plist" "$EXTENSION_DIR/Contents/Info.plist" \
    "$MACOS_SOURCE_DIR/Resources/Host.entitlements" "$MACOS_SOURCE_DIR/Resources/Filter.entitlements"
echo "Built, unsigned: $APP_DIR"
echo 'No Developer ID, entitlements or profiles applied; no extension installed or activated.'
echo 'Apple silicon linkers may add an ad hoc execution signature; this grants no Network Extension capability.'
