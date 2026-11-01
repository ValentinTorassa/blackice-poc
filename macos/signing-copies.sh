#!/bin/bash
# Writes the Team ID-dependent copies that signing needs: the extension Info.plist with
# NEMachServiceName, and both entitlements files with the app group. Never signs, installs or
# activates anything, and never edits the templates in macos/Resources.
set -euo pipefail
MACOS_SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
    echo 'Run on macOS: this uses PlistBuddy and plutil.' >&2
    exit 1
fi
if [[ $# -ne 2 ]]; then
    echo 'usage: macos/signing-copies.sh TEAM_ID output-directory' >&2
    exit 1
fi
TEAM_ID="$1"
OUT_DIR="$2"
# Same rule as validTeamID in Shared/AppConfiguration.swift.
if [[ ! "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
    echo 'TEAM_ID must be 10 uppercase letters or digits.' >&2
    exit 1
fi
if [[ -e "$OUT_DIR" ]]; then
    echo 'Output directory already exists; choose a fresh one.' >&2
    exit 1
fi
APP_GROUP="$TEAM_ID.com.valentorassa.blackice"
MACH_SERVICE="$APP_GROUP.filter"
mkdir -p "$OUT_DIR"
for name in Filter-Info.plist Filter.entitlements Host.entitlements; do
    cp "$MACOS_SOURCE_DIR/Resources/$name" "$OUT_DIR/$name"
done
BUDDY=/usr/libexec/PlistBuddy
"$BUDDY" -c "Add :NetworkExtension:NEMachServiceName string $MACH_SERVICE" "$OUT_DIR/Filter-Info.plist"
for name in Filter.entitlements Host.entitlements; do
    "$BUDDY" -c 'Add :com.apple.security.application-groups array' \
        -c "Add :com.apple.security.application-groups:0 string $APP_GROUP" "$OUT_DIR/$name"
done
plutil -lint "$OUT_DIR/Filter-Info.plist" "$OUT_DIR/Filter.entitlements" "$OUT_DIR/Host.entitlements"
test "$("$BUDDY" -c 'Print :NetworkExtension:NEMachServiceName' "$OUT_DIR/Filter-Info.plist")" = "$MACH_SERVICE"
for name in Filter.entitlements Host.entitlements; do
    test "$("$BUDDY" -c 'Print :com.apple.security.application-groups:0' "$OUT_DIR/$name")" = "$APP_GROUP"
done
echo "Wrote signing copies to $OUT_DIR"
echo "NEMachServiceName $MACH_SERVICE; app group $APP_GROUP"
echo 'Still from the provisioning profiles: com.apple.application-identifier and com.apple.developer.team-identifier.'
echo 'Unverified until a signed run shows the extension starting.'
