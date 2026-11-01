#!/bin/bash
# Writes the Team ID-dependent copies that signing needs: the extension Info.plist with
# NEMachServiceName and the extension entitlements with the app group that name sits under. The
# host never connects to that service, so its entitlements stay as the template. Never signs,
# installs or activates anything, and never edits the templates in macos/Resources.
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
"$BUDDY" -c 'Add :com.apple.security.application-groups array' \
    -c "Add :com.apple.security.application-groups:0 string $APP_GROUP" "$OUT_DIR/Filter.entitlements"
plutil -lint "$OUT_DIR/Filter-Info.plist" "$OUT_DIR/Filter.entitlements" "$OUT_DIR/Host.entitlements"
test "$("$BUDDY" -c 'Print :NetworkExtension:NEMachServiceName' "$OUT_DIR/Filter-Info.plist")" = "$MACH_SERVICE"
test "$("$BUDDY" -c 'Print :com.apple.security.application-groups:0' "$OUT_DIR/Filter.entitlements")" = "$APP_GROUP"
cmp -s "$MACOS_SOURCE_DIR/Resources/Host.entitlements" "$OUT_DIR/Host.entitlements"
echo "Wrote signing copies to $OUT_DIR"
echo "NEMachServiceName $MACH_SERVICE; app group $APP_GROUP (extension only)"
echo 'Still from the provisioning profiles: com.apple.application-identifier and com.apple.developer.team-identifier.'
echo 'Unverified until a signed run shows the extension starting.'
