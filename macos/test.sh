#!/bin/bash
set -euo pipefail
MACOS_SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
    echo 'Run these tests on macOS with Command Line Tools.' >&2
    exit 1
fi
if [[ $# -gt 1 ]]; then echo 'usage: macos/test.sh [output-directory]' >&2; exit 1; fi
TEST_DIR="${1:-$MACOS_SOURCE_DIR/build/tests}"
mkdir -p "$TEST_DIR/module-cache"
xcrun swiftc -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -target "$(uname -m)-apple-macosx13.0" -swift-version 5 -warnings-as-errors -module-name BlackiceFilter \
    -module-cache-path "$TEST_DIR/module-cache" \
    "$MACOS_SOURCE_DIR"/Shared/*.swift "$MACOS_SOURCE_DIR/FilterExtension/FilterDataProvider.swift" \
    "$MACOS_SOURCE_DIR"/Tests/*.swift \
    -framework Foundation -framework CryptoKit -framework LocalAuthentication -framework Security -framework Network -framework NetworkExtension \
    -o "$TEST_DIR/app-filter-tests"
"$TEST_DIR/app-filter-tests"
