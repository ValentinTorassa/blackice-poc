#!/bin/bash
# Render a formula from reviewed release checksums; never download or install anything.
set -euo pipefail

if [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]]; then
    printf '%s\n' 'Usage: brew-formula.sh VERSION SHA256SUMS' \
        'VERSION is X.Y.Z with no leading v. Write stdout to the future tap Formula/blackice.rb.'
    exit 0
fi
if [[ $# -ne 2 ]]; then
    printf '%s\n' 'Usage: brew-formula.sh VERSION SHA256SUMS' >&2
    exit 2
fi

brew_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 -I -c '
import re
import sys
from pathlib import Path


def fail(message):
    print("brew-formula: " + message, file=sys.stderr)
    sys.exit(2)


version, sums_path, template_path = sys.argv[1:]
number = r"(?:0|[1-9][0-9]*)"
if len(version) > 100 or not re.fullmatch(
    rf"{number}\.{number}\.{number}",
    version,
):
    fail("version must be X.Y.Z; no prerelease, build metadata or leading v")

try:
    with open(sums_path, "rb") as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        fail("SHA256SUMS exceeds 1 MiB")
    manifest = raw.decode("ascii")
    template = Path(template_path).read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(str(error))

checksums = {}
for line_number, line in enumerate(manifest.split("\n"), 1):
    if line.endswith("\r"):
        line = line[:-1]
    if not line:
        continue
    match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)", line)
    if not match:
        fail(f"invalid SHA256SUMS line {line_number}; use sha256sum format and bare filenames")
    digest, filename = match.groups()
    if filename in checksums:
        fail(f"duplicate checksum entry: {filename}")
    if filename == "SHA256SUMS":
        fail("SHA256SUMS must not contain a checksum for itself")
    checksums[filename] = digest.lower()

assets = {
    "MAC_ARM_SHA": f"blackice-{version}-aarch64-macos",
    "MAC_INTEL_SHA": f"blackice-{version}-x86_64-macos",
    "LINUX_ARM_SHA": f"blackice-{version}-aarch64-linux",
    "LINUX_INTEL_SHA": f"blackice-{version}-x86_64-linux",
}
missing = [name for name in assets.values() if name not in checksums]
if missing:
    fail("missing checksum entries: " + ", ".join(missing))

values = {key: checksums[name] for key, name in assets.items()}
values["VERSION"] = version
for key, value in values.items():
    token = "@@" + key + "@@"
    if token not in template:
        fail("template is missing token " + token)
    template = template.replace(token, value)
if "@@" in template:
    fail("template contains an unresolved token")

# Nothing reaches stdout until all inputs and template substitutions are valid.
sys.stdout.write(template)
' "$1" "$2" "$brew_script_dir/../../packaging/homebrew/blackice.rb.in"
