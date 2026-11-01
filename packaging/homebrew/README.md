# Homebrew formula preparation

This directory prepares a binary formula for the future
ValentinTorassa/homebrew-tap tap. It does not create that repository or
publish a release. The template is not an installable formula until rendered
with the checksums of a reviewed release.

From this checkout, with Python 3 available:

~~~sh
scripts/release/brew-formula.sh 1.2.3 /path/to/reviewed/SHA256SUMS > /tmp/blackice.rb
~~~

Review the output before copying it to Formula/blackice.rb in the tap that the
owner creates. The intended install command after publication is:

~~~sh
brew install valentintorassa/tap/blackice
~~~

The version must be X.Y.Z with no leading v, prerelease or build metadata,
matching the release workflow's vX.Y.Z tags. URLs use the tag vVERSION in
ValentinTorassa/blackice. The renderer reads local files and writes only stdout;
it never downloads, builds, installs, tags, pushes or publishes.

## Required release files

SHA256SUMS must contain exactly one entry for each of:

~~~text
blackice-VERSION-aarch64-macos
blackice-VERSION-x86_64-macos
blackice-VERSION-aarch64-linux
blackice-VERSION-x86_64-linux
~~~

Use the usual sha256sum format: 64 hexadecimal digits, a space, a space or
asterisk, then a bare filename. Extra distinct entries are permitted. Missing,
duplicate, malformed and path-containing entries fail before any formula is
printed. SHA256SUMS must not include itself. The full release also contains
blackice-linux-helper-VERSION-x86_64-linux and SHA256SUMS; the helper entry is
accepted but unused by this CLI-only formula. A manifest containing only the
four CLI entries also works. The manifest is an input to the renderer, not an
installed resource. Setup and teardown scripts are not release assets.

The renderer validates syntax and completeness, not provenance or review.
Use the authenticated release manifest. Never substitute a development hash or
a checksum from an unreviewed download to make a release formula render.

## Manual Linux setup

Homebrew installs only the CLI on every OS/CPU, as bin/blackice with mode 0755.
No helper, setup script, teardown script or checksum bundle is downloaded or
installed by the formula. There is no postinstall, service or package-manager
sudo/setcap call. A Homebrew upgrade changes only the CLI, not any separately
installed privileged helper.

Linux arm64 ships only the CLI until an arm64 Linux run verifies task scopes.
It must not use the x86_64 setup procedure below.

On Linux x86_64, check out the matching tag and use the Zig version it requires.
Verify the release's SHA256SUMS attestation against that tag and checkout commit,
then verify the downloaded files. Build the helper in the checkout and compare
its SHA-256 with the manifest's versioned x86_64 helper entry. Only after that
match should the checkout's setup script run with that digest as its second
argument. Review docs/linux.md and the checkout's scripts first.

This example uses version 1.2.3; replace it with the formula's release version.
It uses a fresh checkout and stops on a failed check. These are instructions for
the corresponding published release, not a claim that 1.2.3 is already available.
Homebrew never executes this block or prints a sudo command in its caveats:

~~~sh
(
  set -eu
  test "$(uname -s)" = Linux
  test "$(uname -m)" = x86_64
  git clone --branch v1.2.3 --depth 1 https://github.com/ValentinTorassa/blackice.git blackice-v1.2.3
  cd blackice-v1.2.3
  release_dir="$PWD/out/release-v1.2.3"
  mkdir -p "$release_dir"
  gh release download v1.2.3 --repo ValentinTorassa/blackice --dir "$release_dir"
  (
    cd "$release_dir"
    gh attestation verify SHA256SUMS --repo ValentinTorassa/blackice --signer-workflow ValentinTorassa/blackice/.github/workflows/release.yml --source-ref refs/tags/v1.2.3 --source-digest "$(git rev-parse HEAD)" --deny-self-hosted-runners
    sha256sum -c SHA256SUMS
  )
  zig build -Doptimize=ReleaseSafe
  helper_sha256="$(awk '$2 == "blackice-linux-helper-1.2.3-x86_64-linux" { print $1 }' "$release_dir/SHA256SUMS")"
  test "${#helper_sha256}" -eq 64
  printf '%s  zig-out/bin/blackice-linux-helper\n' "$helper_sha256" | sha256sum -c -
  sudo ./scripts/linux-setup.sh "$USER" "$helper_sha256"
)
~~~

The setup digest comes from the independently verified release manifest, never
from formula metadata. Scripts are neither flat release assets nor separately
attested; their integrity comes from the matching tag checkout. The existing
two-argument setup script uses that checkout's zig-out/bin/blackice-linux-helper.
Teardown remains a manual, reviewed operation from the checkout.

The macOS formula contains only the CLI; it does not ship or activate the
unsigned Network Extension app filter.

## Validation

~~~sh
python3 packaging/homebrew/test_renderer.py
bash -n scripts/release/brew-formula.sh
ruby -c /tmp/blackice.rb
brew style /tmp/blackice.rb
~~~

Run the Homebrew checks only where their tooling is already installed. Disable
auto-update and analytics for preparation; do not install gems, tap repositories
or the formula just to run these checks. Current Homebrew requires a formula
name for audit, so after the owner creates and populates the tap, run:

~~~sh
brew audit --strict --formula valentintorassa/tap/blackice
~~~

Online audits and brew test remain release gates with published assets and a
separate authorized install. The formula's test block runs blackice version
without starting a scope. Synthetic manifests can validate rendering and
platform selection, but do not establish release provenance or runtime support.

After an authorized release install, compare the installed CLI's bytes
against the release checksums on each OS/architecture.
skip_clean preserves the shipped executable during Homebrew
cleaning; the release installation check still needs to verify the final bytes.

References: [Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
(platform blocks and nounzip), and
[checksum requirements](https://docs.brew.sh/Checksum-Requirements).
