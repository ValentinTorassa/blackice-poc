# npm distribution

Version **0.1.0** uses a launcher package and four optional platform packages. The scripts here prepare and audit local tarballs; they do not publish, reserve names, log in to npm, build binaries or change a privileged installation. The checked-in manifests are private templates, not publishable packages.

| Output directory | Default package | Platform | Payload beyond metadata, README and license |
| --- | --- | --- | --- |
| `blackice/` | `@legios/blackice` | Node.js 22+ | 33-line launcher; command `blackice` |
| `darwin-arm64/` | `@legios/blackice-darwin-arm64` | macOS arm64 | `bin/blackice` |
| `darwin-x64/` | `@legios/blackice-darwin-x64` | macOS x64 | `bin/blackice` |
| `linux-x64/` | `@legios/blackice-linux-x64` | Linux x64 | `bin/blackice` |
| `linux-arm64/` | `@legios/blackice-linux-arm64` | Linux arm64 | `bin/blackice` |

Every archive has exactly four files. **No npm package contains a Linux helper, setup/teardown script or setup bundle.** Linux arm64 supplies the CLI only; task scopes on that CPU remain unsupported until a reviewed helper and runtime evidence exist.

The launcher has no regular dependencies. Its optional dependencies use exact matching versions, and its generated `blackicePlatforms` map selects the complete package name for each OS/CPU. Platform manifests declare `os` and `cpu`. There are no lifecycle scripts, registry fallback, PATH fallback or runtime downloads. npm fetches packages normally during installation; package code performs no additional downloads or setup. Node's architecture selects the binary, so use a matching Node installation.

## Release input and preparation

The four raw CLI assets and `SHA256SUMS` are required:

```text
blackice-0.1.0-aarch64-macos
blackice-0.1.0-x86_64-macos
blackice-0.1.0-x86_64-linux
blackice-0.1.0-aarch64-linux
SHA256SUMS
```

The full release also contains `blackice-linux-helper-0.1.0-x86_64-linux`, which may appear in the manifest but is never read or copied into npm. The preparer also accepts a CLI-only manifest. Setup/teardown scripts and an ARM helper are not release assets and are rejected as manifest entries. Scripts come from the tag checkout. An absent ARM helper does not block CLI packaging.

Verify release attestations before preparing public packages. The preparer checks CLI integrity, not provenance: its output records `verification: "sha256-only"`. A locally produced checksum file does not establish release identity. Label local fixtures as test inputs, not attested releases.

From the repository root:

```sh
node packaging/npm/prepare.mjs \
  --release-dir /absolute/path/to/verified-release \
  --out-dir out/npm-0.1.0 \
  --version 0.1.0 --scope @legios --name @legios/blackice

node packaging/npm/pack.mjs \
  --prepared-dir out/npm-0.1.0 \
  --out-dir out/npm-tarballs-0.1.0
```

`--version`, `--scope` and `--name` default to the values shown. The preparer supports an explicitly selected scope and main name while keeping the command name `blackice`; platform packages retain the `blackice-<platform>` prefix. Changing `--scope` alone does not change the launcher name. The release workflow requires `NPM_SCOPE=@legios` and `NPM_PACKAGE_NAME=@legios/blackice`, and refuses different values. The operator must own the `legios` organization; if that check fails, stop and ask the release lead. Never switch scopes automatically.

After publication, the install command is `npm install --global --ignore-scripts @legios/blackice@0.1.0`. The launcher tarball is `legios-blackice-0.1.0.tgz` and remains last in `publish-order.txt`.

Both output directories must be new. Required checksums must occur exactly once; duplicate, unknown, path-bearing and missing CLI entries are rejected. Versions must be stable `X.Y.Z`. Inputs must be bounded regular files, not symlinks. The preparer hashes each CLI and copies that same in-memory snapshot, preserving its bytes with explicit executable permissions, then atomically moves the completed output into place. `manifest.json` records source asset hashes and platform-first package order.

The packer checks exact identities, versions, platform selectors, dependency pins, the launcher map and the four-file allowlist. It runs `npm pack --dry-run --ignore-scripts --offline --json` and `npm pack` with the same flags for all packages. It verifies archive entries, extracted bytes and npm integrity hashes. Only after all five archives pass does it write `packs.json` and `publish-order.txt`. Partial output on failure is not publishable; start again with a fresh directory.

## Manual Linux setup

npm installation does not establish the Linux enforcement boundary. On Linux x86_64, check out the matching tag and use the Zig version it requires. Verify the release's `SHA256SUMS` attestation and downloaded files, build the helper in the checkout, and compare its SHA-256 with the manifest's `blackice-linux-helper-0.1.0-x86_64-linux` entry. Only after that match should the checkout's setup script run with that digest as its second argument. Review [docs/linux.md](../../docs/linux.md) and the checkout's scripts first.

The following block uses a fresh checkout and stops on any failed check. It performs an explicit operator setup; npm installation never executes it. Linux arm64 remains CLI-only and must not use this x86_64 procedure.

```sh
(
  set -eu
  test "$(uname -s)" = Linux
  test "$(uname -m)" = x86_64
  git clone --branch v0.1.0 --depth 1 https://github.com/ValentinTorassa/blackice.git blackice-v0.1.0
  cd blackice-v0.1.0
  release_dir="$PWD/out/release-v0.1.0"
  mkdir -p "$release_dir"
  gh release download v0.1.0 --repo ValentinTorassa/blackice --dir "$release_dir"
  (
    cd "$release_dir"
    gh attestation verify SHA256SUMS --repo ValentinTorassa/blackice --signer-workflow ValentinTorassa/blackice/.github/workflows/release.yml --source-ref refs/tags/v0.1.0 --source-digest "$(git rev-parse HEAD)" --deny-self-hosted-runners
    sha256sum -c SHA256SUMS
  )
  zig build -Doptimize=ReleaseSafe
  helper_sha256="$(awk '$2 == "blackice-linux-helper-0.1.0-x86_64-linux" { print $1 }' "$release_dir/SHA256SUMS")"
  test "${#helper_sha256}" -eq 64
  printf '%s  zig-out/bin/blackice-linux-helper\n' "$helper_sha256" | sha256sum -c -
  sudo ./scripts/linux-setup.sh "$USER" "$helper_sha256"
)
```

The release contains four CLIs, the x86_64 helper and `SHA256SUMS`. Scripts are neither flat release assets nor separately attested: their integrity comes from the tag checkout. The root-install digest comes from the independently verified manifest, never from npm metadata. These are instructions for the corresponding published release, not a claim that version 0.1.0 is already available.

## Validation and launcher behavior

```sh
node --test packaging/npm/test.mjs
```

The suite checks changed bytes and malformed checksums, CLI-only releases, configurable scope/name/version, exact archive contents, launcher arguments and I/O, missing packages, numeric exits and signal exits. It exercises the production packer on all five packages, then installs local tarballs offline with scripts disabled and runs the installed launcher. Synthetic test executables do not establish native enforcement.

To exercise a real local binary, prepare a clearly labeled local build fixture, install its matching platform and launcher tarballs offline, and run `blackice version` plus a harmless command. Record the actual binary hash, source commit and reported version. Packaging metadata alone does not establish any of them.

The launcher uses `spawnSync` with inherited stdio and no shell. It mirrors numeric exit status and re-emits the child's termination signal. Terminal signals reach both processes through their shared foreground process group. Because synchronous spawning blocks JavaScript signal handlers, a signal addressed only to the launcher PID is not forwarded while its child runs. Use a supervisor that signals the process group or invoke the native binary directly; immediate PID-only forwarding would require an asynchronous launcher. See [Node's synchronous child-process contract](https://nodejs.org/api/child_process.html#child_processspawnsynccommand-args-options).

## Publication handoff

Security owns `release.yml` and `npm-publish.yml`; they are reviewed separately from this packaging change. Publication is authorized by the operator publishing the reviewed draft release, followed by approval of the protected `npm` environment. Use the reviewed workflows as the source of truth for job permissions and toolchain pins.

Required operator configuration:

1. Set repository variables `NPM_SCOPE=@legios` and `NPM_PACKAGE_NAME=@legios/blackice`. A different namespace or launcher name needs a new explicit decision and workflow review.
2. Create GitHub environment **npm**, require the operator's review, and restrict deployment refs to approved release tags. The YAML selects this environment; its protection rules are repository settings.
3. Configure each of the five npm packages' trusted publishers for repository `ValentinTorassa/blackice`, workflow filename **npm-publish.yml**, environment **npm**, with direct `npm publish` allowed. Initial package setup and ownership verification are operator work; this branch does neither.

[npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) uses OIDC on a GitHub-hosted runner. Publication must use the reviewed, pinned toolchain and no npm token, login or credential fallback. These local packaging scripts never request an identity token or publish.

Before packing, the publication workflow must download the tag's assets, validate the manifest and file set, check the checksums, and verify [GitHub attestations](https://cli.github.com/manual/gh_attestation_verify) against `release.yml`, the repository, tag and commit. Only verified binaries may be run or packaged; the CLI's version must match the release tag. Scripts are not release assets and do not have script attestations.

After all five archives pass the packer's checks, publish the four platform tarballs first and the launcher last with `npm publish --provenance --access public --ignore-scripts`. A failed platform publish must stop before the launcher. npm versions are immutable; a partial publication needs operator reconciliation rather than an automatic overwrite or name change. Publishing is never part of the local tests.

Release attestations establish where the native bytes came from; npm provenance establishes where their packages were assembled. Local tests and mocked workflow checks do not verify live OIDC, registry ownership or release attestations. Those require the configured environment and a real reviewed release.
