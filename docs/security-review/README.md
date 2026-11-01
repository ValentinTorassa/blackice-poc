# Security review

How changes to blackice are reviewed for security, and the rules the CI follows.

## Pull requests

Every pull request gets a security review before it is merged. Findings are posted as review comments, never
as an approval. Each finding has a severity and a concrete fix:

| Severity | Meaning |
|---|---|
| Critical | A confined command reaches the network freely, or gains root, with no special conditions. |
| High | The scope or the integrity of its receipts can be bypassed with ordinary user actions. |
| Medium | A bypass that needs specific conditions (network type, policy shape, a missing check elsewhere), or a loss of defense in depth. |
| Low | Hardening, privacy or robustness problems that do not bypass the scope. |
| Nit | Style or tooling. |

A finding that is not fixed before a recorded run is listed under the limits of that run's evidence entry.

Privileged code (the Linux helper and `scripts/linux-setup.sh` / `scripts/linux-teardown.sh`) is reviewed
before anyone runs it with sudo.

## CI

`.github/workflows/ci.yml` runs on every pull request and on pushes to `main`, on `ubuntu-latest` (x86_64) and
`macos-latest` (arm64): `zig fmt --check` (Linux only), `zig build`, `zig build test`, and a cross-build for the
other OS.

On Linux, the tests run with `kernel.apparmor_restrict_unprivileged_userns=0`. The Ubuntu runner image sets it to
`1`, which leaves a process with no capabilities in a user namespace it creates without privilege, so the
confinement tests cannot mount. The step logs the old value. Only the throwaway runner is changed.

Rules for every workflow in this repository:

- The token is read-only (`permissions: contents: read`), and checkout does not keep it (`persist-credentials: false`).
  The only exceptions are the release workflow's attest and release jobs, listed under [Releases](#releases), and
  the npm workflow's publish job, listed under [npm](#npm).
- No secrets and no `pull_request_target`.
- Actions are pinned to full commit SHAs, with the tag in a comment.
- Values from the event (titles, branch names, bodies) never go straight into a `run:` script. Steps read them
  through `env:`.
- Zig is pinned by version and by the sha256 of each platform's tarball, copied from
  <https://ziglang.org/download/index.json>. The tarball comes from a shuffled pick of Zig's
  [community mirrors](https://ziglang.org/download/community-mirrors/), with ziglang.org as the last resort, and
  is used only if its sha256 matches. Zig recommends a minisign check for mirror downloads; a pinned sha256 is
  stricter, because it fixes the exact bytes of a known release.

### Updating Zig

1. Copy the new version's `shasum` for `x86_64-linux` and `aarch64-macos` from `index.json`.
2. Change `ZIG_VERSION` and both `zig_sha256` values in one commit, and say in the commit message where the
   values came from.
3. Update `minimum_zig_version` in `build.zig.zon` if it changes.

### Updating an action

Get the commit of the new tag (`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`; if the object is an annotated
tag, follow it to its commit), replace the SHA and update the tag in the comment.

## Releases

`.github/workflows/release.yml` runs only when a tag starting with `v` is pushed. It ends with a draft release;
publishing it is a manual step.

1. **tag** checks that the tag is `vX.Y.Z`, that `build.zig.zon` declares the same version, and that the
   tagged commit is on `main`.
2. **build** runs twice, on `ubuntu-latest` and on `macos-latest`. Each builder runs
   `zig build release -Dmacos-min=13.0`, which writes the four CLIs, the x86_64 Linux helper and the build's own
   `SHA256SUMS` to `zig-out/release`. The job fails unless that directory holds exactly those files and its
   `SHA256SUMS` checks, and it copies only the expected files. The Linux builder also runs
   `scripts/linux-build-helper.sh` and checks that its helper is byte-identical to the release's. It then checks
   that `blackice version` prints the tag's version.
3. **compare** fails unless both builders produced the same set of files with the same bytes. It writes
   `SHA256SUMS`.
4. **attest** creates one build provenance attestation per release file (`actions/attest-build-provenance`).
   Only this job gets `id-token: write` and `attestations: write`.
5. **release** creates the draft release with the files and `SHA256SUMS`. Only this job gets
   `contents: write`.

Release files: `blackice-X.Y.Z-{x86_64-linux,aarch64-linux,aarch64-macos,x86_64-macos}`,
`blackice-linux-helper-X.Y.Z-x86_64-linux` and `SHA256SUMS`. No helper ships for a target that has not run on
real hardware, so there is no aarch64 Linux helper yet. The setup scripts are not release files: Linux setup
runs from a checkout of the tag.

Checking a release file before running it:

```sh
sha256sum -c SHA256SUMS --ignore-missing           # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
gh attestation verify blackice-X.Y.Z-aarch64-macos --repo ValentinTorassa/blackice \
  --signer-workflow ValentinTorassa/blackice/.github/workflows/release.yml
```

To check a release without trusting GitHub at all, build the tag with Zig 0.17.0
(`zig build release -Dmacos-min=13.0`) and compare the hashes.

What the workflow assumes. These are repository settings, and changing them is the owner's decision:

- **Only the owner can create `v*` tags** (a tag ruleset). Whoever can push such a tag can run this workflow
  with the tagged commit's own copy of it, so the "on main" check only holds if tags are restricted.
- **`main` cannot be force-pushed or deleted** (a branch ruleset), so "on main" means "reviewed and merged".
- **Immutable releases are on** before the first release is published, so assets cannot be swapped afterwards.
- A draft is visible only to people with write access. Someone reads it before publishing it.

Known gaps before the first release:

- The helper and `scripts/linux-build-helper.sh` reach `main` with the Linux backend pull request, and the
  versioned release files with the 0.1.0 release change. Until both are on `main`, the build job fails, so no
  release can be made.
- `linux-setup.sh` looks for the helper in `../zig-out/bin` relative to itself. Shipping the setup scripts, or
  a Homebrew or tarball install, needs a helper-path argument first. That is a change to privileged setup code
  and needs its own review and a new pinned hash.

## npm

`.github/workflows/npm-publish.yml` runs only when a release is published: a stable `vX.Y.Z` tag, not a draft
and not a prerelease. It publishes the CLI only. No npm package contains the Linux helper or the setup scripts.

1. **prepare** (`contents: read`, `attestations: read`) checks that the tagged commit is on `main`, downloads
   the release files, and verifies the attestation of `SHA256SUMS` and then of every file it lists, bound to
   `release.yml`, the tag and the tagged commit. It runs the Linux binary only after that. It then builds the
   packages with `packaging/npm/prepare.mjs` and `pack.mjs`, and passes each archive's name and sha512 to the
   next job as a job output.
2. **publish** runs in the `npm` environment, which waits for the owner's approval. It is the only job with
   `id-token: write`. It runs no code from the repository and no downloaded binary. It refuses any archive whose
   name or sha512 differs from what prepare recorded, then publishes the four platform packages and the
   launcher last, with npm trusted publishing (OIDC) and provenance. There is no npm token.

Node is pinned by version. npm is pinned by version and by the sha512 of its registry tarball, and installed
from that tarball offline. Install scripts are off everywhere (`--ignore-scripts`). npm's config files and cache
are empty files and directories under the runner's temp directory.

What the workflow assumes. These are settings, and changing them is the owner's decision:

- The repository variables `NPM_SCOPE` and `NPM_PACKAGE_NAME` name packages the owner controls. There is no
  default, so an unset variable stops the run.
- The `npm` environment requires the owner's review and only allows `v*` tags.
- Each of the five npm packages has a trusted publisher for this repository, the workflow file
  `npm-publish.yml` and the environment `npm`.
- The tag ruleset under [Releases](#releases), because the workflow file runs from the tagged commit.

npm versions cannot be replaced. If a publish fails partway, the packages already published stay, and the owner
decides how to finish.
