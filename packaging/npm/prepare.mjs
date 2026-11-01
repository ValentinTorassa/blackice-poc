#!/usr/bin/env node
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync,
  readSync, realpathSync, renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const here = dirname(fileURLToPath(import.meta.url));
export const platforms = [
  { id: 'darwin-arm64', os: 'darwin', cpu: 'arm64', target: 'aarch64-macos' },
  { id: 'darwin-x64', os: 'darwin', cpu: 'x64', target: 'x86_64-macos' },
  { id: 'linux-x64', os: 'linux', cpu: 'x64', target: 'x86_64-linux' },
  { id: 'linux-arm64', os: 'linux', cpu: 'arm64', target: 'aarch64-linux' },
];
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function readRegular(file, limit = 128 * 1024 * 1024) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > limit) throw new Error(`not a bounded regular file: ${file}`);
    const bytes = Buffer.alloc(stat.size + 1);
    let size = 0;
    while (size < bytes.length) {
      const count = readSync(fd, bytes, size, bytes.length - size, null);
      if (count === 0) break;
      size += count;
    }
    if (size !== stat.size) throw new Error(`file changed size during read: ${file}`);
    return bytes.subarray(0, size);
  } finally {
    closeSync(fd);
  }
}

function checksums(bytes, required, allowed) {
  const lines = new TextDecoder('utf-8', { fatal: true }).decode(bytes).split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  const sums = new Map();
  for (const line of lines) {
    const match = /^([a-fA-F0-9]{64}) [ *]([a-zA-Z0-9][a-zA-Z0-9._-]*)$/.exec(line);
    if (!match || !allowed.includes(match[2])) throw new Error('unexpected SHA256SUMS entry');
    if (sums.has(match[2])) throw new Error(`duplicate SHA256SUMS entry: ${match[2]}`);
    sums.set(match[2], match[1].toLowerCase());
  }
  for (const name of required) {
    if (!sums.has(name)) throw new Error(`missing SHA256SUMS entry: ${name}`);
  }
  return sums;
}

export function releaseManifest(releaseDir, version = '0.1.0') {
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version) || version !== version.trim() || version.length > 40) {
    throw new Error('version must be a stable x.y.z version');
  }
  const source = realpathSync(releaseDir);
  const binaries = platforms.map(p => `blackice-${version}-${p.target}`);
  // The release also contains the x86_64 helper. Scripts come from the tag checkout, never release assets.
  const allowed = [...binaries, `blackice-linux-helper-${version}-x86_64-linux`];
  const bytes = readRegular(join(source, 'SHA256SUMS'), 64 * 1024);
  return { source, binaries, bytes, sums: checksums(bytes, binaries, allowed) };
}

function write(file, bytes, mode = 0o644) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, bytes, { flag: 'wx', mode });
  chmodSync(file, mode);
}
const json = value => `${JSON.stringify(value, null, 2)}\n`;

export function prepare({ releaseDir, outDir, version = '0.1.0', scope = '@legios', name = '@legios/blackice' }) {
  if (!releaseDir || !outDir) throw new Error('--release-dir and --out-dir are required');
  if (!/^@[a-z0-9][a-z0-9._-]*$/.test(scope) || scope.length > 180) throw new Error('invalid npm scope');
  if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(name) || name.length > 214) {
    throw new Error('invalid main package name');
  }
  const platformNames = Object.fromEntries(platforms.map(p => [p.id, `${scope}/blackice-${p.id}`]));
  if (Object.values(platformNames).includes(name)) throw new Error('main and platform names collide');
  const { source, binaries: assets, bytes: manifestBytes, sums } = releaseManifest(releaseDir, version);
  const output = resolve(outDir);
  if (output === source || output.startsWith(`${source}${sep}`)) throw new Error('output must be outside release-dir');
  try {
    lstatSync(output);
    throw new Error('output already exists; choose a new output directory');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const snapshots = new Map();
  // Validate every shipped input. Copy the same checked bytes, not a second read.
  for (const asset of assets) {
    const bytes = readRegular(join(source, asset));
    if (digest(bytes) !== sums.get(asset)) throw new Error(`SHA-256 mismatch: ${asset}`);
    snapshots.set(asset, bytes);
  }
  const license = readRegular(join(here, '..', '..', 'LICENSE'));
  const main = JSON.parse(readRegular(join(here, 'blackice', 'package.json')));
  delete main.private;
  main.name = name;
  main.version = version;
  main.blackicePlatforms = platformNames;
  main.optionalDependencies = Object.fromEntries(Object.values(platformNames).map(name => [name, version]));
  const result = {
    version, scope, name, releaseTag: `v${version}`, verification: 'sha256-only',
    checksumsSha256: digest(manifestBytes), packages: [],
  };
  mkdirSync(dirname(output), { recursive: true });
  const staging = mkdtempSync(join(dirname(output), '.blackice-npm-'));
  try {
    for (const platform of platforms) {
      const pkg = JSON.parse(readRegular(join(here, 'platforms', platform.id, 'package.json')));
      delete pkg.private;
      pkg.name = platformNames[platform.id];
      pkg.version = version;
      const mappings = [[`blackice-${version}-${platform.target}`, 'bin/blackice']];
      let readme = `# ${pkg.name}\n\nNative blackice ${version} for ${platform.os}/${platform.cpu}. Installed by ${name}'s optional dependencies. No JavaScript or install scripts.\n`;
      if (platform.os === 'linux') {
        readme += `
## Separate Linux setup

This npm package contains the CLI only. The [matching release](https://github.com/ValentinTorassa/blackice/releases/tag/v${version}) contains four CLIs, the x86_64 helper and SHA256SUMS. Setup and teardown scripts come from the tag checkout; they are not release assets and have no separate attestations. Their integrity comes from that checkout. See [docs/linux.md](https://github.com/ValentinTorassa/blackice/blob/v${version}/docs/linux.md).

Linux arm64 has no supported task scopes until a reviewed helper and runtime evidence exist for that CPU. No helper or setup bundle is shipped in npm, and npm installation runs no setup or privilege changes.
`;
        if (platform.cpu === 'x64') readme += `
On Linux x86_64, use the Zig version required by the tag. Check out v${version}, attest-verify its checksum manifest, check the downloaded files, then build the helper in that checkout. The built helper must match the manifest's blackice-linux-helper-${version}-x86_64-linux entry before the explicit setup command can run:

\`\`\`sh
(
  set -eu
  test "$(uname -s)" = Linux
  test "$(uname -m)" = x86_64
  git clone --branch v${version} --depth 1 https://github.com/ValentinTorassa/blackice.git blackice-v${version}
  cd blackice-v${version}
  release_dir="$PWD/out/release-v${version}"
  mkdir -p "$release_dir"
  gh release download v${version} --repo ValentinTorassa/blackice --dir "$release_dir"
  (
    cd "$release_dir"
    gh attestation verify SHA256SUMS --repo ValentinTorassa/blackice --signer-workflow ValentinTorassa/blackice/.github/workflows/release.yml --source-ref refs/tags/v${version} --source-digest "$(git rev-parse HEAD)" --deny-self-hosted-runners
    sha256sum -c SHA256SUMS
  )
  zig build -Doptimize=ReleaseSafe
  helper_sha256="$(awk '$2 == "blackice-linux-helper-${version}-x86_64-linux" { print $1 }' "$release_dir/SHA256SUMS")"
  test "\${#helper_sha256}" -eq 64
  printf '%s  zig-out/bin/blackice-linux-helper\\n' "$helper_sha256" | sha256sum -c -
  sudo ./scripts/linux-setup.sh "$USER" "$helper_sha256"
)
\`\`\`

The subshell stops on any failed check. The setup digest comes from the independently verified release manifest, never from npm metadata. Review the checkout's scripts before running this operator-only setup. These commands are instructions, not npm install hooks.
`;
      }
      readme += '\n| Release asset | Installed path | SHA-256 |\n| --- | --- | --- |\n';
      for (const [asset, destination] of mappings) {
        write(join(staging, platform.id, destination), snapshots.get(asset), destination === 'bin/blackice' ? 0o755 : 0o644);
        readme += `| ${asset} | ${destination} | ${sums.get(asset)} |\n`;
      }
      write(join(staging, platform.id, 'package.json'), json(pkg));
      write(join(staging, platform.id, 'README.md'), readme);
      write(join(staging, platform.id, 'LICENSE'), license);
      result.packages.push({ directory: platform.id, name: pkg.name, version, assets: mappings.map(([asset, path]) => ({ asset, path, sha256: sums.get(asset) })) });
    }
    write(join(staging, 'blackice', 'package.json'), json(main));
    write(join(staging, 'blackice', 'bin', 'blackice.cjs'), readRegular(join(here, 'blackice', 'bin', 'blackice.cjs')), 0o755);
    write(join(staging, 'blackice', 'LICENSE'), license);
    const readme = readRegular(join(here, 'blackice', 'README.md')).toString('utf8');
    write(join(staging, 'blackice', 'README.md'), readme.replaceAll('{{NAME}}', name).replaceAll('{{VERSION}}', version));
    // The order is intentional: all platform versions must exist before the main package is published.
    result.packages.push({ directory: 'blackice', name, version, assets: [] });
    write(join(staging, 'manifest.json'), json(result));
    renameSync(staging, output);
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  }
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { values } = parseArgs({ options: {
      'release-dir': { type: 'string' }, 'out-dir': { type: 'string' },
      version: { type: 'string', default: '0.1.0' }, scope: { type: 'string', default: '@legios' },
      name: { type: 'string', default: '@legios/blackice' },
    } });
    const result = prepare({ releaseDir: values['release-dir'], outDir: values['out-dir'], ...values });
    console.log(json(result));
  } catch (error) {
    console.error(`blackice npm preparation: ${error.message}`);
    process.exitCode = 1;
  }
}
