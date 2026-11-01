import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { platforms, prepare } from './prepare.mjs';
import { pack } from './pack.mjs';

const host = `${process.platform}-${process.arch}`;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const load = file => JSON.parse(readFileSync(file, 'utf8'));
const fixtureBinary = `#!${process.execPath}
const fs = require('node:fs');
const [op, ...args] = process.argv.slice(2);
if (op === 'exit') process.exit(Number(args[0]));
else if (op === 'signal') process.kill(process.pid, args[0]);
else if (op === 'wait') { fs.writeFileSync(args[0], String(process.pid)); setInterval(() => {}, 1000); }
else {
  process.stdout.write(JSON.stringify({args: [op, ...args], stdin: fs.readFileSync(0, 'utf8'), cwd: process.cwd(), env: process.env.BLACKICE_NPM_TEST}));
  process.stderr.write('fixture-stderr\\n');
}
`;

function fixture(t, version = '0.1.0') {
  const root = mkdtempSync(join(tmpdir(), 'blackice-npm-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const releaseDir = join(root, 'release');
  const outDir = join(root, 'packages');
  mkdirSync(releaseDir);
  const assets = new Map();
  for (const p of platforms) {
    assets.set(`blackice-${version}-${p.target}`, Buffer.from(fixtureBinary));
    if (p.id === 'linux-x64') assets.set(`blackice-linux-helper-${version}-${p.target}`, Buffer.from(`test-only helper ${p.target}\n`));
  }
  for (const [file, bytes] of assets) writeFileSync(join(releaseDir, file), bytes);
  writeFileSync(join(releaseDir, 'SHA256SUMS'), [...assets].map(([file, bytes]) => `${hash(bytes)}  ${file}\n`).join(''));
  return { root, releaseDir, outDir, version, assets };
}

function linkPlatform(f, id = host) {
  const name = load(join(f.outDir, 'blackice/package.json')).blackicePlatforms[id];
  const destination = join(f.outDir, 'blackice', 'node_modules', name);
  mkdirSync(dirname(destination), { recursive: true });
  symlinkSync(join(f.outDir, id), destination, 'dir');
}

function launcher(f, args = [], options = {}) {
  return spawnSync(process.execPath, [join(f.outDir, 'blackice', 'bin', 'blackice.cjs'), ...args], {
    encoding: 'utf8', input: '', timeout: 5000, ...options,
  });
}

test('source templates pin the owned namespace without stale platform identities', () => {
  const main = load(new URL('./blackice/package.json', import.meta.url));
  const platformNames = Object.fromEntries(platforms.map(p => [p.id, `@legios/blackice-${p.id}`]));
  assert.equal(main.name, '@legios/blackice');
  assert.deepEqual(main.blackicePlatforms, platformNames);
  assert.deepEqual(main.optionalDependencies,
    Object.fromEntries(Object.values(platformNames).map(name => [name, main.version])));
  for (const file of ['blackice/package.json', ...platforms.map(p => `platforms/${p.id}/package.json`)]) {
    const raw = readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.doesNotMatch(raw, /@blackice\//, `${file}: unowned namespace in source template`);
    const metadata = JSON.parse(raw);
    if (file !== 'blackice/package.json') {
      assert.equal(metadata.name, platformNames[file.split('/')[1]]);
    }
  }
});

test('all five manifests, exact pins and unchanged release bytes', t => {
  const f = fixture(t);
  const report = prepare(f);
  assert.equal(report.verification, 'sha256-only');
  assert.equal(report.packages.length, 5);
  assert.equal(report.packages.at(-1).directory, 'blackice');
  assert.equal(report.name, '@legios/blackice');
  assert.equal(report.packages.at(-1).name, '@legios/blackice');
  for (const pkg of report.packages) {
    const dir = join(f.outDir, pkg.directory);
    const metadata = load(join(dir, 'package.json'));
    assert.equal(metadata.version, '0.1.0');
    assert.equal(metadata.name, pkg.name);
    for (const field of ['private', 'scripts', 'dependencies', 'devDependencies', 'peerDependencies']) {
      assert.equal(metadata[field], undefined, `${pkg.name}: ${field}`);
    }
    for (const item of pkg.assets) {
      assert.deepEqual(readFileSync(join(dir, item.path)), f.assets.get(item.asset));
      assert.equal(hash(readFileSync(join(dir, item.path))), item.sha256);
    }
    if (pkg.directory !== 'blackice') {
      const p = platforms.find(p => p.id === pkg.directory);
      assert.deepEqual(metadata.os, [p.os]);
      assert.deepEqual(metadata.cpu, [p.cpu]);
      assert.equal(statSync(join(dir, 'bin/blackice')).mode & 0o777, 0o755);
      assert.deepEqual(metadata.files, ['bin/blackice']);
      assert.equal(pkg.assets.length, 1);
      assert.equal(existsSync(join(dir, 'linux-setup')), false);
    }
  }
  assert.deepEqual(load(join(f.outDir, 'blackice/package.json')).optionalDependencies,
    Object.fromEntries(platforms.map(p => [`@legios/blackice-${p.id}`, '0.1.0'])));
  assert.deepEqual(load(join(f.outDir, 'blackice/package.json')).blackicePlatforms,
    Object.fromEntries(platforms.map(p => [p.id, `@legios/blackice-${p.id}`])));
});

test('CLI-only releases need no Linux helper or setup assets', t => {
  const f = fixture(t);
  for (const [name] of f.assets) {
    if (name.includes('helper')) {
      f.assets.delete(name);
      rmSync(join(f.releaseDir, name));
    }
  }
  writeFileSync(join(f.releaseDir, 'SHA256SUMS'), [...f.assets].map(([file, bytes]) => `${hash(bytes)}  ${file}\n`).join(''));
  assert.equal(prepare(f).packages.length, 5);
});

test('release manifest refuses scripts and the unreleased ARM helper', t => {
  const f = fixture(t);
  const file = join(f.releaseDir, 'SHA256SUMS');
  const original = readFileSync(file, 'utf8');
  for (const asset of ['linux-setup.sh', 'linux-teardown.sh', 'blackice-linux-helper-0.1.0-aarch64-linux']) {
    writeFileSync(file, original + `${hash('unreleased asset')}  ${asset}\n`);
    assert.throws(() => prepare(f), /unexpected SHA256SUMS entry/);
    assert.equal(existsSync(f.outDir), false);
  }
});

test('Linux READMEs derive setup from the tag and attested helper checksum; ARM stays CLI-only', t => {
  const f = fixture(t);
  prepare(f);
  for (const id of ['linux-x64', 'linux-arm64']) {
    const readme = readFileSync(join(f.outDir, id, 'README.md'), 'utf8');
    assert.ok(readme.includes('https://github.com/ValentinTorassa/blackice/releases/tag/v0.1.0'));
    assert.ok(readme.includes('https://github.com/ValentinTorassa/blackice/blob/v0.1.0/docs/linux.md'));
    assert.match(readme, /Linux arm64 has no supported task scopes/);
    assert.doesNotMatch(readme, /gh attestation verify [^\n]*(?:setup|teardown)\.sh/);
    if (id === 'linux-arm64') assert.doesNotMatch(readme, /^\s*sudo\b/m);
  }
  const readme = readFileSync(join(f.outDir, 'linux-x64', 'README.md'), 'utf8');
  const command = readme.match(/```sh\n([\s\S]*?)```/)[1];
  const verification = command.split('\n').find(line => line.trimStart().startsWith('gh attestation verify '));
  assert.ok(verification.includes(' --source-digest "$(git rev-parse HEAD)" --deny-self-hosted-runners'),
    'manifest attestation must match the checked-out commit and refuse self-hosted runners');
  const guide = readFileSync(new URL('./README.md', import.meta.url), 'utf8').split('## Manual Linux setup')[1].split('## Validation')[0];
  assert.equal(guide.match(/```sh\n([\s\S]*?)```/)[1], command, 'the two setup command blocks must agree');
  assert.doesNotMatch(guide, /gh attestation verify [^\n]*(?:setup|teardown)\.sh/);
  const ordered = ['git clone --branch v0.1.0', 'gh attestation verify SHA256SUMS', 'sha256sum -c SHA256SUMS',
    'zig build -Doptimize=ReleaseSafe', 'blackice-linux-helper-0.1.0-x86_64-linux', 'sha256sum -c -',
    'sudo ./scripts/linux-setup.sh "$USER" "$helper_sha256"'];
  let previous = -1;
  for (const step of ordered) {
    const offset = command.indexOf(step);
    assert.ok(offset > previous, `setup step missing or out of order: ${step}`);
    previous = offset;
  }
  const parsed = spawnSync('sh', ['-n'], { input: command, encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
});

test('scope, main name and version can change together without changing the command name', t => {
  const f = fixture(t, '1.2.3');
  prepare({ ...f, scope: '@example-native', name: '@example-native/cli' });
  const pkg = load(join(f.outDir, 'blackice/package.json'));
  assert.equal(pkg.name, '@example-native/cli');
  assert.equal(pkg.version, '1.2.3');
  assert.deepEqual(pkg.bin, { blackice: 'bin/blackice.cjs' });
  assert.deepEqual(Object.keys(pkg.optionalDependencies), platforms.map(p => `@example-native/blackice-${p.id}`));
  assert.deepEqual(pkg.blackicePlatforms, Object.fromEntries(platforms.map(p => [p.id, `@example-native/blackice-${p.id}`])));
  linkPlatform(f);
  assert.equal(launcher(f, ['exit', '19']).status, 19);
});

test('CLI --scope changes platform names without implicitly moving the scoped launcher', t => {
  const f = fixture(t);
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('./prepare.mjs', import.meta.url)),
    '--release-dir', f.releaseDir, '--out-dir', f.outDir, '--scope', '@blackice-sh'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const main = load(join(f.outDir, 'blackice/package.json'));
  assert.equal(main.name, '@legios/blackice');
  assert.deepEqual(main.blackicePlatforms,
    Object.fromEntries(platforms.map(p => [p.id, `@blackice-sh/blackice-${p.id}`])));
  linkPlatform(f);
  assert.equal(launcher(f, ['exit', '17']).status, 17);
});

test('release CLI accepts the explicit scoped main name and documents the same install command', t => {
  const f = fixture(t);
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('./prepare.mjs', import.meta.url)),
    '--release-dir', f.releaseDir, '--out-dir', f.outDir,
    '--version', '0.1.0', '--scope', '@legios', '--name', '@legios/blackice'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).packages.at(-1).name, '@legios/blackice');
  assert.deepEqual(load(join(f.outDir, 'blackice/package.json')).bin, { blackice: 'bin/blackice.cjs' });
  const readme = readFileSync(join(f.outDir, 'blackice/README.md'), 'utf8');
  assert.match(readme, /^# @legios\/blackice\n/);
  assert.ok(readme.includes('npm install --global --ignore-scripts @legios/blackice@0.1.0'));
  assert.doesNotMatch(readme, /npm install[^\n]*\sblackice@/);
});

test('only stable X.Y.Z versions are accepted, without prerelease, build or whitespace suffixes', t => {
  const f = fixture(t);
  for (const version of ['0.1.0-beta.1', '0.1.0+build.1', 'v0.1.0', '0.1', '0.01.0', ' 0.1.0', '0.1.0\n']) {
    assert.throws(() => prepare({ ...f, version }), /version must be a stable x\.y\.z version/);
    assert.equal(existsSync(f.outDir), false);
  }
});

test('modified bytes, missing/duplicate/path checksum entries and symlinks refuse before output', async t => {
  for (const kind of ['bytes', 'missing', 'duplicate', 'path', 'symlink']) {
    await t.test(kind, t => {
      const f = fixture(t);
      const file = [...f.assets.keys()][0];
      const manifest = join(f.releaseDir, 'SHA256SUMS');
      if (kind === 'bytes') writeFileSync(join(f.releaseDir, file), 'modified');
      if (kind === 'missing') writeFileSync(manifest, readFileSync(manifest, 'utf8').split('\n').slice(1).join('\n'));
      if (kind === 'duplicate') writeFileSync(manifest, readFileSync(manifest, 'utf8') + `${hash(f.assets.get(file))}  ${file}\n`);
      if (kind === 'path') writeFileSync(manifest, readFileSync(manifest, 'utf8').replace(file, `../${file}`));
      if (kind === 'symlink') {
        const outside = join(f.root, 'outside');
        writeFileSync(outside, f.assets.get(file));
        rmSync(join(f.releaseDir, file));
        symlinkSync(outside, join(f.releaseDir, file));
      }
      assert.throws(() => prepare(f));
      assert.equal(existsSync(f.outDir), false);
    });
  }
});

test('invalid names/versions and an existing output are refused', t => {
  const f = fixture(t);
  for (const extra of [{ scope: '../escape' }, { name: 'Bad Name' }, { version: '01.2.3' }, { name: '@legios/blackice-linux-x64' }]) {
    assert.throws(() => prepare({ ...f, ...extra }));
  }
  mkdirSync(f.outDir);
  const marker = join(f.outDir, 'keep');
  writeFileSync(marker, 'unchanged');
  assert.throws(() => prepare(f), /output already exists/);
  assert.equal(readFileSync(marker, 'utf8'), 'unchanged');
});

test('launcher preserves arguments, stdin/stdout/stderr, cwd, environment and exit status', t => {
  const f = fixture(t);
  prepare(f);
  linkPlatform(f);
  const args = ['echo', 'space value', '; touch NOT_EXECUTED', '$(not-a-command)', '--', 'ñ'];
  const result = launcher(f, args, { cwd: f.root, input: 'stdin\nvalue', env: { ...process.env, BLACKICE_NPM_TEST: 'synthetic-value' } });
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout), { args, stdin: 'stdin\nvalue', cwd: f.root, env: 'synthetic-value' });
  assert.equal(result.stderr, 'fixture-stderr\n');
  assert.equal(existsSync(join(f.root, 'NOT_EXECUTED')), false);
  for (const status of [0, 7, 125, 127]) assert.equal(launcher(f, ['exit', String(status)]).status, status);
});

test('launcher refuses absent/mismatched packages and a non-executable binary', t => {
  const f = fixture(t);
  prepare(f);
  let result = launcher(f);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /missing .* optional dependencies/);
  linkPlatform(f);
  const file = join(f.outDir, host, 'package.json');
  const metadata = load(file);
  writeFileSync(file, JSON.stringify({ ...metadata, version: '9.9.9' }));
  result = launcher(f);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /expected .*0\.1\.0/);
  writeFileSync(file, JSON.stringify(metadata));
  chmodSync(join(f.outDir, host, 'bin/blackice'), 0o644);
  result = launcher(f);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /EACCES/);
});

test('launcher refuses unsupported operating systems', t => {
  const f = fixture(t);
  prepare(f);
  const code = `Object.defineProperty(process, 'platform', {value: 'win32'}); require(${JSON.stringify(join(f.outDir, 'blackice/bin/blackice.cjs'))});`;
  const result = spawnSync(process.execPath, ['-e', code], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unsupported platform win32/);
});

test('child termination signals are re-emitted by the launcher', t => {
  const f = fixture(t);
  prepare(f);
  linkPlatform(f);
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    const result = launcher(f, ['signal', signal]);
    assert.equal(result.status, null);
    assert.equal(result.signal, signal);
  }
});

test('foreground process-group termination reaches the binary and launcher', { timeout: 5000 }, async t => {
  const f = fixture(t);
  prepare(f);
  linkPlatform(f);
  const marker = join(f.root, 'child.pid');
  const child = spawn(process.execPath, [join(f.outDir, 'blackice/bin/blackice.cjs'), 'wait', marker], {
    stdio: 'ignore', detached: true,
  });
  const closed = once(child, 'close');
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    }
  });
  for (let i = 0; i < 100 && !existsSync(marker); i++) await delay(20);
  assert.ok(existsSync(marker), 'binary must be running before the signal');
  process.kill(-child.pid, 'SIGTERM');
  const [status, signal] = await closed;
  assert.equal(status, null);
  assert.equal(signal, 'SIGTERM');
});

test('npm pack dry-run for all packages, then offline installation with scripts disabled', t => {
  const f = fixture(t);
  prepare(f);
  const tarballs = join(f.root, 'tarballs');
  const userconfig = join(f.root, 'user.npmrc');
  const globalconfig = join(f.root, 'global.npmrc');
  writeFileSync(userconfig, '');
  writeFileSync(globalconfig, '');
  const env = { PATH: process.env.PATH, npm_config_userconfig: userconfig, npm_config_globalconfig: globalconfig, npm_config_cache: join(f.root, 'npm-cache') };
  const records = pack({ preparedDir: f.outDir, outDir: tarballs, env });
  assert.deepEqual(records.map(p => p.directory), [...platforms.map(p => p.id), 'blackice']);
  assert.equal(records.at(-1).name, '@legios/blackice');
  assert.equal(records.at(-1).filename, 'legios-blackice-0.1.0.tgz');
  assert.equal(readFileSync(join(tarballs, 'publish-order.txt'), 'utf8'), records.map(p => p.path).join('\n') + '\n');
  for (const pkg of records) {
    assert.equal(pkg.files.length, 4);
    assert.ok(pkg.files.every(p => !p.includes('helper') && !p.includes('setup')));
    t.diagnostic(`npm pack --dry-run + archive check ${pkg.name}@${pkg.version}: 4 files, CLI only`);
  }
  const packs = new Map(records.map(p => [p.directory, p.path]));
  const install = join(f.root, 'installed');
  const result = spawnSync('npm', ['install', '--prefix', install, '--ignore-scripts', '--offline', '--no-audit', '--no-fund', '--package-lock=false', packs.get(host), packs.get('blackice')], { env, encoding: 'utf8', timeout: 30000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(load(join(install, 'node_modules/@legios/blackice/package.json')).name, '@legios/blackice');
  const run = spawnSync(join(install, 'node_modules/.bin/blackice'), ['exit', '23'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(run.status, 23, run.stderr);
});

test('packing refuses a changed binary and emits no publish order', t => {
  const f = fixture(t);
  prepare(f);
  writeFileSync(join(f.outDir, platforms[0].id, 'bin/blackice'), 'modified after prepare');
  const outDir = join(f.root, 'bad-pack');
  assert.throws(() => pack({ preparedDir: f.outDir, outDir }), /prepared binary checksum mismatch/);
  assert.equal(existsSync(join(outDir, 'publish-order.txt')), false);
});

test('packing refuses helpers or lifecycle hooks added to a prepared manifest', t => {
  const f = fixture(t);
  prepare(f);
  const file = join(f.outDir, platforms[0].id, 'package.json');
  const metadata = load(file);
  writeFileSync(file, JSON.stringify({ ...metadata, files: [...metadata.files, 'linux-setup'] }));
  assert.throws(() => pack({ preparedDir: f.outDir, outDir: join(f.root, 'extra-files') }), /file allowlist/);
  writeFileSync(file, JSON.stringify({ ...metadata, scripts: { postinstall: 'false' } }));
  assert.throws(() => pack({ preparedDir: f.outDir, outDir: join(f.root, 'extra-hook') }), /unexpected scripts/);
});
