#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual, parseArgs } from 'node:util';
import { platforms } from './prepare.mjs';

const load = file => JSON.parse(readFileSync(file, 'utf8'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function check(ok, message) { if (!ok) throw new Error(message); }
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { timeout: 120000, maxBuffer: 128 * 1024 * 1024, ...options });
  if (result.error || result.status !== 0) throw new Error(`${command} failed: ${result.error?.message || result.stderr?.toString()}`);
  return result.stdout;
}
function packResult(bytes) {
  const data = JSON.parse(bytes);
  return Array.isArray(data) ? data[0] : Object.values(data)[0];
}

// Produces local tarballs only. There is deliberately no publishing operation here.
export function pack({ preparedDir, outDir, env = process.env }) {
  check(preparedDir && outDir, '--prepared-dir and --out-dir are required');
  const root = resolve(preparedDir);
  const output = resolve(outDir);
  const manifest = load(join(root, 'manifest.json'));
  const directories = [...platforms.map(p => p.id), 'blackice'];
  check(isDeepStrictEqual(manifest.packages.map(p => p.directory), directories), 'unexpected package order/set');
  mkdirSync(output); // Refuse reuse; never publish a stale tarball left by an earlier run.
  const records = [];
  for (const pkg of manifest.packages) {
    const cwd = join(root, pkg.directory);
    const metadata = load(join(cwd, 'package.json'));
    const isMain = pkg.directory === 'blackice';
    const binary = isMain ? 'bin/blackice.cjs' : 'bin/blackice';
    const files = ['LICENSE', 'README.md', 'package.json', binary].sort();
    check(metadata.name === pkg.name && metadata.version === manifest.version, 'package identity/version mismatch');
    check(isDeepStrictEqual(metadata.files, [binary]), 'unexpected package file allowlist');
    for (const field of ['private', 'scripts', 'dependencies', 'devDependencies', 'peerDependencies']) {
      check(metadata[field] === undefined, `unexpected ${field} in ${pkg.name}`);
    }
    if (isMain) {
      const platformNames = Object.fromEntries(platforms.map(p => [p.id, `${manifest.scope}/blackice-${p.id}`]));
      check(isDeepStrictEqual(metadata.blackicePlatforms, platformNames), 'unexpected launcher platform map');
      check(isDeepStrictEqual(metadata.optionalDependencies,
        Object.fromEntries(Object.values(platformNames).map(name => [name, manifest.version]))), 'optional dependencies are not exact platform pins');
    } else {
      const target = platforms.find(p => p.id === pkg.directory);
      check(metadata.name === `${manifest.scope}/blackice-${target.id}`, 'platform package name mismatch');
      check(isDeepStrictEqual(metadata.os, [target.os]) && isDeepStrictEqual(metadata.cpu, [target.cpu]), 'platform selector mismatch');
      check(metadata.optionalDependencies === undefined && pkg.assets.length === 1, 'unexpected platform payload/dependency');
      check(pkg.assets[0].path === binary, 'unexpected binary path');
      check(digest(readFileSync(join(cwd, binary))) === pkg.assets[0].sha256, 'prepared binary checksum mismatch');
    }
    const options = { cwd, env };
    const preview = packResult(run('npm', ['pack', '--dry-run', '--ignore-scripts', '--offline', '--json'], options));
    check(isDeepStrictEqual(preview.files.map(f => f.path).sort(), files), 'unexpected npm archive payload');
    const expectedName = `${pkg.name.replace(/^@/, '').replace('/', '-')}-${manifest.version}.tgz`;
    check(/^[a-z0-9][a-z0-9._-]*\.tgz$/.test(expectedName) && preview.filename === expectedName, 'unexpected tarball filename');
    const packed = packResult(run('npm', ['pack', '--ignore-scripts', '--offline', '--json', '--pack-destination', output], options));
    check(packed.filename === expectedName && packed.integrity === preview.integrity, 'pack differs from dry-run');
    const archive = join(output, expectedName);
    const bytes = readFileSync(archive);
    check(packed.integrity === `sha512-${createHash('sha512').update(bytes).digest('base64')}`, 'tarball integrity mismatch');
    const archiveFiles = run('tar', ['-tzf', archive]).toString('utf8').trimEnd().split('\n').sort();
    check(isDeepStrictEqual(archiveFiles, files.map(f => `package/${f}`).sort()), 'archive entries differ from allowlist');
    for (const file of files) {
      const actual = run('tar', ['-xOf', archive, `package/${file}`]);
      const expected = readFileSync(join(cwd, file));
      check(file === 'package.json' ? isDeepStrictEqual(JSON.parse(actual), JSON.parse(expected)) : actual.equals(expected),
        `archive changed bytes: ${pkg.name}/${file}`);
    }
    records.push({ directory: pkg.directory, name: pkg.name, version: metadata.version, filename: expectedName,
      path: archive, integrity: packed.integrity, sha256: digest(bytes), files });
  }
  // Written only after every tarball passes. The workflow publishes this exact order.
  writeFileSync(join(output, 'packs.json'), `${JSON.stringify(records, null, 2)}\n`, { flag: 'wx' });
  writeFileSync(join(output, 'publish-order.txt'), `${records.map(p => p.path).join('\n')}\n`, { flag: 'wx' });
  return records;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { values } = parseArgs({ options: { 'prepared-dir': { type: 'string' }, 'out-dir': { type: 'string' } } });
    console.log(JSON.stringify(pack({ preparedDir: values['prepared-dir'], outDir: values['out-dir'] }), null, 2));
  } catch (error) {
    console.error(`blackice npm packing: ${error.message}`);
    process.exitCode = 1;
  }
}
