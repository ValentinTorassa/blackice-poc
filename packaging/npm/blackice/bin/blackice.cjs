#!/usr/bin/env node
'use strict';
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { dirname, join } = require('node:path');
const { version, optionalDependencies, blackicePlatforms } = require('../package.json');
const platform = `${process.platform}-${process.arch}`;
const name = blackicePlatforms?.[platform];
function fail(message) {
  console.error(`blackice: ${message}`);
  process.exit(1);
}
if (!name) fail(`unsupported platform ${platform}; use a supported native release.`);
if (optionalDependencies?.[name] !== version) fail(`invalid platform mapping for ${platform}.`);
let binary;
try {
  const file = require.resolve(`${name}/package.json`);
  const installed = JSON.parse(readFileSync(file, 'utf8'));
  if (installed.name !== name || installed.version !== version) {
    fail(`expected ${name}@${version}; reinstall matching packages.`);
  }
  binary = join(dirname(file), 'bin', 'blackice');
} catch {
  fail(`missing ${name}@${version}; reinstall with optional dependencies enabled.`);
}
const result = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit', shell: false });
if (result.error) fail(`cannot run ${name}: ${result.error.code || result.error.message}`);
if (result.signal) {
  // Preserve a signal exit; terminal signals reach the shared process group directly.
  process.kill(process.pid, result.signal);
} else {
  process.exit(result.status ?? 1);
}
