#!/usr/bin/env node
// Reference Node.js client for sluice.
//
// Prefers the native addon at ../node when built (~2.8 ms per call,
// no fork+exec). Falls back to spawning the `sluicify` companion
// binary when the addon isn't available.
//
// Usage:
//   sluicify.js <socket> <cmd> [args...]

'use strict';

const args = process.argv.slice(2);
if (args.length < 2) {
  console.error('usage: sluicify.js <socket> <cmd> [args...]');
  process.exit(2);
}
const [sockPath, ...argv] = args;

let status;
let usedNative = false;
try {
  const sluice = require('../node');
  status = sluice.call(sockPath, argv);
  usedNative = true;
} catch (e) {
  if (e.code !== 'MODULE_NOT_FOUND' && !/no built addon/.test(e.message)) {
    throw e;
  }
  // Fall back to the helper binary.
  const { spawnSync } = require('node:child_process');
  const r = spawnSync('sluicify', [sockPath, ...argv], { stdio: 'inherit' });
  if (r.error) {
    console.error(`sluicify.js: ${r.error.message}`);
    console.error(
      'hint: build the native addon (cd sluice/node && cargo build --release) ' +
        'or place sluicify on PATH.'
    );
    process.exit(2);
  }
  status = r.status ?? 1;
}

if (process.env.SLUICE_DEBUG) {
  console.error(`[sluicify.js] via=${usedNative ? 'native' : 'spawn'} status=${status}`);
}
process.exit(status);
