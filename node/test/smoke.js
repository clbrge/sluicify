#!/usr/bin/env node
// node/test/smoke.js — release-time smoke test for the native addon.
//
// Spawns a `sluice serve` against a tiny rules file, calls the broker
// from this Node process via the addon, and verifies the round-trip.
// Cleans up its tempdir on exit.
//
// Run from the node/ directory (where the .node artifact lives) AFTER
// `npm run build` (or `cargo build --release && cp target/release/
// libsluicify_node.so sluicify-native.node`):
//
//   node test/smoke.js
//
// Exits 0 on success, non-zero on failure with a diagnostic.

'use strict';

const { spawn } = require('node:child_process');
const { existsSync, mkdirSync, writeFileSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

const sluice = require('../');                                    // load addon

// ----- pick paths -------------------------------------------------------

const sluiceBin = process.env.SLUICE_BIN ||
  join(__dirname, '..', '..', 'target', 'release', 'sluice');
if (!existsSync(sluiceBin)) {
  console.error(`sluice binary not found at ${sluiceBin} — set SLUICE_BIN`);
  process.exit(2);
}

const dir = join(tmpdir(), `sluicify-node-smoke-${process.pid}-${Date.now()}`);
mkdirSync(dir, { recursive: true, mode: 0o700 });
const rules = join(dir, 'rules');
const sock  = join(dir, 'sock');

writeFileSync(rules, [
  'defaults:',
  '  audit = best-effort',
  '  env   = HOME,LANG',
  '',
  'echo #1',
  '  1 = ^[a-zA-Z0-9_]+$',
].join('\n'));

// ----- start broker -----------------------------------------------------

const broker = spawn(sluiceBin, ['serve', '--rules', rules, '--socket', sock], {
  stdio: ['ignore', 'pipe', 'pipe'],
});

let brokerStderr = '';
broker.stderr.on('data', (b) => { brokerStderr += b.toString(); });

function cleanup(code, msg) {
  if (msg) console.error(msg);
  if (brokerStderr) console.error('--- broker stderr ---\n' + brokerStderr);
  try { broker.kill(); } catch (_) {}
  try { rmSync(dir, { recursive: true, force: true }); } catch (_) {}
  process.exit(code);
}

// Wait up to 2s for the socket to appear.
const deadline = Date.now() + 2000;
function waitForSocket() {
  if (existsSync(sock)) return main();
  if (Date.now() > deadline) cleanup(2, 'broker did not bind socket');
  setTimeout(waitForSocket, 20);
}
waitForSocket();

// ----- the actual test --------------------------------------------------

function main() {
  let status;
  try {
    status = sluice.call(sock, ['echo', 'native_addon_works']);
  } catch (e) {
    cleanup(1, `sluice.call threw: ${e.message}`);
    return;
  }
  if (status !== 0) {
    cleanup(1, `expected status 0, got ${status}`);
    return;
  }
  console.log('OK: native addon round-trip succeeded');
  cleanup(0);
}
