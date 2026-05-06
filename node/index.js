'use strict';
// Loader for the sluicify native addon.
//
// `napi build` produces a platform-tagged `.node` file (e.g.
// sluicify-native.linux-x64-gnu.node). A plain `cargo build` produces
// an untagged shared library `libsluicify_node.so`. Try both.

const { existsSync } = require('node:fs');
const { join } = require('node:path');

const here = __dirname;
const arch = process.arch === 'x64' ? 'x64' : process.arch;
const platform = process.platform;

const candidates = [
  // napi-rs --platform output:
  `sluicify-native.${platform}-${arch}-gnu.node`,
  `sluicify-native.${platform}-${arch}-musl.node`,
  // plain `cargo build` outputs (rename target/release/libsluicify_node.so):
  'sluicify-native.node',
  'libsluicify_node.so',
];

let loaded = null;
for (const name of candidates) {
  const p = join(here, name);
  if (existsSync(p)) {
    loaded = require(p);
    break;
  }
}
if (!loaded) {
  throw new Error(
    'sluicify-native: no built addon found in ' + here +
      '. Run `npm install && npm run build` here, ' +
      'or `cargo build --release` and ' +
      '`cp target/release/libsluicify_node.so sluicify-native.node`.'
  );
}

module.exports = loaded;
