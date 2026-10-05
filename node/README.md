# sluicify-native

Native Node.js addon for [sluicify](../). Same wire protocol as the
Python and Rust clients; calls `sendmsg` + `SCM_RIGHTS` directly from
the Node process — no `fork+exec` of a helper binary per call.

## Build

```sh
cd sluicify/node
npm install
npm run build
```

This produces `sluicify-native.linux-<arch>-gnu.node` in this directory.

Without `npm install`, vanilla cargo also works:

```sh
cd sluicify/node
cargo build --release
cp target/release/libsluicify_node.so sluicify-native.node
```

The loader (`index.js`) finds either form automatically.

## Usage

```js
const sluice = require('sluicify-native');

const status = sluice.call('/run/agent.sock', ['echo', 'hello']);
// Negative = broker error (see index.d.ts); map like the sluicify binary.
process.exit(status >= 0 ? status : status === -7 ? 124 : 128 - status);
```

`call` is **synchronous** and blocks the calling JS thread until the
broker replies. The spawned child inherits this Node process's stdio
fds, so the JS event loop continues serving other I/O while the child
runs against the terminal/pipes — but the calling function awaits the
reply.

To keep the calling thread free (e.g. UI server doing background
sluice calls), invoke `call` from a `worker_threads` Worker:

```js
const { Worker } = require('node:worker_threads');
const w = new Worker(`
  const sluice = require('sluicify-native');
  parentPort.postMessage(sluice.call(workerData.sock, workerData.argv));
`, { eval: true, workerData: { sock: '/run/agent.sock', argv: ['echo','hi'] } });
w.on('message', (status) => console.log('done', status));
```

## Why a native addon

Compared to spawning the `sluicify` binary:

| approach          | distribution           | per-call cost      |
|-------------------|------------------------|--------------------|
| native addon      | npm install or cargo   | one syscall pair   |
| spawn `sluicify`  | ship binary on PATH    | fork+exec per call |

For agents making frequent sluice calls, the native addon is
meaningfully faster. For occasional calls, the helper binary is
simpler to deploy.

## Smoke test

`test/smoke.js` spawns `sluice serve` in a tempdir and round-trips a
call through the addon. Run it after every build:

```sh
cd sluicify/node
node test/smoke.js
# OK: native addon round-trip succeeded
```

It expects `target/release/sluice` to exist (produced by `cargo build
--release` from the parent dir). Override with `SLUICE_BIN=/path/to/sluice
node test/smoke.js`.

## Constraints

- **Linux only.** The wire protocol uses `SOCK_SEQPACKET`, which macOS
  doesn't support. Same as the broker.
- **Synchronous API.** Use `worker_threads` for concurrency.
