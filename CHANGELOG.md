# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the `0.x.y` caveat: while `version < 1.0.0`, minor bumps may include
breaking changes (and will be called out under **Changed** with a note).

## [Unreleased]

### Added

- Rules: `$HOME` / `${HOME}` and `$XDG_RUNTIME_DIR` / `${XDG_RUNTIME_DIR}`
  are expanded in `logfile`, `stdoutfile`, `stderrfile`, and `cwd`
  (defaults and per-rule). Expansion happens once at parse / `SIGHUP`
  reload using the broker's environment, so rules files can be shared
  across users without per-user editing. Allowlist is intentionally
  tight: any other `$VAR` is a parse error, as is an unset allowlisted
  var (no silent empty splices). The existing `#$slot` syntax is
  unaffected and composes naturally (`$HOME/log/c#$call.out`).
- `allow_dash` and `allow_any` rule attributes, listing slots that may
  take option-like values or any value. `sluice check` lists them.

### Changed

- **Rules:** every slot needs a regex unless listed in `allow_any`, and
  slot values starting with `-` are refused unless the slot is listed
  in `allow_dash` (reject reason `option_like`).
- **Wire protocol:** a child killed by a signal now reports `128 +
  signo` instead of `ERR_SIGNALED` (-5, no longer sent). A fired rule
  timeout reports the new `ERR_TIMEOUT` (-7); `sluicify` and the
  example clients exit 124 for it.
- `sluicify` client errors are now ssh-style one-liners. `sluice error
  status -4` becomes `Failed to spawn <cmd> (exec error)`; `connect:
  ENOENT` becomes `Broker not running: no socket at <path>`. Each
  broker error code maps to a distinct message.
- Manifest: start events carry `"resolved"` (the binary executed);
  exit events carry `"signal"` and `"timed_out"` when set. An
  executable that doesn't resolve is a `reject` (`exe_unresolved`)
  instead of a start/exit pair.
- Rule attribute values: a value starting with a quote is one quoted
  word, so it can contain `;`; otherwise quotes are literal and `;`
  starts a comment unless written `\;`.
- `sluice serve` refuses to start when another broker is listening on
  the socket path, instead of unlinking it.

### Fixed

- Requests with trailing bytes or truncated by the receive buffer are
  rejected.
- `sluice check` reports the number of slots, not the number of slot
  regexes.
- `sluicify` reports a non-UTF-8 argument instead of panicking.
- Slot regexes are anchored as `^(?:…)$`. Previously `a|b` became
  `^a|b$` (each branch anchored on one side only) and a trailing `\$`
  counted as an end anchor. **Behavior change:** values that only
  matched through the partial anchor are now rejected.
- Fds passed with a malformed request or with the wrong fd count are
  closed instead of leaking in the broker.
- Received fds are marked close-on-exec atomically
  (`MSG_CMSG_CLOEXEC`), so a concurrent spawn can't inherit another
  caller's stdio.
- With `stdoutfile`/`stderrfile`, the reply no longer waits for
  background processes that hold the child's stdout/stderr; it goes out
  when the child exits, as in direct mode. Capture continues until they
  close the pipe or until the rule's timeout + 2 s, and the exit event
  is written then (`"drain_timeout":true` when cut).
- A `timeout` is still enforced when `pidfd_open` or `poll` fails
  (e.g. EMFILE); the child was previously sent `SIGTERM` immediately,
  or never killed on a `poll` error.
- A per-rule `logfile` is a parse error; it was accepted and ignored.
- A panicking connection handler or a failed thread spawn no longer
  leaks a concurrency slot or takes down the accept loop.
- A call whose peer credentials can't be read is refused with the new
  `ERR_PEER` (-8), reject reason `peer_unknown`, instead of being
  logged as pid/uid 0.
- Spawned children start with an empty signal mask and default
  `SIGPIPE`; they previously inherited `SIGHUP` blocked and `SIGPIPE`
  ignored.

## [0.1.0] - 2026-05-06

Initial public release. The crate ships two binaries (`sluice` daemon and
`sluicify` client) and a native Node.js addon (`sluicify-native`). Linux only.

### Added

#### Broker (`sluice`)

- AF_UNIX `SOCK_SEQPACKET` accept loop with `MAX_ACTIVE = 64` concurrent
  connections and a 5-second `SO_RCVTIMEO` per connection (DoS-bounded).
- `SCM_RIGHTS` fd-passing for caller stdio; child runs against the
  caller's `0/1/2` byte-for-byte (no buffering, no transformation).
- Declarative whitelist with `#1`/`#name` slot syntax and per-slot regex
  constraints. Quote-aware comments. Whole-token slot semantics.
- `defaults:` block with per-rule overrides for `timeout`, `cwd`, `env`,
  `log`, `logfile`, `stdoutfile`, `stderrfile`, `audit`, `exec_path`.
- `SIGHUP` reload — re-parses rules, reopens manifest (logrotate
  cooperation), clears sink cache, preserves monotonic call IDs.
- `sluice check` and `sluice match` subcommands for offline rule
  verification.

#### Client (`sluicify`)

- Companion binary that does the `sendmsg` + `SCM_RIGHTS` dance for
  callers in languages without ancillary-data support (~380 KB stripped).
- Maps wire-protocol error codes to `128 + |status|` exit codes.
- Stdlib reference clients shipped alongside: `examples/sluicify.py`
  (Python) and `examples/sluicify.js` (Node).

#### Audit

- JSON-Lines manifest of `start` / `exit` / `reject` events at
  `defaults.logfile`. Optional.
- Per-call raw `stdoutfile` / `stderrfile` sidecars — byte-identical to
  upstream stdio, no base64 framing. Path templates support six system
  slots: `#$call`, `#$pid`, `#$uid`, `#$rule`, `#$ts`, `#$ts_ms`.
- Three log policies (`full`, `argv-only`, `exit-only`) with `exit-only`
  suppressing argv from the manifest entirely (for callers whose argv
  may carry secrets).
- `audit = strict` (default) refuses to operate when audit can't be
  honored: socket parent dir writable by another uid, `logfile` open
  failure, sink open failure mid-call, manifest write failure, sink
  write failure (the broker becomes "unhealthy" and refuses subsequent
  calls until reload).
- `audit = best-effort` downgrades the above to warnings on stderr.
- `truncated: true` marker on exit events when at least one sink lost
  bytes during the call.

#### Hardening

- Audit files opened with `O_NOFOLLOW` (rejects symlink swaps) at mode
  `0600` (regardless of process umask).
- Audit parent dirs created with mode `0700` when missing; refused if
  pre-existing with group/world write or owned by another uid.
- Socket file bound under `umask 0o077` (mode 0600).
- Socket parent dir checked: refused under `audit = strict` if writable
  by another uid; warned under `best-effort`.
- `exec_path` defaults to `/bin:/usr/bin:/sbin:/usr/sbin` (root-owned
  dirs only). Resolution happens in Rust with `execve` — `execvpe`'s
  caller-PATH-based lookup is bypassed. `inherit` opt-in available;
  empty and relative `exec_path` entries rejected at parse time.
- Children run in their own process group (`setpgid` from both parent
  and child to close the race window). Timeouts use `pidfd_open` for
  race-free wait + `killpg` for tree termination.
- Receive deadline (`SO_RCVTIMEO`) closes the trivial DoS where a
  connected-but-silent client could hold an active slot indefinitely.

#### Native Node addon (`sluicify-native`)

- napi-rs based addon at `node/`. Exposes a single synchronous
  `call(socketPath, argv) -> number` function.
- Loader (`node/index.js`) finds either the `napi build`-style platform-
  tagged `.node` file or a vanilla `cargo build`-produced `.so`.
- `node/test/smoke.js` for release-time round-trip verification.

#### Documentation and tooling

- `README.md` — design intent, comparison with related tools (sudo,
  sshd, flatpak portals, polkit, ssh-agent, etc.), primary use case
  (coding agents in dev jails), end-to-end user-land tutorial.
- `REFERENCE.md` — exhaustive spec: every attribute, slot, audit
  matrix, log-policy table, wire protocol, CLI, error codes, production
  checklist.
- 56 Rust tests (48 unit + 5 integration + 3 example smoke) + manual
  Node smoke.

[Unreleased]: https://github.com/clbrge/sluicify/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/clbrge/sluicify/releases/tag/v0.1.0
