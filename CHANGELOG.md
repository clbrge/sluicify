# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the `0.x.y` caveat: while `version < 1.0.0`, minor bumps may include
breaking changes (and will be called out under **Changed** with a note).

## [Unreleased]

### Added

- `sluicify-native`, the Node addon, is published on npm for linux x64.

## [0.3.0] - 2026-10-06

### Changed

- A bare-name rule matches only an `argv[0]` equal to its name, and an
  absolute rule only its exact path. A caller sending a path for a
  bare-name rule (`/usr/bin/git` for `git`) now gets `ERR_NO_RULE`.

## [0.2.2] - 2026-10-05

### Added

- `sluicify --version` / `-V` and `--help` / `-h`, as the first argument
  only; after the socket path every argument belongs to the command.

## [0.2.1] - 2026-10-05

### Changed

- README and REFERENCE: new "Auditing rules" section — how a rule ends up
  granting more than intended, with counter-examples and a per-rule
  procedure to follow before a rule goes live.
- The README tutorial and `examples/sluice.rules` use only closed rules:
  none runs a file the caller can write, and `git` and `systemctl` run
  with `--no-pager`.

## [0.2.0] - 2026-10-05

### Upgrading

- Every slot needs a regex or an `allow_any` entry; a rules file with a
  bare slot no longer parses. Run the new `sluice check` on your rules
  before restarting the broker.
- Slot values starting with `-` are refused unless the slot is listed
  in `allow_dash`.
- Clients that interpret wire status: `-5` is no longer sent (signal
  deaths are `128 + signo`); handle `-7` (`ERR_TIMEOUT`) and `-8`
  (`ERR_PEER`).

### Security

- Slot regexes are anchored as `^(?:…)$`, so every branch of an
  alternation must match the whole value and a trailing `\$` is not
  taken for an end anchor.
- Every slot needs a regex unless listed in `allow_any`, and values
  starting with `-` are refused unless the slot is listed in
  `allow_dash` (reject reason `option_like`).
- Fds passed with a malformed request or the wrong fd count are closed
  instead of leaking in the broker.
- Received fds are close-on-exec atomically (`MSG_CMSG_CLOEXEC`), so a
  concurrent spawn can't inherit another caller's stdio.
- `sluice serve` refuses to start when another broker is listening on
  the socket path, instead of unlinking it.

### Added

- `allow_dash` and `allow_any` rule attributes. `sluice check` lists
  every slot they widen.
- `$HOME` and `$XDG_RUNTIME_DIR` (also `${…}`) expand in `logfile`,
  `stdoutfile`, `stderrfile` and `cwd`, once at parse or `SIGHUP`
  reload. Any other `$VAR`, or an unset one, is a parse error.
- Wire status `ERR_TIMEOUT` (-7) when a rule timeout fires; `sluicify`
  and the example clients exit 124 for it.
- Wire status `ERR_PEER` (-8) when the caller's `SO_PEERCRED` can't be
  read (reject reason `peer_unknown`).
- Manifest: `"resolved"` (the binary executed) on start events;
  `"signal"`, `"timed_out"` and `"drain_timeout"` on exit events when
  set.

### Changed

- A child killed by a signal reports `128 + signo`.
- With `stdoutfile`/`stderrfile`, the reply goes out when the child
  exits. Output from background processes still holding the pipe is
  captured until they close it, or until the rule's timeout + 2 s; the
  exit event is written then.
- An executable that doesn't resolve via `exec_path` is a `reject`
  (`exe_unresolved`) instead of a start/exit pair.
- Rule attribute values: a value starting with a quote is one quoted
  word and may contain `;`. Otherwise quotes are literal and `;` starts
  a comment unless written `\;`.
- A per-rule `logfile` is a parse error.
- `sluicify` prints one actionable line per error, e.g. `No matching
  rule for command: <cmd>` or `Broker not running: no socket at <path>`.

### Removed

- Wire status `ERR_SIGNALED` (-5).

### Fixed

- Spawned children no longer inherit `SIGHUP` blocked and `SIGPIPE`
  ignored.
- A `timeout` is enforced by polling when `pidfd_open` or `poll` fails
  (e.g. EMFILE), instead of killing the child at once or never.
- A panicking connection handler or a failed thread spawn no longer
  leaks a concurrency slot or stops the accept loop.
- Requests with trailing bytes, or truncated by the receive buffer, are
  rejected.
- `sluice check` reports the number of slots, not of slot regexes.
- `sluicify` reports a non-UTF-8 argument instead of panicking.

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

[Unreleased]: https://github.com/clbrge/sluicify/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/clbrge/sluicify/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/clbrge/sluicify/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/clbrge/sluicify/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/clbrge/sluicify/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/clbrge/sluicify/releases/tag/v0.1.0
