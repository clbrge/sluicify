# sluicify

A small, declarative command broker for sandboxed callers. A process
inside a sandbox connects to a unix socket and asks the daemon to spawn
a command on the outside; the daemon matches the request against a
whitelist and runs it with the caller's stdin/stdout/stderr attached
via `SCM_RIGHTS` fd-passing.

The crate ships two binaries:

- **`sluice`** — the broker daemon (`sluice serve`, `sluice check`,
  `sluice match`). One running daemon per sandbox.
- **`sluicify`** — the verb. The client callers in the sandbox use to
  hand commands to the daemon (`sluicify <socket> <cmd> [args...]`).

Linux-only. Optional Node native addon. ~3000 LOC of Rust.

```sh
cargo install sluicify        # builds and installs both binaries
```

---

## What it is

sluice is the **outbound side** of the sandbox boundary. Your sandbox
keeps its caller locked down (no network, restricted filesystem,
seccomp, whatever). sluice gives the caller a precise menu of
operations on the outside that are allowed under controlled conditions.

Three things make it useful:

1. **Declarative whitelist.** Rules look like literal command lines
   with regex constraints on each slot. No code, no shell, no
   re-implementation of argv parsing in policy.
2. **Stdio is unmodified.** The child runs against the caller's actual
   `0/1/2`, byte-for-byte. There's no protocol translation, no UTF-8
   decode, no buffering layer to leak through.
3. **Audit-first.** Every call is recorded in a JSON-Lines manifest
   plus optional per-call raw stdio sidecars. The default refuses to
   execute when audit can't be honored.

## What it is NOT

- **Not a sandboxer.** It doesn't sandbox anything itself. You bring
  your own sandbox (bubblewrap, firejail, landlock, systemd-nspawn,
  rootless containers, gVisor — anything). sluice just provides the
  whitelisted escape.
- **Not a privilege escalator.** All children inherit the broker's
  uid/gid. No `setuid`, no identity switching. If a rule needs another
  identity, it explicitly invokes `sudo` / `ssh` / `doas` / `pkexec` —
  and those tools' own policies (sudoers, authorized_keys, polkit) are
  what decide.
- **Not an auth system.** Identity is "which socket you can reach". One
  socket per sandbox; the bind-mount is the credential. `SO_PEERCRED`
  is a sanity check, not the auth mechanism.
- **Not a network service.** AF_UNIX only. You bind-mount the socket
  into the sandbox.
- **Not a way to grant a shell.** A rule whitelists *one specific*
  argv shape with regex constraints. If you want a shell, write a rule
  that runs `/bin/sh -c '<exact-fixed-script>'` — but at that point you
  could just put the script on PATH and whitelist it.

## How it differs from related tools

| Tool                       | What it does                                       | Why sluice differs                                       |
|----------------------------|----------------------------------------------------|----------------------------------------------------------|
| `sudo` / `doas`            | Caller invokes a privileged tool in their PATH     | sluice keeps zero binaries in the sandbox; just a socket |
| `sshd` + `ForceCommand`    | Per-key allowed command in `authorized_keys`       | sluice is local-only, declarative per-arg regex          |
| `flatpak-spawn` / portals  | Sandboxed app asks D-Bus portal to spawn on host   | sluice is sandbox-agnostic; AF_UNIX, no D-Bus            |
| `polkit` / `pkexec`        | Session-mediated privilege requests                | sluice is path-driven (one socket per sandbox)           |
| `runc exec` / `docker exec`| Outside → spawns into container                    | sluice is the reverse: inside → spawns outside           |
| `ssh-agent` / `nix-daemon` | Single-purpose SCM_RIGHTS broker                   | same architecture, sluice generalizes it                 |

The closest cousin in shape is `ssh-agent`: a small AF_UNIX daemon
that brokers a narrow, fd-aware operation on behalf of a less-trusted
caller. sluice is what you'd build if `ssh-agent` brokered "spawn a
command" instead of "sign with this key".

---

## Primary use case: coding agents and dev jails

The motivating case. An LLM coding assistant or autonomous coding
agent runs in a tight sandbox — usually:

- read-only root filesystem,
- writable workspace under `/work`,
- no network, no `sudo`, no host PATH,
- seccomp filters on dangerous syscalls.

The agent needs **occasional, narrow** access to outside operations:

- `git -C /work add/commit/push` against a specific repo,
- `make test` for the project's test target,
- `npm install` (or `cargo fetch`) to populate dependencies,
- `gh pr create` to open a PR,
- a curated set of read-only host introspection (`uname`, `which`).

You don't want to give the agent a shell on the host. You don't want
to bake all those binaries into the sandbox image (network access for
`npm install` defeats the network-isolation in the first place). And
you absolutely want an audit trail of every command the agent ran,
with full stdio.

sluice is exactly that menu. The agent gets one bind-mounted unix
socket, calls a 30-line client to invoke whitelisted operations, and
every call lands in a per-call `c<N>.out` file you can `cat` and a
manifest line you can `jq`.

### Other use cases (less load-bearing)

- **CI runner for untrusted PRs.** The PR's code runs in a sandbox; a
  curated set of `git`/`make`/`docker build` operations route through
  sluice with audit.
- **Reproducible build sandboxes.** Nix-style fully-sealed builds need
  *just enough* outside access (e.g. fetching tarballs from a known
  mirror via the project's tooling). sluice exposes that one operation
  cleanly.
- **MCP / tool-use sandboxes.** Same shape as the coding agent: the
  tool LLM gets a narrow API to outside operations.

---

## Tutorial: a coding agent that can commit and run tests

This walks you through configuring sluice end to end, **entirely in
user-land** — no `sudo`, no dedicated system user, no `/var` paths.
Your own uid runs the broker; the audit dir is under your home.
That's the right setup for the primary use case (a dev running a
coding agent on a laptop or workstation).

For multi-tenant servers, CI hosts, or shared deployments where the
broker must run as a separate uid, see the
[Production checklist](REFERENCE.md#production-checklist) and the
systemd unit example in REFERENCE.md.

### 1. Pick directories

Three locations, all under your home or runtime dir:

```sh
mkdir -p "$XDG_RUNTIME_DIR/sluice"         # socket — already 0700, owned by you
mkdir -p "$HOME/.config/sluice"            # rules file
mkdir -p "$HOME/.local/state/sluice"       # audit manifest + per-call stdio
chmod 0700 "$HOME/.config/sluice" "$HOME/.local/state/sluice"
```

These are the XDG-spec default locations (`$XDG_CONFIG_HOME` →
`~/.config`, `$XDG_STATE_HOME` → `~/.local/state`, `$XDG_RUNTIME_DIR`
→ `/run/user/$UID`). Most distros only export `XDG_RUNTIME_DIR`
explicitly — the other two are conventions, not env vars you can rely
on, so the literal paths above are the portable form.

sluice's default audit mode is **strict** — it refuses to bind or
write into any directory not owned exclusively by the broker uid.
After `chmod 0700`, these dirs satisfy that without further ceremony.

### 2. Write a rules file

The agent works in `$HOME/work` (substitute your project root). It
has no PATH and no shell inside the sandbox — only the broker socket.

```sh
cat > "$HOME/.config/sluice/agent.rules" <<EOF
;
; Whitelist for a coding agent. The agent has no PATH and no shell
; inside the sandbox — only this socket.

defaults:
  timeout    = 120s
  env        = HOME,LANG
  logfile    = $HOME/.local/state/sluice/manifest.jsonl
  stdoutfile = $HOME/.local/state/sluice/calls/c#\$call.out
  stderrfile = $HOME/.local/state/sluice/calls/c#\$call.err

; Git operations confined to the agent's workspace.
git -C $HOME/work add #path
  path = ^[a-zA-Z0-9._/-]+\$

git -C $HOME/work commit -m #msg
  msg = ^[\x20-\x7e]{1,200}\$          ; printable ASCII, ≤200 chars

git -C $HOME/work status

git -C $HOME/work log --oneline -n #n
  n = ^[1-9][0-9]?\$                   ; 1–99

; Run the project's test target. No arguments — the Makefile decides.
make -C $HOME/work test
  timeout = 600s

; Open a PR. gh's auth comes from \$HOME (which we inherit).
gh pr create --title #title --body #body --head #branch
  title  = ^[\x20-\x7e]{1,80}\$
  body   = ^[\x20-\x7e]{0,4000}\$
  branch = ^[a-z][a-z0-9-]{0,40}\$
EOF
```

The heredoc lets `$HOME` expand (so the rules file ends up with your
real home directory baked in) but escapes `\$call` / `\$` so sluice's
slot syntax and end-of-line regex anchors survive.

If you'd rather keep `$HOME` literal in the file (e.g. checking the
rules into a dotfiles repo shared between users), sluice expands
`$HOME` and `$XDG_RUNTIME_DIR` itself at parse time — see
[REFERENCE.md → Environment-variable expansion](REFERENCE.md#environment-variable-expansion).
No other `$VAR` is allowed; typos and unset vars fail loudly at parse
time rather than landing audit data in a literal `$HOMW` directory.

Test it without running the broker:

```sh
$ sluice check ~/.config/sluice/agent.rules
ok: 5 rule(s)
  line  10: BareName("git")  tokens=4  slots=1
  line  13: BareName("git")  tokens=4  slots=1
  line  16: BareName("git")  tokens=2  slots=0
  line  18: BareName("git")  tokens=4  slots=1
  line  22: BareName("make") tokens=2  slots=0
  line  26: BareName("gh")   tokens=8  slots=3
```

### 3. Start the broker

Just run it directly — no `sudo`, no daemonisation, your own uid:

```sh
sluice serve \
    --rules  ~/.config/sluice/agent.rules \
    --socket "$XDG_RUNTIME_DIR/sluice/agent.sock"
```

Output:

```
sluice: manifest = /home/you/.local/state/sluice/manifest.jsonl
sluice: serving 5 rules at /run/user/1000/sluice/agent.sock (max 64 concurrent)
```

For laptop/workstation use, `nohup … &` or a tmux pane is fine. To
auto-start on login, use a **user-level** systemd unit at
`~/.config/systemd/user/sluice.service`:

```ini
[Unit]
Description=sluice — coding agent broker

[Service]
ExecStart=%h/.local/bin/sluice serve \
    --rules  %h/.config/sluice/agent.rules \
    --socket %t/sluice/agent.sock
Restart=on-failure

[Install]
WantedBy=default.target
```

Then `systemctl --user enable --now sluice`. Still no system-level
privileges. (`%h` = `$HOME`, `%t` = `$XDG_RUNTIME_DIR`.)

### 4. Bind-mount the socket into the sandbox

bubblewrap is rootless — works with your own uid:

```sh
bwrap \
  --ro-bind /usr /usr   --ro-bind /lib /lib   --ro-bind /lib64 /lib64 \
  --bind    "$HOME/work" /work \
  --bind    "$XDG_RUNTIME_DIR/sluice/agent.sock" /run/agent.sock \
  --unshare-all \
  --setenv  PATH "" \
  /path/to/your/agent-entrypoint
```

The agent now has `/run/agent.sock` available inside its sandbox —
the only contact with the outside.

### 5. Call from inside the sandbox

The agent can use any client that speaks the wire protocol. Three are
shipped — bind-mount or copy whichever you prefer into the sandbox:

```sh
# Python (stdlib only — no extra dependency)
python3 /usr/local/share/sluice/sluicify.py /run/agent.sock git -C /work status

# The Rust client (~380 KB static binary)
sluicify /run/agent.sock git -C /work commit -m "fix: handle empty input"

# Node (native addon or spawn fallback)
node /usr/local/share/sluice/sluicify.js /run/agent.sock make -C /work test
```

stdio is byte-for-byte: `git status`'s output appears on the agent's
stdout exactly as if it had run locally, exit code propagates.

A request that doesn't match any rule (or trips a regex, or puts a
`-`-prefixed value in a slot not listed in `allow_dash`) returns exit
`129` — `128 + |ERR_NO_RULE|`:

```sh
$ sluicify /run/agent.sock cat /etc/passwd
sluicify: No matching rule for command: cat
$ echo $?
129
```

A rule timeout exits `124` (as GNU `timeout`); a child killed by a
signal exits `128 + signo`.

### 6. Inspect the audit log

Every accepted call shows up as a `start`/`exit` pair in the manifest;
rejected calls as `reject`:

```sh
$ jq -c '{call,kind,argv,resolved,reason,status,duration_ms}
         | with_entries(select(.value != null))' \
    < ~/.local/state/sluice/manifest.jsonl
{"call":1,"kind":"start","argv":["git","-C","/home/you/work","status"],"resolved":"/usr/bin/git"}
{"call":1,"kind":"exit","status":0,"duration_ms":42}
{"call":2,"kind":"start","argv":["git","-C","/home/you/work","commit","-m","fix: handle empty input"],"resolved":"/usr/bin/git"}
{"call":2,"kind":"exit","status":0,"duration_ms":118}
{"call":3,"kind":"reject","argv":["cat","/etc/passwd"],"reason":"no_rule"}
```

`resolved` is the binary that actually ran; `argv[0]` is only what the
caller sent.

And every accepted call's actual stdout/stderr are byte-identical
sidecars:

```sh
$ cat ~/.local/state/sluice/calls/c2.out
[main 7c3a1f2] fix: handle empty input
 1 file changed, 3 insertions(+), 1 deletion(-)
```

`logrotate` (or your own rotation script) works on the manifest.
`SIGHUP` reloads the rules file in place:

```sh
$ kill -HUP $(pgrep -u "$USER" sluice)
sluice: SIGHUP — reloading rules
sluice: reload OK
```

### 7. Build it

```sh
git clone <this-repo>/sluice
cd sluice
cargo build --release
install -Dm755 target/release/sluice    "$HOME/.local/bin/sluice"
install -Dm755 target/release/sluicify  "$HOME/.local/bin/sluicify"
```

(Make sure `$HOME/.local/bin` is on your `PATH`. No `sudo install`
needed for personal use; for system-wide install see REFERENCE.md.)

That's it. See `REFERENCE.md` for the full attribute list, slot system,
wire protocol, and production checklist.

---

## Where to look next

- **`REFERENCE.md`** — exhaustive: every attribute, every slot, every
  CLI subcommand, the wire protocol, error codes, production checklist.
- **`examples/sluice.rules`** — annotated example covering the full
  attribute set.
- **`examples/sluicify.py`** — the Python reference client (stdlib
  only, ~50 lines). Read this if you want to write your own client in a
  language that can do `SCM_RIGHTS` directly.
- **`node/`** — Node.js native addon and Node example client.
- **`src/proto.rs`** — the wire-format spec, in code.

## License

MIT OR Apache-2.0 (see Cargo.toml).
