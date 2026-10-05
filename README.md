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
- **Not a way to grant a shell** — on purpose. A rule whitelists *one
  specific* argv shape with regex constraints. But many innocent-looking
  rules are a shell anyway: `python3` reads a program from stdin,
  `make` runs whatever the Makefile says, `git` runs hooks and config
  from the repository. See [Auditing rules](#auditing-rules) below.

## Auditing rules

**sluice checks the shape of an argv; it does not understand the
program it runs.** A rule grants everything that program can be made
to do with any value your regexes accept, any bytes on stdin, and any
file the caller can write — as the broker's uid, outside the sandbox.
That is almost always more than the one command you had in mind, and
the gap rarely shows when you read the rule.

Treat every rule as a security decision and audit it against the
program's whole manual, not against the command you meant. The common
ways a rule grants more than intended — rules with no slots that still
run caller code, values a program reads as directives (`@file`,
`+cmd`), arguments a remote shell parses again, paths that escape,
regexes looser than they read, caller-chosen destinations, and rules
that combine — are worked through with examples in
[REFERENCE.md → Auditing rules](REFERENCE.md#auditing-rules), with a
per-rule procedure to follow before a rule goes live.

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

The agent does its work — editing, building, testing, committing —
inside the sandbox. It needs **occasional, narrow** access to the
operations the sandbox deliberately lacks:

- handing its commits back for review, into a checkout it can't write,
- network-backed reads: PR or CI status, a package index,
- the dev services its code talks to: their status and logs,
- telling you something is ready.

You don't want to give the agent a shell on the host, and you don't
want to open the sandbox's network for a handful of calls. And you
absolutely want an audit trail of every command the agent ran, with
full stdio.

What doesn't belong on that menu is anything that runs code the agent
wrote: `make test`, `npm install` or any `git` command in the agent's
own workspace execute its Makefile, its install scripts, its hooks
and its `.git/config` — on the host, outside the sandbox. Those run
inside the sandbox, or not through sluice. See
[Auditing rules](#auditing-rules).

sluice is exactly that menu. The agent gets one bind-mounted unix
socket, calls a 30-line client to invoke whitelisted operations, and
every call lands in a per-call `c<N>.out` file you can `cat` and a
manifest line you can `jq`.

### Other use cases (less load-bearing)

- **CI runner for untrusted PRs.** The PR's build and tests run in the
  sandbox; sluice exposes only the outside operations the job needs,
  with their targets fixed in the rules — posting a status, uploading
  an artifact to one location.
- **Reproducible build sandboxes.** Nix-style fully-sealed builds need
  *just enough* outside access (e.g. fetching tarballs from a known
  mirror via the project's tooling). sluice exposes that one operation
  cleanly.
- **MCP / tool-use sandboxes.** Same shape as the coding agent: the
  tool LLM gets a narrow API to outside operations.

---

## Tutorial: a coding agent that hands its work back for review

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

The agent works in `$HOME/work`, bind-mounted into its sandbox, and
runs `git`, the build and the tests there, inside the sandbox. Its
commits come back to you as a patch series applied to a separate
review clone, `$HOME/review/project`, which the agent cannot write:

```sh
git clone https://example.com/example-org/project.git "$HOME/review/project"
```

Every rule below is closed: fixed arguments, or slots pinned by a
strict regex, and no rule reads a file the agent can write. Free text —
the patches — travels on stdin as data, never in argv.

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

; Hand commits back: a patch series (git format-patch output) on stdin,
; applied to the review clone. Its hooks and config are yours.
git -C $HOME/review/project am --quiet

; PR status. gh's auth comes from \$HOME (which we inherit).
gh pr view #number -R example-org/project --json number,title,state,url
  number = ^[1-9][0-9]{0,5}\$

; The dev service the agent's code talks to. --no-pager: with a
; terminal on stdout, a pager would accept shell escapes.
systemctl --user --no-pager status #unit
  unit = ^[a-z0-9-]{1,40}\.service\$

journalctl --user --no-pager -n 200 -u #unit
  unit = ^[a-z0-9-]{1,40}\.service\$

; Tell you something is ready.
notify-send -t 5000 #msg
  msg = ^[A-Za-z0-9 ,.:!?()'/-]{1,80}\$
  env = DBUS_SESSION_BUS_ADDRESS
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

> **Left out on purpose.** There is no `make test`, no `npm install`
> and no `git -C $HOME/work …` here. `$HOME/work` is the agent's, so it
> writes the `Makefile`, the install scripts, `.git/hooks/` and
> `.git/config` — and any of those rules would run whatever the agent
> put there, on your host, as you. No regex changes that. They are the
> first counter-examples in
> [Auditing rules](REFERENCE.md#auditing-rules).

Test it without running the broker:

```sh
$ sluice check ~/.config/sluice/agent.rules
ok: 5 rule(s)
  line  14: BareName("git")  tokens=4  slots=0
  line  17: BareName("gh")  tokens=7  slots=1
  line  22: BareName("systemctl")  tokens=4  slots=1
  line  25: BareName("journalctl")  tokens=6  slots=1
  line  29: BareName("notify-send")  tokens=3  slots=1
```

Then try the worst values you can think of — each should be refused:

```sh
$ sluice match ~/.config/sluice/agent.rules systemctl --user --no-pager status 'api.service;id'
no match
$ sluice match ~/.config/sluice/agent.rules notify-send -t 5000 -u
no match: rule at line 29 refuses slot #msg: value starts with '-' (list the slot in allow_dash to accept option-like values)
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
python3 /usr/local/share/sluice/sluicify.py /run/agent.sock \
    systemctl --user --no-pager status api.service

# The Rust client (~380 KB static binary): the branch's commits,
# formatted inside the sandbox, applied to the review clone outside
git -C /work format-patch --stdout origin/main.. \
  | sluicify /run/agent.sock git -C /home/you/review/project am --quiet

# Node (native addon or spawn fallback)
node /usr/local/share/sluice/sluicify.js /run/agent.sock \
    notify-send -t 5000 "Patches for review in ~/review/project"
```

stdio is byte-for-byte: `systemctl`'s output appears on the agent's
stdout exactly as if it had run locally, the patch series reaches
`git am` on stdin untouched, and the exit code propagates.

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
{"call":1,"kind":"start","argv":["systemctl","--user","--no-pager","status","api.service"],"resolved":"/usr/bin/systemctl"}
{"call":1,"kind":"exit","status":0,"duration_ms":31}
{"call":2,"kind":"start","argv":["git","-C","/home/you/review/project","am","--quiet"],"resolved":"/usr/bin/git"}
{"call":2,"kind":"exit","status":0,"duration_ms":118}
{"call":3,"kind":"reject","argv":["cat","/etc/passwd"],"reason":"no_rule"}
```

`resolved` is the binary that actually ran; `argv[0]` is only what the
caller sent.

And every accepted call's actual stdout/stderr are byte-identical
sidecars:

```sh
$ cat ~/.local/state/sluice/calls/c1.out
● api.service - Example API (dev)
     Loaded: loaded (/home/you/.config/systemd/user/api.service; enabled)
     Active: active (running) since Mon 2026-10-05 09:12:44 UTC; 2h ago
```

stdin is not captured: the patch series call 2 applied is recorded by
the commits in the review clone, not by the sidecars.

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

- **`REFERENCE.md` → [Auditing rules](REFERENCE.md#auditing-rules)** —
  read before writing rules for anything that matters.
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
