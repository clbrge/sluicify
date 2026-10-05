use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fs::File;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use nix::sys::socket::{
    accept4, bind, listen, recvmsg, sendmsg, setsockopt, socket, sockopt, AddressFamily, Backlog,
    ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
};
use nix::sys::time::TimeVal;
use sluicify::log::{open_raw, CallId, ExitEvent, Logger};
use sluicify::peer::peer_of;
use sluicify::proto::{
    decode_request, encode_reply, Request, ERR_AUDIT, ERR_FDS, ERR_NO_RULE, ERR_PROTO, MAX_PAYLOAD,
};
use sluicify::rules::{self, AuditMode, LogPolicy, PathCtx, PathTemplate, Rules};
use sluicify::spawn::{run_matched, Drain, Drained, SpawnCtx, SpawnOutcome, TeeSink};

#[derive(Parser)]
#[command(name = "sluice", version, about = "AF_UNIX command broker")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Check {
        rules: PathBuf,
    },
    Match {
        rules: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    Serve {
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        socket: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Check { rules } => check(&rules),
        Cmd::Match { rules, argv } => match_cmd(&rules, &argv),
        Cmd::Serve { rules, socket } => match serve(&rules, &socket) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sluice: {e}");
                ExitCode::from(2)
            }
        },
    }
}

fn read_rules(path: &Path) -> Result<Rules, String> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    rules::parse(&src).map_err(|e| format!("parse error: {e}"))
}

fn check(path: &Path) -> ExitCode {
    let rules = match read_rules(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sluice: {e}");
            return ExitCode::from(1);
        }
    };
    println!("ok: {} rule(s)", rules.rules.len());
    for r in &rules.rules {
        println!(
            "  line {:>3}: {:?}  tokens={}  slots={}",
            r.line_no,
            r.exe,
            r.tokens.len(),
            r.slot_regex.len()
        );
    }
    for r in &rules.rules {
        for slot in r.unconstrained_slots() {
            println!(
                "warning: line {}: slot {slot} has no regex — accepts any value, including option flags",
                r.line_no
            );
        }
    }
    ExitCode::SUCCESS
}

fn match_cmd(path: &Path, argv: &[String]) -> ExitCode {
    let rules = match read_rules(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sluice: {e}");
            return ExitCode::from(1);
        }
    };
    match rules.match_argv(argv) {
        Some(m) => {
            println!("match: rule at line {}", m.rule.line_no);
            for (k, v) in &m.bindings {
                println!("  {k} = {v:?}");
            }
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("no match");
            ExitCode::from(1)
        }
    }
}

/// Cache of open raw-byte sink files keyed by resolved path. Concurrent
/// calls that resolve to the same file share one `Mutex<File>`; appends
/// serialize through it so no interleaving is possible regardless of
/// write size. Entries are `Weak` so the file closes when the last
/// relay holding it drops — for per-call paths the cache effectively
/// holds nothing alive between calls.
#[derive(Default)]
struct SinkCache {
    files: Mutex<HashMap<PathBuf, std::sync::Weak<Mutex<File>>>>,
}

impl SinkCache {
    fn get_or_open(&self, path: &Path) -> std::io::Result<Arc<Mutex<File>>> {
        let mut map = self.files.lock().unwrap();
        if let Some(weak) = map.get(path) {
            if let Some(arc) = weak.upgrade() {
                return Ok(arc);
            }
        }
        let f = open_raw(path)?;
        let arc = Arc::new(Mutex::new(f));
        map.insert(path.to_path_buf(), Arc::downgrade(&arc));
        // Cheap periodic prune: when the map gets large, drop dead Weaks.
        if map.len() > 1024 {
            map.retain(|_, w| w.strong_count() > 0);
        }
        Ok(arc)
    }

    fn clear(&self) {
        self.files.lock().unwrap().clear();
    }
}

/// Live ruleset + manifest. Atomically swappable on SIGHUP.
struct LiveState {
    rules: Arc<Rules>,
    manifest: Option<Arc<Logger>>,
}

fn open_state(rules_path: &Path) -> Result<(Arc<LiveState>, Option<PathBuf>), String> {
    let rules = Arc::new(read_rules(rules_path)?);
    let manifest_path = resolve_manifest_path(&rules);
    let manifest = match &manifest_path {
        Some(p) => match Logger::open(p) {
            Ok(l) => Some(Arc::new(l)),
            Err(e) => return Err(format!("cannot open logfile {}: {e}", p.display())),
        },
        None => None,
    };
    Ok((Arc::new(LiveState { rules, manifest }), manifest_path))
}

fn serve(rules_path: &Path, sock_path: &Path) -> Result<(), String> {
    // Block SIGHUP in the main thread — it inherits to all spawned
    // worker threads. The dedicated reload thread will be the only
    // place that observes it (via sigwait).
    let mut hup_set = SigSet::empty();
    hup_set.add(Signal::SIGHUP);
    nix::sys::signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&hup_set), None)
        .map_err(|e| format!("sigprocmask: {e}"))?;

    let (state, manifest_path) = open_state(rules_path)?;
    if let Some(p) = &manifest_path {
        eprintln!("sluice: manifest = {}", p.display());
    }
    let state: Arc<Mutex<Arc<LiveState>>> = Arc::new(Mutex::new(state));

    {
        let snap = state.lock().unwrap().clone();
        check_socket_parent(sock_path, snap.rules.defaults.audit)?;
    }

    // Stale-socket cleanup
    if let Ok(meta) = std::fs::symlink_metadata(sock_path) {
        use std::os::unix::fs::FileTypeExt;
        if meta.file_type().is_socket() {
            std::fs::remove_file(sock_path)
                .map_err(|e| format!("cannot remove stale socket: {e}"))?;
        } else {
            return Err(format!(
                "{} exists and is not a socket — refusing to overwrite",
                sock_path.display()
            ));
        }
    }

    let prev_umask = unsafe { nix::libc::umask(0o077) };
    let listener: OwnedFd = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| format!("socket(): {e}"))?;
    let addr = UnixAddr::new(sock_path).map_err(|e| format!("UnixAddr: {e}"))?;
    bind(listener.as_raw_fd(), &addr).map_err(|e| format!("bind(): {e}"))?;
    listen(&listener, Backlog::new(64).unwrap()).map_err(|e| format!("listen(): {e}"))?;
    unsafe { nix::libc::umask(prev_umask) };

    {
        let snap = state.lock().unwrap().clone();
        eprintln!(
            "sluice: serving {} rules at {} (max {} concurrent)",
            snap.rules.rules.len(),
            sock_path.display(),
            MAX_ACTIVE
        );
    }

    let sinks = Arc::new(SinkCache::default());
    let active = Arc::new(AtomicUsize::new(0));
    // Monotonic call counter — survives SIGHUP reload (Logger no longer
    // owns it, so reopening the manifest doesn't reset call IDs).
    let call_counter = Arc::new(AtomicU64::new(1));

    // Reload thread: sigwait on SIGHUP, atomically swap LiveState.
    {
        let state_h = Arc::clone(&state);
        let sinks_h = Arc::clone(&sinks);
        let rules_path_h = rules_path.to_path_buf();
        std::thread::spawn(move || reload_thread(rules_path_h, state_h, sinks_h));
    }

    loop {
        let conn_raw = match accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                eprintln!("sluice: accept: {e}");
                continue;
            }
        };
        let conn = unsafe { OwnedFd::from_raw_fd(conn_raw) };

        // Receive deadline: a connected client that doesn't send within
        // RECV_TIMEOUT_SECS holds a slot only that long, then `recvmsg`
        // returns EAGAIN and we close. Without this, an authorized but
        // misbehaving caller can hold MAX_ACTIVE slots forever.
        let tv = TimeVal::new(RECV_TIMEOUT_SECS, 0);
        let _ = setsockopt(&conn, sockopt::ReceiveTimeout, &tv);

        let n = active.fetch_add(1, Ordering::SeqCst);
        if n >= MAX_ACTIVE {
            active.fetch_sub(1, Ordering::SeqCst);
            eprintln!("sluice: at cap ({MAX_ACTIVE}), rejecting connection");
            drop(conn);
            continue;
        }

        // Snapshot the current LiveState. In-flight calls keep their
        // snapshot across a SIGHUP; new calls see the fresh state.
        let snap = state.lock().unwrap().clone();
        let sk = Arc::clone(&sinks);
        let a = Arc::clone(&active);
        let cc = Arc::clone(&call_counter);
        std::thread::spawn(move || {
            handle_conn(conn, snap, sk, cc);
            a.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn reload_thread(rules_path: PathBuf, state: Arc<Mutex<Arc<LiveState>>>, sinks: Arc<SinkCache>) {
    let mut set = SigSet::empty();
    set.add(Signal::SIGHUP);
    loop {
        match set.wait() {
            Ok(Signal::SIGHUP) => {
                eprintln!("sluice: SIGHUP — reloading rules");
                match open_state(&rules_path) {
                    Ok((new_state, _)) => {
                        *state.lock().unwrap() = new_state;
                        sinks.clear();
                        eprintln!("sluice: reload OK");
                    }
                    Err(e) => {
                        eprintln!("sluice: reload failed: {e} — keeping old rules");
                    }
                }
            }
            Ok(_) | Err(_) => {} // ignore others; sigwait may return EINTR
        }
    }
}

const MAX_ACTIVE: usize = 64;
const RECV_TIMEOUT_SECS: i64 = 5;

/// Check that the socket's parent directory is not writable by anyone
/// other than the broker's uid. Mode 0600 on the socket file itself
/// protects the connect path, but a permissive parent lets other uids
/// `rm` or replace the socket — DoS at minimum.
///
/// Behavior depends on `audit` mode:
/// - `Strict`     → refuse to bind (return Err) when permissive
/// - `BestEffort` → warn on stderr and proceed
///
/// Sticky-bit `/tmp` (1777) is still considered permissive under
/// strict — non-owners can't unlink, but metadata leakage and bind
/// races still apply, and an audit broker should err on the safer side.
fn check_socket_parent(sock_path: &Path, audit: AuditMode) -> Result<(), String> {
    let Some(parent) = sock_path.parent() else {
        return Ok(());
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let meta = match std::fs::metadata(parent) {
        Ok(m) => m,
        Err(e) => {
            // Can't stat — safer to surface this and let the bind fail
            // naturally, rather than guess.
            eprintln!(
                "sluice: WARNING: cannot stat socket parent {}: {e}",
                parent.display()
            );
            return Ok(());
        }
    };
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o7777;
    let owner = meta.uid();
    let our_uid = nix::unistd::geteuid().as_raw();

    let group_w = mode & 0o020 != 0;
    let world_w = mode & 0o002 != 0;
    let sticky = mode & 0o1000 != 0;
    let owned_by_us = owner == our_uid;

    if !group_w && !world_w && owned_by_us {
        return Ok(());
    }

    let mut notes: Vec<String> = Vec::new();
    if !owned_by_us {
        notes.push(format!("uid={} (broker is {})", owner, our_uid));
    }
    if world_w {
        notes.push(
            if sticky {
                "world-writable (sticky bit limits unlink to owner)"
            } else {
                "world-writable"
            }
            .to_string(),
        );
    }
    if group_w {
        notes.push("group-writable".into());
    }

    let summary = format!(
        "socket parent {} mode={:04o} {}",
        parent.display(),
        mode,
        notes.join(", ")
    );

    match audit {
        AuditMode::Strict => Err(format!(
            "refusing to bind ({}). \
             Use a directory you own with mode 0700 (e.g. /run/sluice/), \
             or set `audit = best-effort` in defaults to downgrade to a warning.",
            summary
        )),
        AuditMode::BestEffort => {
            eprintln!(
                "sluice: WARNING: {summary} — a uid with write access here can rm or \
                 replace the socket. Prefer a directory you own with mode 0700."
            );
            Ok(())
        }
    }
}

/// Pick the manifest path (if any). Looks at defaults.logfile first;
/// per-rule manifest paths aren't supported (it's intentionally a
/// single shared timeline). Resolves slots with a sentinel context so
/// operators can use static paths or a `#$ts`-stamped one for daily
/// rotation. Per-call slots in the manifest path are nonsensical and
/// would refuse to resolve usefully — operators who want per-call
/// files use `stdoutfile`/`stderrfile`.
fn resolve_manifest_path(rules: &Rules) -> Option<PathBuf> {
    let t = rules.defaults.logfile.as_ref()?;
    let ctx = PathCtx {
        call: 0,
        pid: 0,
        uid: 0,
        rule: 0,
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        ts_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };
    Some(t.resolve(&ctx))
}

fn effective_path<'a>(
    rule_attr: Option<&'a PathTemplate>,
    default_attr: Option<&'a PathTemplate>,
) -> Option<&'a PathTemplate> {
    rule_attr.or(default_attr)
}

fn handle_conn(
    conn: OwnedFd,
    snap: Arc<LiveState>,
    sinks: Arc<SinkCache>,
    call_counter: Arc<AtomicU64>,
) {
    let rules = &snap.rules;
    let manifest = &snap.manifest;
    // Rejects happen before rule matching, so they fall back to defaults.log.
    let reject_log_argv = rules.defaults.log != LogPolicy::ExitOnly;
    let next_call = || CallId(call_counter.fetch_add(1, Ordering::SeqCst));
    let status = match recv_request(&conn) {
        Ok((req, fds)) => match fds {
            None => {
                if let Some(l) = manifest {
                    let argv: &[String] = if reject_log_argv { &req.argv } else { &[] };
                    l.reject(next_call(), "wrong_fd_count", argv);
                } else if reject_log_argv {
                    eprintln!("sluice: rejected (wrong fd count) argv={:?}", req.argv);
                } else {
                    eprintln!("sluice: rejected (wrong fd count)");
                }
                ERR_FDS
            }
            Some(stdio) => match rules.match_argv(&req.argv) {
                None => {
                    if let Some(l) = manifest {
                        let argv: &[String] = if reject_log_argv { &req.argv } else { &[] };
                        l.reject(next_call(), "no_rule", argv);
                    } else if reject_log_argv {
                        eprintln!("sluice: no rule matched argv={:?}", req.argv);
                    } else {
                        eprintln!("sluice: no rule matched (argv suppressed)");
                    }
                    ERR_NO_RULE
                }
                Some(m) => {
                    return dispatch(m.rule, &snap, &req, stdio, &conn, &sinks, &call_counter)
                }
            },
        },
        Err(()) => ERR_PROTO,
    };
    send_reply(&conn, status);
}

fn send_reply(conn: &OwnedFd, status: i32) {
    let reply = encode_reply(status);
    let _ = sendmsg::<UnixAddr>(
        conn.as_raw_fd(),
        &[IoSlice::new(&reply)],
        &[],
        MsgFlags::empty(),
        None,
    );
}

fn dispatch(
    rule: &rules::Rule,
    snap: &LiveState,
    req: &Request,
    stdio: [OwnedFd; 3],
    conn: &OwnedFd,
    sinks: &Arc<SinkCache>,
    call_counter: &Arc<AtomicU64>,
) {
    let rules: &Rules = &snap.rules;
    let manifest = &snap.manifest;
    let peer = peer_of(conn);
    let peer_pid = peer.map(|p| p.pid).unwrap_or(0);
    let peer_uid = peer.map(|p| p.uid).unwrap_or(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Effective log policy: rule overrides defaults.
    //   Full       → start+exit events (with argv) + stdio tee if sinks set
    //   ArgvOnly   → start+exit events (with argv), no stdio tee
    //   ExitOnly   → exit event only (NO argv anywhere), no stdio tee
    let effective_log = rule.log.unwrap_or(rules.defaults.log);
    let log_argv = effective_log != LogPolicy::ExitOnly;
    let allow_tee = effective_log == LogPolicy::Full;

    // Resolve effective stdoutfile/stderrfile (rule overrides default).
    // We only consult them when the policy permits stdio tee — otherwise
    // we'd open files we never write to.
    let stdout_tmpl = if allow_tee {
        effective_path(rule.stdoutfile.as_ref(), rules.defaults.stdoutfile.as_ref())
    } else {
        None
    };
    let stderr_tmpl = if allow_tee {
        effective_path(rule.stderrfile.as_ref(), rules.defaults.stderrfile.as_ref())
    } else {
        None
    };

    // Allocate a call id whenever any audit channel will fire.
    let any_audit = manifest.is_some() || stdout_tmpl.is_some() || stderr_tmpl.is_some();
    let call_id = if any_audit {
        Some(CallId(call_counter.fetch_add(1, Ordering::SeqCst)))
    } else {
        None
    };

    let path_ctx = PathCtx {
        call: call_id.map(|c| c.0).unwrap_or(0),
        pid: peer_pid,
        uid: peer_uid,
        rule: rule.line_no,
        ts: now.as_secs(),
        ts_ms: now.as_millis() as u64,
    };

    let stdout_path = stdout_tmpl.map(|t| t.resolve(&path_ctx));
    let stderr_path = stderr_tmpl.map(|t| t.resolve(&path_ctx));

    let mut sink_open_failed: Option<String> = None;
    let stdout_sink = stdout_path
        .as_ref()
        .and_then(|p| match sinks.get_or_open(p) {
            Ok(file) => Some(TeeSink {
                file,
                bytes: Arc::new(AtomicU64::new(0)),
            }),
            Err(e) => {
                eprintln!("sluice: cannot open stdoutfile {}: {e}", p.display());
                sink_open_failed = Some(format!("stdoutfile {}: {e}", p.display()));
                None
            }
        });
    let stderr_sink = stderr_path
        .as_ref()
        .and_then(|p| match sinks.get_or_open(p) {
            Ok(file) => Some(TeeSink {
                file,
                bytes: Arc::new(AtomicU64::new(0)),
            }),
            Err(e) => {
                eprintln!("sluice: cannot open stderrfile {}: {e}", p.display());
                sink_open_failed.get_or_insert_with(|| format!("stderrfile {}: {e}", p.display()));
                None
            }
        });

    // Strict audit: refuse to execute when a configured sink is
    // unwritable. Without this, an operator running sluice for
    // compliance/audit could get silent gaps in the record.
    if sink_open_failed.is_some() && rules.defaults.audit == AuditMode::Strict {
        let reason = sink_open_failed.unwrap();
        if let (Some(l), Some(call)) = (manifest, call_id) {
            let argv: &[String] = if log_argv { &req.argv } else { &[] };
            l.reject(call, &format!("audit_unwritable: {reason}"), argv);
        }
        eprintln!("sluice: refusing to execute (audit=strict): {reason}");
        send_reply(conn, ERR_AUDIT);
        return;
    }

    // Strict + unhealthy manifest: refuse before doing anything else.
    // Once a manifest write has failed, the audit log is already broken
    // and continuing produces silent gaps — the exact failure mode
    // strict mode exists to prevent.
    if let Some(l) = manifest {
        if !l.is_healthy() && rules.defaults.audit == AuditMode::Strict {
            eprintln!("sluice: refusing to execute (audit=strict): manifest unhealthy");
            send_reply(conn, ERR_AUDIT);
            return;
        }
    }

    // Manifest start event — skipped under ExitOnly (the operator
    // explicitly asked to keep argv out of the audit log).
    if let (Some(l), Some(call)) = (manifest, call_id) {
        if log_argv {
            let ok = l.start(
                call,
                peer_pid,
                rule.line_no,
                &req.argv,
                stdout_path.as_deref(),
                stderr_path.as_deref(),
            );
            if !ok && rules.defaults.audit == AuditMode::Strict {
                eprintln!("sluice: refusing to execute (audit=strict): start write failed");
                send_reply(conn, ERR_AUDIT);
                return;
            }
        }
    } else if log_argv {
        eprintln!(
            "sluice: match line={} pid={} argv={:?}",
            rule.line_no, peer_pid, req.argv
        );
    } else {
        eprintln!("sluice: match line={} pid={}", rule.line_no, peer_pid);
    }

    let started = Instant::now();
    let ctx = if stdout_sink.is_some() || stderr_sink.is_some() {
        Some(SpawnCtx {
            call: call_id.unwrap_or(CallId(0)),
            stdout_sink,
            stderr_sink,
        })
    } else {
        None
    };
    let SpawnOutcome { status, drain } = run_matched(rule, rules, &req.argv, stdio, ctx);
    let dur_ms = started.elapsed().as_millis() as u64;
    send_reply(conn, status);
    let Drained {
        stdout_bytes,
        stderr_bytes,
        sink_failed,
        cut,
    } = drain.map(Drain::wait).unwrap_or_default();

    // A sink write failed mid-call. Mid-call we can't undo — the child
    // already produced bytes that didn't make it to disk. But we
    // propagate to the manifest's unhealthy flag so the next strict-
    // mode call refuses, symmetric with manifest write failures.
    if sink_failed {
        if let Some(l) = manifest {
            l.mark_unhealthy();
        }
        eprintln!(
            "sluice: AUDIT SINK FAILED mid-call (call={}); strict mode will refuse next calls",
            call_id.map(|c| c.0).unwrap_or(0)
        );
    }

    if let (Some(l), Some(call)) = (manifest, call_id) {
        l.exit(
            call,
            &ExitEvent {
                status,
                duration_ms: dur_ms,
                stdout_bytes,
                stderr_bytes,
                truncated: sink_failed,
                drain_timeout: cut,
            },
        );
    }
}

fn recv_request(conn: &OwnedFd) -> Result<(Request, Option<[OwnedFd; 3]>), ()> {
    let mut buf = vec![0u8; MAX_PAYLOAD];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    // Sized for the kernel's per-message SCM_MAX_FD so MSG_CTRUNC can't
    // fire: on truncation nix refuses to iterate, and the fds that did
    // arrive would be unreachable.
    let mut cmsg = nix::cmsg_space!([RawFd; SCM_MAX_FD]);

    let msg = recvmsg::<UnixAddr>(
        conn.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(|_| ())?;
    let n = msg.bytes;

    let mut fds: Vec<OwnedFd> = Vec::new();
    for c in msg.cmsgs().map_err(|_| ())? {
        if let ControlMessageOwned::ScmRights(rfds) = c {
            fds.extend(
                rfds.into_iter()
                    .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
            );
        }
    }

    let req = decode_request(&buf[..n]).map_err(|_| ())?;
    let stdio = <[OwnedFd; 3]>::try_from(fds).ok();
    Ok((req, stdio))
}

const SCM_MAX_FD: usize = 253;
