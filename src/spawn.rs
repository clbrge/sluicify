//! Spawn a child for a matched rule.
//!
//! Two paths:
//! - **Direct** (default): caller's three fds are `dup2`'d straight onto
//!   the child's 0/1/2. Stdio is end-to-end kernel passthrough; the
//!   broker never touches the bytes.
//! - **Tee** (any of `stdoutfile`/`stderrfile` set): caller's fd 0 is
//!   still direct, but stdout and stderr are interposed by pipes; relay
//!   threads read from the pipe, write to the caller's fd, AND append
//!   the raw bytes to the per-call sink file. No transformation —
//!   what the child writes is byte-identical to what the caller sees
//!   and to what the file captures.

use crate::log::CallId;
use crate::proto::{ERR_SIGNALED, ERR_SPAWN};
use crate::rules::{EnvPolicy, ExeMatch, ExecPath, Rule, Rules};
use nix::fcntl::OFlag;
use nix::libc;
use nix::sys::signal::{
    kill, killpg, pthread_sigmask, signal, SigHandler, SigSet, SigmaskHow, Signal,
};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, dup2, execve, fork, getpgid, pipe2, setpgid, ForkResult, Pid};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub struct TeeSink {
    pub file: Arc<Mutex<File>>,
    pub bytes: Arc<AtomicU64>,
}

#[derive(Default)]
pub struct SpawnOutcome {
    pub status: i32,
    /// Tee mode only: relays still draining output from descendants
    /// that outlive the direct child.
    pub drain: Option<Drain>,
}

pub struct Drain {
    stdout: JoinHandle<Relayed>,
    stderr: JoinHandle<Relayed>,
    done: mpsc::Receiver<()>,
}

#[derive(Default)]
pub struct Drained {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    /// At least one sink write failed mid-call. Strict mode propagates
    /// this to the manifest's unhealthy flag, refusing the next call.
    pub sink_failed: bool,
    /// The drain deadline passed while a descendant still held a pipe.
    pub cut: bool,
}

impl Drain {
    fn settle(&self, within: Duration) {
        let deadline = Instant::now() + within;
        for _ in 0..2 {
            let left = deadline.saturating_duration_since(Instant::now());
            if self.done.recv_timeout(left).is_err() {
                return;
            }
        }
    }

    pub fn wait(self) -> Drained {
        let out = joined(self.stdout);
        let err = joined(self.stderr);
        Drained {
            stdout_bytes: out.bytes,
            stderr_bytes: err.bytes,
            sink_failed: out.sink_failed || err.sink_failed,
            cut: out.cut || err.cut,
        }
    }
}

fn joined(h: JoinHandle<Relayed>) -> Relayed {
    h.join().unwrap_or(Relayed {
        sink_failed: true,
        ..Default::default()
    })
}

#[derive(Default)]
struct Relayed {
    bytes: u64,
    sink_failed: bool,
    cut: bool,
}

const KILL_GRACE: Duration = Duration::from_secs(2);

/// Upper bound on how long the reply waits for the relays to reach EOF
/// after the direct child exits. Without background holders EOF is
/// immediate, so the caller's output and the sink are complete before
/// the reply.
const REPLY_SETTLE: Duration = Duration::from_millis(200);

pub struct SpawnCtx {
    pub call: CallId,
    pub stdout_sink: Option<TeeSink>,
    pub stderr_sink: Option<TeeSink>,
}

pub fn build_argv(rule: &Rule, caller_argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(rule.tokens.len() + 1);
    let exe = match &rule.exe {
        ExeMatch::BareName(n) => n.clone(),
        ExeMatch::Absolute(p) => p.to_string_lossy().into_owned(),
    };
    out.push(exe);
    for i in 0..rule.tokens.len() {
        out.push(caller_argv[i + 1].clone());
    }
    out
}

/// Resolve the executable path to an absolute path using the rule's
/// effective `exec_path`. We do this in Rust (not via execvpe) because
/// execvpe consults the *caller's* PATH for lookup, not envp's PATH —
/// so envp's PATH alone wouldn't gate which binary actually runs.
pub fn resolve_exe(rule: &Rule, rules: &Rules) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let bare = match &rule.exe {
        ExeMatch::Absolute(p) => return Some(p.clone()),
        ExeMatch::BareName(n) => n,
    };
    let exec_path = rule.exec_path.as_ref().unwrap_or(&rules.defaults.exec_path);
    let path_str = match exec_path {
        ExecPath::Inherit => std::env::var("PATH").ok()?,
        ExecPath::Explicit(s) => s.clone(),
    };
    for dir in path_str.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = std::path::PathBuf::from(dir).join(bare);
        if let Ok(meta) = std::fs::metadata(&candidate) {
            if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn build_envp(rule: &Rule, rules: &Rules) -> Vec<(String, String)> {
    let policy = rule.env.as_ref().unwrap_or(&rules.defaults.env);
    let mut envp: Vec<(String, String)> = match policy {
        EnvPolicy::None => Vec::new(),
        EnvPolicy::Allow(names) => names
            .iter()
            .filter_map(|n| std::env::var(n).ok().map(|v| (n.clone(), v)))
            .collect(),
    };

    // exec_path takes precedence over any inherited PATH from env. This
    // is what makes bare-name lookups go through the configured dirs
    // (defaulting to /bin:/usr/bin:/sbin:/usr/sbin) instead of whatever
    // the launcher's PATH happens to contain. execvpe consults the
    // PATH from envp, not the broker's process PATH, so this is also
    // what gates lookup.
    let exec_path = rule.exec_path.as_ref().unwrap_or(&rules.defaults.exec_path);
    let path_value = match exec_path {
        ExecPath::Inherit => std::env::var("PATH").ok(),
        ExecPath::Explicit(s) => Some(s.clone()),
    };
    if let Some(p) = path_value {
        envp.retain(|(k, _)| k != "PATH");
        envp.push(("PATH".to_string(), p));
    }
    envp
}

/// Run a matched rule.
pub fn run_matched(
    rule: &Rule,
    rules: &Rules,
    caller_argv: &[String],
    stdio: [OwnedFd; 3],
    ctx: Option<SpawnCtx>,
) -> SpawnOutcome {
    let argv = build_argv(rule, caller_argv);
    let envp = build_envp(rule, rules);
    let cwd = rule.cwd.as_ref().or(rules.defaults.cwd.as_ref()).cloned();
    let timeout = rule.timeout.or(rules.defaults.timeout);

    let argv_c: Vec<CString> = argv
        .iter()
        .filter_map(|s| CString::new(s.as_bytes()).ok())
        .collect();
    if argv_c.len() != argv.len() {
        return SpawnOutcome {
            status: ERR_SPAWN,
            ..Default::default()
        };
    }
    let envp_c: Vec<CString> = envp
        .iter()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect();

    // Resolve bare names against exec_path *now* (in the parent), so
    // `execve` gets an absolute path and lookup can't be redirected
    // through the caller's PATH.
    let resolved = match resolve_exe(rule, rules) {
        Some(p) => p,
        None => {
            eprintln!(
                "sluice: cannot resolve executable for rule at line {} (exec_path miss)",
                rule.line_no
            );
            return SpawnOutcome {
                status: ERR_SPAWN,
                ..Default::default()
            };
        }
    };
    let resolved_c = match CString::new(resolved.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => {
            return SpawnOutcome {
                status: ERR_SPAWN,
                ..Default::default()
            }
        }
    };

    let _ = Instant::now(); // start tracked in main

    let want_tee = matches!(&ctx, Some(c) if c.stdout_sink.is_some() || c.stderr_sink.is_some());

    if want_tee {
        run_with_tee(
            stdio,
            &resolved_c,
            &argv_c,
            &envp_c,
            cwd.as_deref(),
            timeout,
            ctx.unwrap(),
        )
    } else {
        let status = run_direct(
            stdio,
            &resolved_c,
            &argv_c,
            &envp_c,
            cwd.as_deref(),
            timeout,
        );
        SpawnOutcome {
            status,
            ..Default::default()
        }
    }
}

fn run_direct(
    stdio: [OwnedFd; 3],
    resolved_c: &CString,
    argv_c: &[CString],
    envp_c: &[CString],
    cwd: Option<&std::path::Path>,
    timeout: Option<Duration>,
) -> i32 {
    let raw: [RawFd; 3] = [
        stdio[0].as_raw_fd(),
        stdio[1].as_raw_fd(),
        stdio[2].as_raw_fd(),
    ];
    match unsafe { fork() } {
        Err(_) => ERR_SPAWN,
        Ok(ForkResult::Child) => {
            reset_child_signals();
            // Become own process-group leader. Both parent and child
            // call setpgid to close the race window — whichever lands
            // first wins, the other returns EACCES (harmless).
            let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));
            for (i, fd) in raw.iter().enumerate() {
                if dup2(*fd, i as RawFd).is_err() {
                    unsafe { nix::libc::_exit(127) };
                }
            }
            if let Some(p) = cwd {
                if chdir(p).is_err() {
                    unsafe { nix::libc::_exit(126) };
                }
            }
            let _ = execve(resolved_c, argv_c, envp_c);
            unsafe { nix::libc::_exit(127) };
        }
        Ok(ForkResult::Parent { child }) => {
            let _ = setpgid(child, child);
            wait_child_with_timeout(child, timeout)
        }
    }
}

fn run_with_tee(
    stdio: [OwnedFd; 3],
    resolved_c: &CString,
    argv_c: &[CString],
    envp_c: &[CString],
    cwd: Option<&std::path::Path>,
    timeout: Option<Duration>,
    ctx: SpawnCtx,
) -> SpawnOutcome {
    let [stdin_fd, stdout_fd, stderr_fd] = stdio;

    let (pout_r, pout_w) = match pipe2(OFlag::O_CLOEXEC) {
        Ok(p) => p,
        Err(_) => {
            return SpawnOutcome {
                status: ERR_SPAWN,
                ..Default::default()
            }
        }
    };
    let (perr_r, perr_w) = match pipe2(OFlag::O_CLOEXEC) {
        Ok(p) => p,
        Err(_) => {
            return SpawnOutcome {
                status: ERR_SPAWN,
                ..Default::default()
            }
        }
    };

    let drain_deadline = timeout.map(|t| Instant::now() + t + KILL_GRACE);
    let stdin_raw = stdin_fd.as_raw_fd();
    let pout_w_raw = pout_w.as_raw_fd();
    let perr_w_raw = perr_w.as_raw_fd();

    match unsafe { fork() } {
        Err(_) => SpawnOutcome {
            status: ERR_SPAWN,
            ..Default::default()
        },
        Ok(ForkResult::Child) => {
            reset_child_signals();
            let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));
            if dup2(stdin_raw, 0).is_err()
                || dup2(pout_w_raw, 1).is_err()
                || dup2(perr_w_raw, 2).is_err()
            {
                unsafe { nix::libc::_exit(127) };
            }
            if let Some(p) = cwd {
                if chdir(p).is_err() {
                    unsafe { nix::libc::_exit(126) };
                }
            }
            let _ = execve(resolved_c, argv_c, envp_c);
            unsafe { nix::libc::_exit(127) };
        }
        Ok(ForkResult::Parent { child }) => {
            let _ = setpgid(child, child);
            drop(pout_w);
            drop(perr_w);
            drop(stdin_fd);

            let (done_tx, done) = mpsc::channel();
            let stdout_done = done_tx.clone();
            let stdout = std::thread::spawn(move || {
                let r = relay(pout_r, stdout_fd, ctx.stdout_sink, drain_deadline);
                let _ = stdout_done.send(());
                r
            });
            let stderr = std::thread::spawn(move || {
                let r = relay(perr_r, stderr_fd, ctx.stderr_sink, drain_deadline);
                let _ = done_tx.send(());
                r
            });

            let status = wait_child_with_timeout(child, timeout);
            let drain = Drain {
                stdout,
                stderr,
                done,
            };
            drain.settle(REPLY_SETTLE);
            SpawnOutcome {
                status,
                drain: Some(drain),
            }
        }
    }
}

/// Runs until every writer has closed the pipe or, past `deadline`,
/// until nothing is left buffered. `sink_failed` lets the caller mark
/// the broker unhealthy so the next strict-mode call refuses,
/// symmetric with manifest write failures.
fn relay(src: OwnedFd, dst: OwnedFd, sink: Option<TeeSink>, deadline: Option<Instant>) -> Relayed {
    let mut buf = [0u8; 8192];
    let mut out = Relayed::default();
    loop {
        if let Some(d) = deadline {
            let left_ms = d
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32;
            match poll_readable(&src, left_ms) {
                0 => {
                    out.cut = true;
                    break;
                }
                r if r < 0 => break,
                _ => {}
            }
        }
        let n = match nix::unistd::read(src.as_raw_fd(), &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        };
        // Forward to caller (best effort — caller may have gone away).
        let _ = write_all(&dst, &buf[..n]);
        // Tee to sink. Only count bytes we actually wrote — the
        // manifest's stdout_bytes/stderr_bytes must reflect what's on
        // disk, not what we attempted.
        if let Some(s) = &sink {
            let written = if let Ok(mut f) = s.file.lock() {
                use std::io::Write;
                match f.write_all(&buf[..n]) {
                    Ok(()) => n as u64,
                    Err(e) => {
                        eprintln!("sluice: AUDIT SINK WRITE FAILED: {e}");
                        out.sink_failed = true;
                        0
                    }
                }
            } else {
                out.sink_failed = true;
                0
            };
            s.bytes.fetch_add(written, Ordering::Relaxed);
            out.bytes += written;
        }
    }
    out
}

fn write_all(fd: &OwnedFd, mut buf: &[u8]) -> Result<(), nix::errno::Errno> {
    while !buf.is_empty() {
        match nix::unistd::write(fd.as_fd(), buf) {
            Ok(0) => return Err(nix::errno::Errno::EIO),
            Ok(n) => buf = &buf[n..],
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Both survive execve: the Rust runtime ignores SIGPIPE at startup and
/// `serve` blocks SIGHUP for its sigwait thread.
fn reset_child_signals() {
    let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None);
    let _ = unsafe { signal(Signal::SIGPIPE, SigHandler::SigDfl) };
}

fn wait_child(pid: Pid) -> i32 {
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => return code.clamp(0, 255),
            Ok(WaitStatus::Signaled(_, _, _)) => return ERR_SIGNALED,
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return ERR_SPAWN,
        }
    }
}

/// Race-free wait+timeout via `pidfd_open` + `poll`. Signals are sent
/// to the child's *process group* via `killpg` so grandchildren that
/// inherit the group are caught (e.g. `sh -c 'helper & wait'`).
///
/// We verify `getpgid(child) == child` before each `killpg` so a freak
/// `setpgid` failure can't cause the broker to signal its own group.
/// In that fallback we send to the direct child only via pidfd — at
/// worst the grandchildren leak (same as pre-fix behavior).
///
/// Falls back to a plain `wait_child` (no timeout) if `pidfd_open`
/// isn't supported (Linux < 5.3 — basically nothing in 2026).
fn wait_child_with_timeout(pid: Pid, timeout: Option<Duration>) -> i32 {
    let timeout = match timeout {
        None => return wait_child(pid),
        Some(d) => d,
    };

    let pidfd = match pidfd_open(pid) {
        Ok(fd) => fd,
        Err(_) => {
            let _ = kill_tree(pid, Signal::SIGTERM, None);
            return wait_child(pid);
        }
    };

    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    if poll_readable(&pidfd, timeout_ms) == 0 {
        // Timeout fired. Signal the whole process group, then a brief
        // grace period, then SIGKILL the group.
        let _ = kill_tree(pid, Signal::SIGTERM, Some(&pidfd));
        if poll_readable(&pidfd, KILL_GRACE.as_millis() as i32) == 0 {
            let _ = kill_tree(pid, Signal::SIGKILL, Some(&pidfd));
        }
    }
    drop(pidfd);
    wait_child(pid)
}

/// Send `sig` to `child`'s process group if `child` is the group leader
/// (the expected state after our setpgid pair). Falls back to a single
/// pidfd-based signal to the direct child if the pgid check fails.
fn kill_tree(child: Pid, sig: Signal, pidfd: Option<&OwnedFd>) -> std::io::Result<()> {
    match getpgid(Some(child)) {
        Ok(pgid) if pgid == child => {
            // child is its own group leader → safe to signal the group.
            killpg(child, sig).map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        }
        _ => {
            // setpgid didn't take effect (extremely rare) — fall back
            // to single-process kill so we don't accidentally signal
            // the broker's group.
            if let Some(fd) = pidfd {
                pidfd_send_signal(fd, sig as i32)
            } else {
                kill(child, sig).map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            }
        }
    }
}

fn pidfd_open(pid: Pid) -> std::io::Result<OwnedFd> {
    // SYS_pidfd_open(pid, flags). Linux 5.3+.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn pidfd_send_signal(pidfd: &OwnedFd, sig: i32) -> std::io::Result<()> {
    // SYS_pidfd_send_signal(pidfd, sig, info, flags). Linux 5.1+.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Returns: positive if `fd` is readable (for a pidfd: the process
/// exited; for a pipe: data or hangup), 0 on timeout, negative on error.
fn poll_readable(fd: &OwnedFd, timeout_ms: i32) -> i32 {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let r = unsafe { libc::poll(&mut pfd as *mut _, 1, timeout_ms) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return -1;
        }
        return r;
    }
}

// Quiet the now-unused-via-removed-path `kill` import warning while
// keeping it available for the pidfd-open-failure fallback above.
#[allow(unused_imports)]
use nix::sys::signal::kill as _kill_alias;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn resolve_exe_absolute_path_passes_through() {
        let r = parse("/bin/echo\n").unwrap();
        let resolved = resolve_exe(&r.rules[0], &r);
        assert_eq!(resolved.unwrap(), std::path::PathBuf::from("/bin/echo"));
    }

    #[test]
    fn resolve_exe_bare_name_finds_in_classic_path() {
        // Default exec_path includes /bin and /usr/bin; `sh` lives in one of them.
        let r = parse("sh\n").unwrap();
        let resolved = resolve_exe(&r.rules[0], &r);
        let p = resolved.expect("sh should resolve in default exec_path");
        let s = p.to_string_lossy();
        assert!(
            s == "/bin/sh" || s == "/usr/bin/sh",
            "unexpected resolved path: {s}"
        );
    }

    #[test]
    fn resolve_exe_bare_name_not_found_returns_none() {
        let r = parse("sluicify-no-such-binary-zzz\n").unwrap();
        assert!(resolve_exe(&r.rules[0], &r).is_none());
    }

    #[test]
    fn resolve_exe_uses_explicit_exec_path() {
        // Force exec_path to /usr/bin only — `ls` is there.
        let r = parse("defaults:\n  exec_path = /usr/bin\n\nls\n").unwrap();
        let resolved = resolve_exe(&r.rules[0], &r);
        assert_eq!(resolved.unwrap(), std::path::PathBuf::from("/usr/bin/ls"));
    }

    #[test]
    fn resolve_exe_skips_non_executable_match() {
        // Make a file that looks right but isn't executable; resolution should miss.
        let dir = tempdir();
        let candidate = dir.join("fake-exe");
        std::fs::write(&candidate, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o644)).unwrap();
        let rule_text = format!(
            "defaults:\n  exec_path = {}\n\nfake-exe\n",
            dir.to_string_lossy()
        );
        let r = parse(&rule_text).unwrap();
        assert!(resolve_exe(&r.rules[0], &r).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_envp_none_with_default_path_emits_only_path() {
        let r = parse("defaults:\n  env = none\n\necho\n").unwrap();
        let envp = build_envp(&r.rules[0], &r);
        assert_eq!(envp.len(), 1);
        assert_eq!(envp[0].0, "PATH");
        assert_eq!(envp[0].1, "/bin:/usr/bin:/sbin:/usr/sbin");
    }

    #[test]
    fn build_envp_explicit_exec_path_overrides_inherited_path() {
        // env policy lists PATH (so it would be inherited), but exec_path
        // is the source of truth. We assert PATH is from exec_path, not
        // from std::env::var("PATH").
        let r =
            parse("defaults:\n  env = PATH\n  exec_path = /opt/sluice-test-bin\n\necho\n").unwrap();
        let envp = build_envp(&r.rules[0], &r);
        let path = envp.iter().find(|(k, _)| k == "PATH").unwrap();
        assert_eq!(path.1, "/opt/sluice-test-bin");
        assert_eq!(envp.len(), 1, "no other vars should appear: {envp:?}");
    }

    #[test]
    fn build_argv_for_bare_name_keeps_token_count() {
        let r = parse("git log -n #1\n").unwrap();
        let caller = vec!["git".into(), "log".into(), "-n".into(), "5".into()];
        let argv = build_argv(&r.rules[0], &caller);
        assert_eq!(argv, vec!["git", "log", "-n", "5"]);
    }

    use std::path::PathBuf;
    fn tempdir() -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sluicify-spawn-test-{pid}-{nanos}"));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&p)
            .unwrap();
        p
    }
}
