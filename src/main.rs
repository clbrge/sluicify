use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use nix::sys::socket::{
    accept4, bind, connect, listen, recvmsg, sendmsg, setsockopt, socket, sockopt, AddressFamily,
    Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
};
use nix::sys::time::TimeVal;
use sluicify::log::{open_raw, CallId, ExitEvent, Logger, StartEvent};
use sluicify::peer::peer_of;
use sluicify::proto::{
    decode_request, encode_listing, encode_reply, Request, ERR_AUDIT, ERR_FDS, ERR_NO_RULE,
    ERR_PEER, ERR_PROTO, ERR_SPAWN, ERR_TOO_LARGE, MAX_LISTING, MAX_PAYLOAD,
};
use sluicify::rules::{
    self, AuditMode, LogPolicy, Miss, PathCtx, PathTemplate, Rules, TokenPattern,
};
use sluicify::spawn::{resolve_exe, run_matched, Drain, Drained, SpawnCtx, SpawnOutcome, TeeSink};

#[derive(Parser)]
#[command(name = "sluice", version, about = "AF_UNIX command broker")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Check {
        rules: Option<PathBuf>,
        #[arg(long, conflicts_with = "rules")]
        rules_dir: Option<PathBuf>,
    },
    Match {
        rules: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    Serve {
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["rules", "socket"])]
        rules_dir: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["rules", "socket"])]
        socket_dir: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Check {
            rules: Some(rules), ..
        } => check(&rules),
        Cmd::Check {
            rules_dir: Some(dir),
            ..
        } => check_dir(&dir),
        Cmd::Check { .. } => {
            eprintln!("sluice: check takes a rules file, or --rules-dir <dir>");
            ExitCode::from(2)
        }
        Cmd::Match { rules, argv } => match_cmd(&rules, &argv),
        Cmd::Serve {
            rules,
            socket,
            rules_dir,
            socket_dir,
        } => {
            let served = match (rules, socket, rules_dir, socket_dir) {
                (Some(rules), Some(socket), None, None) => serve(&rules, &socket),
                (None, None, Some(rules_dir), Some(socket_dir)) => {
                    serve_dir(&rules_dir, &socket_dir)
                }
                _ => Err(
                    "serve takes --rules and --socket, or --rules-dir and --socket-dir".to_string(),
                ),
            };
            match served {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("sluice: {e}");
                    ExitCode::from(2)
                }
            }
        }
    }
}

fn read_rules(path: &Path) -> Result<Rules, String> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    rules::parse(&src).map_err(|e| format!("parse error: {e}"))
}

fn check(path: &Path) -> ExitCode {
    if report(path) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn check_dir(dir: &Path) -> ExitCode {
    let found = match rules_files(dir) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("sluice: {e}");
            return ExitCode::from(1);
        }
    };
    for why in &found.refused {
        eprintln!("sluice: {why}");
    }
    if found.files.is_empty() && found.refused.is_empty() {
        println!("no *.rules files in {}", dir.display());
    }
    let mut ok = found.refused.is_empty();
    for (name, path) in &found.files {
        println!("{name}:");
        ok &= report(path);
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Parses one rules file and says what it holds, or why it does not parse.
fn report(path: &Path) -> bool {
    let rules = match read_rules(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sluice: {e}");
            return false;
        }
    };
    println!("ok: {} rule(s)", rules.rules.len());
    for r in &rules.rules {
        println!(
            "  line {:>3}: {:?}  tokens={}  slots={}",
            r.line_no,
            r.exe,
            r.tokens.len(),
            r.tokens
                .iter()
                .filter(|t| matches!(t, TokenPattern::Slot(_)))
                .count()
        );
    }
    for r in &rules.rules {
        for slot in r.slots() {
            let line = r.line_no;
            if r.allow_any.contains(slot) {
                println!("note: line {line}: slot {slot} accepts any value (allow_any)");
            } else if r.allow_dash.contains(slot) {
                println!("note: line {line}: slot {slot} accepts option-like values (allow_dash)");
            } else if r
                .slot_regex
                .get(slot)
                .is_some_and(rules::requires_leading_dash)
            {
                println!(
                    "warning: line {line}: slot {slot} only matches values starting with '-', \
                     which are refused unless it is listed in allow_dash"
                );
            }
        }
    }
    true
}

fn match_cmd(path: &Path, argv: &[String]) -> ExitCode {
    let rules = match read_rules(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sluice: {e}");
            return ExitCode::from(1);
        }
    };
    match rules.check_argv(argv) {
        Ok(m) => {
            println!("match: rule at line {}", m.rule.line_no);
            for (k, v) in &m.bindings {
                println!("  {k} = {v:?}");
            }
            ExitCode::SUCCESS
        }
        Err(Miss::NoRule) => {
            eprintln!("no match");
            ExitCode::from(1)
        }
        Err(Miss::OptionLike { line, slot }) => {
            eprintln!(
                "no match: rule at line {line} refuses slot {slot}: value starts with '-' \
                 (list the slot in allow_dash to accept option-like values)"
            );
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

/// The `<name>.rules` files of a rules directory, by name, and what was
/// refused. A dotfile is skipped without a word, since editors leave them;
/// a name that cannot name a socket directory is refused.
struct Found {
    files: BTreeMap<String, PathBuf>,
    refused: Vec<String>,
}

fn rules_files(dir: &Path) -> Result<Found, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut found = Found {
        files: BTreeMap::new(),
        refused: Vec::new(),
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(name) = file.strip_suffix(".rules") else {
            continue;
        };
        if file.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            found.refused.push(format!(
                "{}: a socket directory cannot be named {name:?}; use letters, digits, '.', '-' and '_'",
                path.display()
            ));
            continue;
        }
        found.files.insert(name.to_string(), path);
    }
    Ok(found)
}

/// What tells a rules file changed: replacing it, as editors do, changes
/// the inode, and writing it in place the time or the length.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
    ino: u64,
}

impl Stamp {
    fn of(path: &Path) -> Option<Stamp> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Stamp {
            modified: meta.modified().ok(),
            len: meta.len(),
            ino: meta.ino(),
        })
    }
}

/// What every socket of one broker shares: the audit sinks, the cap on
/// calls at once, and the call counter, so that call ids stay unique
/// across sockets writing to one manifest.
struct Shared {
    sinks: Arc<SinkCache>,
    active: Arc<AtomicUsize>,
    calls: Arc<AtomicU64>,
}

impl Shared {
    fn new() -> Self {
        Shared {
            sinks: Arc::new(SinkCache::default()),
            active: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(AtomicU64::new(1)),
        }
    }
}

/// One rules file served on one socket: its rules, swapped whole on
/// reload, and the thread accepting on it. In-flight calls keep the rules
/// they started with.
struct Served {
    rules_path: PathBuf,
    sock_path: PathBuf,
    state: Arc<Mutex<Arc<LiveState>>>,
    sinks: Arc<SinkCache>,
    stop: Arc<AtomicBool>,
    accepting: std::thread::JoinHandle<()>,
}

impl Served {
    fn start(rules_path: &Path, sock_path: &Path, shared: &Shared) -> Result<Served, String> {
        let (state, manifest_path) = open_state(rules_path)?;
        if let Some(p) = &manifest_path {
            eprintln!("sluice: manifest = {}", p.display());
        }
        check_socket_parent(sock_path, state.rules.defaults.audit)?;

        if let Ok(meta) = std::fs::symlink_metadata(sock_path) {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_socket() {
                ensure_socket_stale(sock_path)?;
                std::fs::remove_file(sock_path)
                    .map_err(|e| format!("cannot remove stale socket: {e}"))?;
            } else {
                return Err(format!(
                    "{} exists and is not a socket — refusing to overwrite",
                    sock_path.display()
                ));
            }
        }

        let listener = listen_at(sock_path)?;
        eprintln!(
            "sluice: serving {} rules at {} (max {} concurrent)",
            state.rules.rules.len(),
            sock_path.display(),
            MAX_ACTIVE
        );

        let state = Arc::new(Mutex::new(state));
        let stop = Arc::new(AtomicBool::new(false));
        let accepting = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            let sinks = Arc::clone(&shared.sinks);
            let active = Arc::clone(&shared.active);
            let calls = Arc::clone(&shared.calls);
            std::thread::Builder::new()
                .spawn(move || accept_loop(listener, state, sinks, active, calls, stop))
                .map_err(|e| format!("cannot accept on {}: {e}", sock_path.display()))?
        };
        Ok(Served {
            rules_path: rules_path.to_path_buf(),
            sock_path: sock_path.to_path_buf(),
            state,
            sinks: Arc::clone(&shared.sinks),
            stop,
            accepting,
        })
    }

    fn reload(&self) {
        match open_state(&self.rules_path) {
            Ok((new_state, _)) => {
                *self.state.lock().unwrap() = new_state;
                self.sinks.clear();
                eprintln!("sluice: reloaded {}", self.rules_path.display());
            }
            Err(e) => {
                eprintln!(
                    "sluice: reload of {} failed: {e} — keeping its old rules",
                    self.rules_path.display()
                );
            }
        }
    }

    /// Stops accepting and removes the socket. Calls already running
    /// finish on their own threads.
    fn close(self) {
        self.stop.store(true, Ordering::SeqCst);
        // accept4 waits without a timeout: a connection of our own is what
        // wakes it to see `stop`.
        let woke = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .ok()
        .zip(UnixAddr::new(&self.sock_path).ok())
        .is_some_and(|(probe, addr)| connect(probe.as_raw_fd(), &addr).is_ok());
        if woke {
            let _ = self.accepting.join();
        } else {
            eprintln!(
                "sluice: cannot reach {} to stop accepting on it; its thread is left waiting",
                self.sock_path.display()
            );
        }
        if let Err(e) = std::fs::remove_file(&self.sock_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("sluice: cannot remove {}: {e}", self.sock_path.display());
            }
        }
    }
}

/// Binds under umask 077, so the socket file is the broker's alone.
fn listen_at(sock_path: &Path) -> Result<OwnedFd, String> {
    let prev_umask = unsafe { nix::libc::umask(0o077) };
    let listening = bind_and_listen(sock_path);
    unsafe { nix::libc::umask(prev_umask) };
    listening
}

fn bind_and_listen(sock_path: &Path) -> Result<OwnedFd, String> {
    let listener: OwnedFd = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| format!("socket(): {e}"))?;
    let addr = UnixAddr::new(sock_path)
        .map_err(|e| format!("{} cannot be a socket address: {e}", sock_path.display()))?;
    bind(listener.as_raw_fd(), &addr).map_err(|e| format!("bind(): {e}"))?;
    listen(&listener, Backlog::new(64).unwrap()).map_err(|e| format!("listen(): {e}"))?;
    Ok(listener)
}

fn accept_loop(
    listener: OwnedFd,
    state: Arc<Mutex<Arc<LiveState>>>,
    sinks: Arc<SinkCache>,
    active: Arc<AtomicUsize>,
    calls: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
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
        if stop.load(Ordering::SeqCst) {
            return;
        }

        // Receive deadline: a connected client that doesn't send within
        // RECV_TIMEOUT_SECS holds a slot only that long, then `recvmsg`
        // returns EAGAIN and we close. Without this, an authorized but
        // misbehaving caller can hold MAX_ACTIVE slots forever.
        let tv = TimeVal::new(RECV_TIMEOUT_SECS, 0);
        let _ = setsockopt(&conn, sockopt::ReceiveTimeout, &tv);

        let Some(slot) = ActiveSlot::acquire(&active) else {
            eprintln!("sluice: at cap ({MAX_ACTIVE}), rejecting connection");
            drop(conn);
            continue;
        };

        // Snapshot the current LiveState. In-flight calls keep their
        // snapshot across a SIGHUP; new calls see the fresh state.
        let snap = state.lock().unwrap().clone();
        let sk = Arc::clone(&sinks);
        let cc = Arc::clone(&calls);
        let spawned = std::thread::Builder::new().spawn(move || {
            let _slot = slot;
            handle_conn(conn, snap, sk, cc);
        });
        if let Err(e) = spawned {
            eprintln!("sluice: cannot spawn connection thread: {e}");
        }
    }
}

/// Blocks SIGHUP in this thread and in every thread it starts afterwards,
/// so that only the main thread's wait sees it.
fn block_sighup() -> Result<SigSet, String> {
    let mut set = SigSet::empty();
    set.add(Signal::SIGHUP);
    nix::sys::signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), None)
        .map_err(|e| format!("sigprocmask: {e}"))?;
    Ok(set)
}

fn hup_within(set: &SigSet, timeout: Duration) -> bool {
    let ts = nix::libc::timespec {
        tv_sec: timeout.as_secs() as _,
        tv_nsec: timeout.subsec_nanos() as _,
    };
    unsafe { nix::libc::sigtimedwait(set.as_ref(), std::ptr::null_mut(), &ts) == nix::libc::SIGHUP }
}

fn serve(rules_path: &Path, sock_path: &Path) -> Result<(), String> {
    let hup = block_sighup()?;
    let served = Served::start(rules_path, sock_path, &Shared::new())?;
    loop {
        if let Ok(Signal::SIGHUP) = hup.wait() {
            eprintln!("sluice: SIGHUP — reloading rules");
            served.reload();
        }
    }
}

const RESCAN: Duration = Duration::from_secs(1);

fn serve_dir(rules_dir: &Path, socket_dir: &Path) -> Result<(), String> {
    let hup = block_sighup()?;
    make_socket_dir(socket_dir)?;
    rules_files(rules_dir)?;
    eprintln!(
        "sluice: serving each <name>.rules in {} at {}/<name>/sluice.sock",
        rules_dir.display(),
        socket_dir.display()
    );
    let mut dir = DirServed {
        rules_dir: rules_dir.to_path_buf(),
        socket_dir: socket_dir.to_path_buf(),
        shared: Shared::new(),
        served: BTreeMap::new(),
        failed: BTreeMap::new(),
        said: HashSet::new(),
    };
    let mut reload_all = false;
    loop {
        dir.sync(reload_all);
        reload_all = hup_within(&hup, RESCAN);
        if reload_all {
            eprintln!("sluice: SIGHUP — reloading every rules file");
        }
    }
}

/// A rules directory served one socket per file, kept in step with the
/// directory: a file added is served, a file changed is reloaded, and a
/// file removed has its socket closed.
struct DirServed {
    rules_dir: PathBuf,
    socket_dir: PathBuf,
    shared: Shared,
    served: BTreeMap<String, (Stamp, Served)>,
    /// A file that could not be served, as it was then: it is tried again
    /// once it changes, or on SIGHUP.
    failed: BTreeMap<String, Stamp>,
    /// What was already said about the directory, so a rescan does not
    /// say it again.
    said: HashSet<String>,
}

impl DirServed {
    fn sync(&mut self, reload_all: bool) {
        let found = match rules_files(&self.rules_dir) {
            Ok(found) => found,
            Err(e) => return self.say(e),
        };
        for why in found.refused {
            self.say(why);
        }

        let gone: Vec<String> = self
            .served
            .keys()
            .filter(|name| !found.files.contains_key(*name))
            .cloned()
            .collect();
        for name in gone {
            if let Some((_, served)) = self.served.remove(&name) {
                served.close();
            }
            let dir = self.socket_dir.join(&name);
            if let Err(e) = std::fs::remove_dir(&dir) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("sluice: cannot remove {}: {e}", dir.display());
                }
            }
            eprintln!("sluice: {name}.rules is gone — its socket is closed");
        }
        self.failed.retain(|name, _| found.files.contains_key(name));

        for (name, path) in &found.files {
            let Some(stamp) = Stamp::of(path) else {
                continue;
            };
            if let Some((was, served)) = self.served.get_mut(name) {
                if reload_all || *was != stamp {
                    served.reload();
                    *was = stamp;
                }
                continue;
            }
            if !reload_all && self.failed.get(name) == Some(&stamp) {
                continue;
            }
            match self.start(name, path) {
                Ok(served) => {
                    self.failed.remove(name);
                    self.served.insert(name.clone(), (stamp, served));
                }
                Err(e) => {
                    eprintln!("sluice: {name}: {e} — not served");
                    self.failed.insert(name.clone(), stamp);
                }
            }
        }
    }

    /// A socket directory exists only while its file is served, so a
    /// caller never finds one with nothing in it.
    fn start(&self, name: &str, rules_path: &Path) -> Result<Served, String> {
        let dir = self.socket_dir.join(name);
        make_socket_dir(&dir)?;
        Served::start(rules_path, &dir.join("sluice.sock"), &self.shared).inspect_err(|_| {
            let _ = std::fs::remove_dir(&dir);
        })
    }

    fn say(&mut self, what: String) {
        if self.said.insert(what.clone()) {
            eprintln!("sluice: {what}");
        }
    }
}

/// Makes `dir`, and what leads to it, at mode 0700 when missing, and
/// refuses one that is not this uid's directory or that another uid can
/// write: whoever can write it can replace a socket in it.
fn make_socket_dir(dir: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("cannot stat {}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} must be a directory of yours that no other user can write (it is mode {:04o}, uid {})",
            dir.display(),
            meta.mode() & 0o7777,
            meta.uid()
        ));
    }
    Ok(())
}

/// Held for the life of a connection thread; released on drop, so a
/// panicking handler or a failed thread spawn still frees the slot.
struct ActiveSlot(Arc<AtomicUsize>);

impl ActiveSlot {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_ACTIVE {
            active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ActiveSlot(Arc::clone(active)))
    }
}

impl Drop for ActiveSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A socket file nobody listens on refuses connections; anything else
/// means a live broker (or an unknown state) we must not unlink.
fn ensure_socket_stale(sock_path: &Path) -> Result<(), String> {
    let probe = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| format!("socket(): {e}"))?;
    let addr = UnixAddr::new(sock_path).map_err(|e| format!("UnixAddr: {e}"))?;
    match connect(probe.as_raw_fd(), &addr) {
        Err(nix::errno::Errno::ECONNREFUSED) => Ok(()),
        Ok(()) => Err(format!(
            "another broker is listening at {} — refusing to take it over",
            sock_path.display()
        )),
        Err(e) => Err(format!(
            "cannot tell whether {} is stale (connect: {e}) — refusing to remove it",
            sock_path.display()
        )),
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
        Ok((Request::List, _)) => return send_listing(&conn, rules),
        Ok((Request::Call { argv }, fds)) => match fds {
            None => {
                if let Some(l) = manifest {
                    let logged: &[String] = if reject_log_argv { &argv } else { &[] };
                    l.reject(next_call(), "wrong_fd_count", logged);
                } else if reject_log_argv {
                    eprintln!("sluice: rejected (wrong fd count) argv={argv:?}");
                } else {
                    eprintln!("sluice: rejected (wrong fd count)");
                }
                ERR_FDS
            }
            Some(stdio) => match rules.check_argv(&argv) {
                Err(miss) => {
                    let reason = match &miss {
                        Miss::NoRule => "no_rule".to_string(),
                        Miss::OptionLike { line, slot } => {
                            format!("option_like: rule at line {line}, slot {slot}")
                        }
                    };
                    if let Some(l) = manifest {
                        let logged: &[String] = if reject_log_argv { &argv } else { &[] };
                        l.reject(next_call(), &reason, logged);
                    } else if reject_log_argv {
                        eprintln!("sluice: rejected ({reason}) argv={argv:?}");
                    } else {
                        eprintln!("sluice: rejected ({reason}, argv suppressed)");
                    }
                    ERR_NO_RULE
                }
                Ok(m) => {
                    return dispatch(m.rule, &snap, &argv, stdio, &conn, &sinks, &call_counter)
                }
            },
        },
        Err(()) => ERR_PROTO,
    };
    send_reply(&conn, status);
}

fn send_listing(conn: &OwnedFd, rules: &Rules) {
    let Some(reply) = encode_listing(&rules.listing()) else {
        eprintln!("sluice: listing refused: longer than {MAX_LISTING} bytes");
        return send_reply(conn, ERR_TOO_LARGE);
    };
    let _ = sendmsg::<UnixAddr>(
        conn.as_raw_fd(),
        &[IoSlice::new(&reply)],
        &[],
        MsgFlags::empty(),
        None,
    );
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
    argv: &[String],
    stdio: [OwnedFd; 3],
    conn: &OwnedFd,
    sinks: &Arc<SinkCache>,
    call_counter: &Arc<AtomicU64>,
) {
    let rules: &Rules = &snap.rules;
    let manifest = &snap.manifest;
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

    let refuse = |reason: &str, status: i32| {
        if let Some(l) = manifest {
            let logged: &[String] = if log_argv { argv } else { &[] };
            let call = CallId(call_counter.fetch_add(1, Ordering::SeqCst));
            l.reject(call, reason, logged);
        }
        send_reply(conn, status);
    };

    let peer = match peer_of(conn) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sluice: refusing call: SO_PEERCRED failed: {e}");
            return refuse("peer_unknown", ERR_PEER);
        }
    };
    let peer_pid = peer.pid;
    let peer_uid = peer.uid;

    // Resolved in the parent against the rule's exec_path, so `execve`
    // gets an absolute path the caller's PATH can't redirect.
    let Some(exe) = resolve_exe(rule, rules) else {
        eprintln!(
            "sluice: cannot resolve executable for rule at line {} (exec_path miss)",
            rule.line_no
        );
        return refuse("exe_unresolved", ERR_SPAWN);
    };

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
            let logged: &[String] = if log_argv { argv } else { &[] };
            l.reject(call, &format!("audit_unwritable: {reason}"), logged);
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
                &StartEvent {
                    pid: peer_pid,
                    line: rule.line_no,
                    argv,
                    resolved: &exe,
                    stdout: stdout_path.as_deref(),
                    stderr: stderr_path.as_deref(),
                },
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
            rule.line_no, peer_pid, argv
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
    let SpawnOutcome {
        status,
        signal,
        timed_out,
        drain,
    } = run_matched(rule, rules, argv, &exe, stdio, ctx);
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
                signal,
                timed_out,
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
    let truncated = msg.flags.contains(MsgFlags::MSG_TRUNC);

    let mut fds: Vec<OwnedFd> = Vec::new();
    for c in msg.cmsgs().map_err(|_| ())? {
        if let ControlMessageOwned::ScmRights(rfds) = c {
            fds.extend(
                rfds.into_iter()
                    .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
            );
        }
    }

    if truncated {
        return Err(());
    }
    let req = decode_request(&buf[..n]).map_err(|_| ())?;
    let stdio = <[OwnedFd; 3]>::try_from(fds).ok();
    Ok((req, stdio))
}

const SCM_MAX_FD: usize = 253;
