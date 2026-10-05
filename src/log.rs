//! JSON-Lines audit log of *events only* — start, exit, reject.
//!
//! Stdio bytes are captured to separate raw files (see `stdoutfile` /
//! `stderrfile` in rules), not inline. Manifest events reference those
//! files by resolved path.
//!
//! ```jsonl
//! {"call":1,"ts":...,"kind":"start","pid":6210,"line":4,"argv":["echo","hi"],
//!  "resolved":"/usr/bin/echo",
//!  "stdout":"~/.local/state/sluice/c1.out","stderr":"~/.local/state/sluice/c1.err"}
//! {"call":1,"ts":...,"kind":"exit","status":0,"duration_ms":2,
//!  "stdout_bytes":6,"stderr_bytes":0}
//! {"call":2,"ts":...,"kind":"reject","reason":"no_rule","argv":["cat","/etc/passwd"]}
//! {"call":3,"ts":...,"kind":"exit","status":0,"duration_ms":42,
//!  "stdout_bytes":1024,"stderr_bytes":0,"truncated":true}
//! {"call":4,"ts":...,"kind":"exit","status":-7,"signal":15,"timed_out":true,
//!  "duration_ms":30000,"stdout_bytes":0,"stderr_bytes":0}
//! ```
//!
//! `ts` is unix-epoch milliseconds.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Copy, Clone)]
pub struct CallId(pub u64);

pub struct StartEvent<'a> {
    pub pid: i32,
    pub line: usize,
    pub argv: &'a [String],
    /// The binary actually executed; argv[0] is only what the caller sent.
    pub resolved: &'a Path,
    pub stdout: Option<&'a Path>,
    pub stderr: Option<&'a Path>,
}

pub struct ExitEvent {
    /// Wire status sent to the caller.
    pub status: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    /// Until the direct child exited; output drain afterwards excluded.
    pub duration_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    /// At least one stdio sink lost bytes (the child wrote more than
    /// landed on disk).
    pub truncated: bool,
    /// Output capture stopped at the rule's timeout plus kill grace
    /// while a descendant still held stdout or stderr open.
    pub drain_timeout: bool,
}

pub struct Logger {
    file: Mutex<File>,
    /// Cleared on first write/flush failure; never auto-recovers.
    /// Reload (SIGHUP) creates a fresh Logger which resets it.
    healthy: AtomicBool,
}

impl Logger {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = open_audit_file(path)?;
        Ok(Logger {
            file: Mutex::new(file),
            healthy: AtomicBool::new(true),
        })
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    /// Mark the manifest unhealthy from outside (e.g. a sink write
    /// failed during a call). Symmetric with what `append_line` does
    /// internally on its own write failures.
    pub fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::SeqCst);
    }

    /// Returns true if the start event was successfully written. Under
    /// strict audit, callers refuse to spawn the child when this is
    /// false — silently spawning past a failed start is exactly the
    /// audit-gap case strict mode exists to prevent.
    pub fn start(&self, call: CallId, e: &StartEvent) -> bool {
        let mut s = String::with_capacity(160);
        s.push('{');
        emit_meta(&mut s, call, "start");
        write!(s, ",\"pid\":{},\"line\":{},\"argv\":", e.pid, e.line).unwrap();
        emit_argv(&mut s, e.argv);
        s.push_str(",\"resolved\":");
        emit_path(&mut s, e.resolved);
        if let Some(p) = e.stdout {
            s.push_str(",\"stdout\":");
            emit_path(&mut s, p);
        }
        if let Some(p) = e.stderr {
            s.push_str(",\"stderr\":");
            emit_path(&mut s, p);
        }
        s.push('}');
        self.append_line(&s)
    }

    /// `signal`, `timed_out`, `truncated` and `drain_timeout` are
    /// emitted only when set —
    /// common successful calls keep the line shorter and JSONL
    /// consumers can `select(.truncated)` to find audit gaps without a
    /// numeric comparison.
    pub fn exit(&self, call: CallId, e: &ExitEvent) {
        let mut s = String::with_capacity(96);
        s.push('{');
        emit_meta(&mut s, call, "exit");
        write!(
            s,
            ",\"status\":{},\"duration_ms\":{}\
             ,\"stdout_bytes\":{},\"stderr_bytes\":{}",
            e.status, e.duration_ms, e.stdout_bytes, e.stderr_bytes
        )
        .unwrap();
        if let Some(sig) = e.signal {
            write!(s, ",\"signal\":{sig}").unwrap();
        }
        if e.timed_out {
            s.push_str(",\"timed_out\":true");
        }
        if e.truncated {
            s.push_str(",\"truncated\":true");
        }
        if e.drain_timeout {
            s.push_str(",\"drain_timeout\":true");
        }
        s.push('}');
        let _ = self.append_line(&s);
    }

    pub fn reject(&self, call: CallId, reason: &str, argv: &[String]) {
        let mut s = String::with_capacity(96);
        s.push('{');
        emit_meta(&mut s, call, "reject");
        s.push_str(",\"reason\":");
        emit_string(&mut s, reason);
        s.push_str(",\"argv\":");
        emit_argv(&mut s, argv);
        s.push('}');
        let _ = self.append_line(&s);
    }

    fn append_line(&self, line: &str) -> bool {
        let mut f = match self.file.lock() {
            Ok(g) => g,
            Err(_) => {
                self.healthy.store(false, Ordering::SeqCst);
                return false;
            }
        };
        if let Err(e) = writeln!(f, "{line}") {
            eprintln!("sluice: AUDIT WRITE FAILED: {e}");
            self.healthy.store(false, Ordering::SeqCst);
            return false;
        }
        if let Err(e) = f.flush() {
            eprintln!("sluice: AUDIT FLUSH FAILED: {e}");
            self.healthy.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }
}

use std::fmt::Write as _;

fn emit_meta(s: &mut String, call: CallId, kind: &str) {
    write!(
        s,
        "\"call\":{},\"ts\":{},\"kind\":\"{}\"",
        call.0,
        now_ms(),
        kind
    )
    .unwrap();
}

fn emit_argv(s: &mut String, argv: &[String]) {
    s.push('[');
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        emit_string(s, a);
    }
    s.push(']');
}

fn emit_path(s: &mut String, p: &Path) {
    emit_string(s, &p.to_string_lossy());
}

fn emit_string(s: &mut String, v: &str) {
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            '\x08' => s.push_str("\\b"),
            '\x0c' => s.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                write!(s, "\\u{:04x}", c as u32).unwrap();
            }
            c => s.push(c),
        }
    }
    s.push('"');
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Open a raw byte sink (stdoutfile / stderrfile target).
///
/// Same hardening as the manifest: mode 0600 at create, `O_NOFOLLOW`
/// (a symlink at the path is rejected), parent dir created with mode
/// 0700 if missing, and refusal if the parent is writable by anyone
/// other than the broker uid.
pub fn open_raw(path: &Path) -> io::Result<File> {
    open_audit_file(path)
}

/// Shared implementation for manifest + sink files.
fn open_audit_file(path: &Path) -> io::Result<File> {
    ensure_safe_audit_parent(path)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
}

/// Create the parent dir with mode 0700 if missing, then verify it
/// isn't writable by anyone other than us. The check protects audit
/// files from the same rm/replace and TOCTOU vectors as the socket
/// parent check, but is unconditional (audit data isn't optional).
fn ensure_safe_audit_parent(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;

    let meta = std::fs::metadata(parent)?;
    let mode = meta.mode() & 0o7777;
    let owner = meta.uid();
    let our_uid = nix::unistd::geteuid().as_raw();
    let group_w = mode & 0o020 != 0;
    let world_w = mode & 0o002 != 0;
    if owner != our_uid || group_w || world_w {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "audit parent {} is unsafe (uid={}, mode={:04o}); \
                 expect owned by uid {} with no group/world write",
                parent.display(),
                owner,
                mode,
                our_uid
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;

    /// Each test gets its own private 0700 subdir under `$TMPDIR`. The
    /// audit-parent check rejects anything not owner-only, so tests
    /// can't write directly into a world-writable `/tmp`.
    fn temp_path() -> PathBuf {
        let pid = std::process::id();
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sluice-log-test-{pid}-{n}"));
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&dir)
            .unwrap();
        dir.join("manifest.jsonl")
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_file(p);
        if let Some(parent) = p.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[test]
    fn start_exit_pair() {
        let p = temp_path();
        let logger = Logger::open(&p).unwrap();
        let c = CallId(1);
        let stdout_p = PathBuf::from("/tmp/c1.out");
        let stderr_p = PathBuf::from("/tmp/c1.err");
        logger.start(
            c,
            &StartEvent {
                pid: 1234,
                line: 5,
                argv: &["echo".into(), "hi".into()],
                resolved: Path::new("/usr/bin/echo"),
                stdout: Some(&stdout_p),
                stderr: Some(&stderr_p),
            },
        );
        logger.exit(c, &exit_event(0, 6, false, false));
        drop(logger);

        let mut s = String::new();
        File::open(&p).unwrap().read_to_string(&mut s).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"kind\":\"start\""));
        assert!(lines[0].contains("\"stdout\":\"/tmp/c1.out\""));
        assert!(lines[0].contains("\"argv\":[\"echo\",\"hi\"]"));
        assert!(lines[0].contains("\"resolved\":\"/usr/bin/echo\""));
        assert!(lines[1].contains("\"kind\":\"exit\""));
        assert!(lines[1].contains("\"status\":0"));
        assert!(lines[1].contains("\"stdout_bytes\":6"));
        cleanup(&p);
    }

    fn exit_event(
        status: i32,
        stdout_bytes: u64,
        truncated: bool,
        drain_timeout: bool,
    ) -> ExitEvent {
        ExitEvent {
            status,
            signal: None,
            timed_out: false,
            duration_ms: 7,
            stdout_bytes,
            stderr_bytes: 0,
            truncated,
            drain_timeout,
        }
    }

    #[test]
    fn exit_signal_and_timed_out_only_when_set() {
        let p = temp_path();
        let logger = Logger::open(&p).unwrap();
        logger.exit(CallId(1), &exit_event(0, 0, false, false));
        logger.exit(
            CallId(2),
            &ExitEvent {
                signal: Some(9),
                timed_out: true,
                ..exit_event(crate::proto::ERR_TIMEOUT, 0, false, false)
            },
        );
        drop(logger);
        let s = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert!(!lines[0].contains("signal") && !lines[0].contains("timed_out"));
        assert!(lines[1].contains("\"status\":-7"), "{}", lines[1]);
        assert!(lines[1].contains("\"signal\":9"), "{}", lines[1]);
        assert!(lines[1].contains("\"timed_out\":true"), "{}", lines[1]);
        cleanup(&p);
    }

    #[test]
    fn exit_drain_timeout_field_only_when_true() {
        let p = temp_path();
        let logger = Logger::open(&p).unwrap();
        logger.exit(CallId(1), &exit_event(0, 3, false, false));
        logger.exit(CallId(2), &exit_event(0, 3, false, true));
        drop(logger);
        let s = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert!(!lines[0].contains("drain_timeout"));
        assert!(lines[1].contains("\"drain_timeout\":true"));
        cleanup(&p);
    }

    #[test]
    fn reject_event() {
        let p = temp_path();
        let logger = Logger::open(&p).unwrap();
        let c = CallId(7);
        logger.reject(c, "no_rule", &["cat".into(), "/etc/passwd".into()]);
        drop(logger);
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("\"kind\":\"reject\""));
        assert!(s.contains("\"reason\":\"no_rule\""));
        cleanup(&p);
    }

    #[test]
    fn exit_truncated_field_only_when_true() {
        let p = temp_path();
        let logger = Logger::open(&p).unwrap();
        logger.exit(CallId(1), &exit_event(0, 100, false, false));
        logger.exit(CallId(2), &exit_event(0, 50, true, false));
        drop(logger);
        let s = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert!(!lines[0].contains("truncated"), "no truncated when false");
        assert!(
            lines[1].contains("\"truncated\":true"),
            "truncated:true when set"
        );
        cleanup(&p);
    }

    #[test]
    fn mark_unhealthy_flips_health_flag() {
        let p = temp_path();
        let logger = Logger::open(&p).unwrap();
        assert!(logger.is_healthy());
        logger.mark_unhealthy();
        assert!(!logger.is_healthy());
        // Idempotent — calling again stays unhealthy.
        logger.mark_unhealthy();
        assert!(!logger.is_healthy());
        cleanup(&p);
    }

    #[test]
    fn open_raw_creates_file_mode_0600() {
        let p = temp_path();
        let f = open_raw(&p).unwrap();
        drop(f);
        let mode = std::fs::metadata(&p).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "file should be 0600 regardless of umask");
        cleanup(&p);
    }

    #[test]
    fn open_raw_creates_missing_parent_at_0700() {
        let p = temp_path();
        let nested = p
            .parent()
            .unwrap()
            .join("deeper")
            .join("subdir")
            .join("audit");
        // Parent of nested doesn't exist yet — open_raw must mkdir it.
        let f = open_raw(&nested).unwrap();
        drop(f);
        let mode = std::fs::metadata(nested.parent().unwrap()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700, "created parent dir should be 0700");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn open_raw_rejects_symlink_at_path() {
        let p = temp_path();
        // Create a symlink at the audit path. With O_NOFOLLOW the open
        // must fail — even though the symlink target doesn't exist.
        std::os::unix::fs::symlink("/nonexistent-target-zzz", &p).unwrap();
        let err = open_raw(&p).unwrap_err();
        // ELOOP (40) on Linux for O_NOFOLLOW + symlink.
        assert_eq!(
            err.raw_os_error(),
            Some(nix::libc::ELOOP),
            "expected ELOOP, got {err:?}"
        );
        cleanup(&p);
    }

    #[test]
    fn open_raw_rejects_world_writable_parent() {
        let p = temp_path();
        // Loosen the parent that temp_path() created at 0700.
        std::fs::set_permissions(p.parent().unwrap(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let err = open_raw(&p).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        // Restore mode so cleanup succeeds.
        std::fs::set_permissions(p.parent().unwrap(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        cleanup(&p);
    }

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn json_escape_handles_quotes_and_controls() {
        let p = temp_path();
        let logger = Logger::open(&p).unwrap();
        let c = CallId(1);
        logger.reject(c, "x", &["a\"b\nc".into()]);
        drop(logger);
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("\"a\\\"b\\nc\""));
        cleanup(&p);
    }
}
