//! End-to-end integration tests.
//!
//! Each test spawns `sluice serve` as a real subprocess in a 0700
//! tempdir, exercises a runtime path the unit tests can't reach, then
//! kills the broker and cleans up.

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SLUICE_BIN: &str = env!("CARGO_BIN_EXE_sluice");
const SLUICIFY_BIN: &str = env!("CARGO_BIN_EXE_sluicify");

struct Broker {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
}

impl Broker {
    fn start(rules_text_template: &str) -> Self {
        let dir = tempdir_0700();
        // The harness substitutes $DIR for the tempdir absolute path so
        // tests can write paths into the rules text without juggling.
        let rules_text =
            rules_text_template.replace("$DIR", dir.to_string_lossy().as_ref());
        let rules_path = dir.join("rules");
        std::fs::write(&rules_path, rules_text).unwrap();
        let socket = dir.join("sock");
        let child = Command::new(SLUICE_BIN)
            .arg("serve")
            .arg("--rules")
            .arg(&rules_path)
            .arg("--socket")
            .arg(&socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sluice");
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if socket.exists() {
                return Broker { child, socket, dir };
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("broker didn't bind {} within 2s", socket.display());
    }

    fn call(&self, argv: &[&str]) -> (i32, String, String) {
        let out = Command::new(SLUICIFY_BIN)
            .arg(&self.socket)
            .args(argv)
            .output()
            .expect("run sluicify");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn manifest(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join("manifest.jsonl")).ok()
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tempdir_0700() -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("sluicify-it-{pid}-{nanos}"));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&p)
        .unwrap();
    p
}

fn pid_alive(pid: i32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

// --- tests ---------------------------------------------------------------

#[test]
fn happy_path_echo() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  env = HOME,LANG\n\n\
         echo #1\n  1 = ^[a-zA-Z0-9_]+$\n",
    );
    let (code, stdout, _) = broker.call(&["echo", "hello_world"]);
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "hello_world");
}

#[test]
fn unknown_command_rejected_with_129() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  env = HOME,LANG\n\n\
         echo #1\n",
    );
    let (code, _, _) = broker.call(&["cat", "/etc/passwd"]);
    assert_eq!(code, 129, "ERR_NO_RULE → 128 + 1 = 129");
}

#[test]
fn raw_sidecar_without_logfile_writes_bytes_verbatim() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  env = HOME,LANG\n\
         \x20\x20stdoutfile = $DIR/c#$call.out\n\n\
         echo #1\n  1 = ^[a-zA-Z0-9_]+$\n",
    );
    let (code, _, _) = broker.call(&["echo", "sidecar_only"]);
    assert_eq!(code, 0);
    let bytes = std::fs::read(broker.dir.join("c1.out")).expect("c1.out");
    assert_eq!(bytes, b"sidecar_only\n");
}

#[test]
fn exit_only_suppresses_argv_in_manifest() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  env = HOME,LANG\n\
         \x20\x20log = exit-only\n  logfile = $DIR/manifest.jsonl\n\n\
         echo #1\n",
    );
    let (code, _, _) = broker.call(&["echo", "secret_token_zzz"]);
    assert_eq!(code, 0);
    // Allow the broker a brief moment to flush the exit event.
    std::thread::sleep(Duration::from_millis(100));
    let manifest = broker.manifest().expect("manifest");
    assert!(
        !manifest.contains("\"kind\":\"start\""),
        "exit-only must not emit start events; got:\n{manifest}"
    );
    assert!(manifest.contains("\"kind\":\"exit\""));
    assert!(
        !manifest.contains("secret_token_zzz"),
        "argv leaked under exit-only; got:\n{manifest}"
    );
}

#[test]
fn timeout_kills_grandchild_in_process_group() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  env = HOME,LANG,PATH\n  exec_path = inherit\n\n\
         /bin/sh -c #1\n  timeout = 1s\n",
    );
    let marker = broker.dir.join("gc.pid");
    let cmd = format!("sleep 30 & echo $! > {} ; wait", marker.display());
    let _ = broker.call(&["/bin/sh", "-c", &cmd]);
    // After the call returns the timeout has fired and the broker has
    // started killing the group; give the kernel a moment.
    std::thread::sleep(Duration::from_millis(500));
    let gc_pid: i32 = std::fs::read_to_string(&marker)
        .expect("gc.pid")
        .trim()
        .parse()
        .expect("valid pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !pid_alive(gc_pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Best-effort cleanup before failing.
    let _ = Command::new("kill").arg("-9").arg(gc_pid.to_string()).status();
    panic!("grandchild pid {gc_pid} survived timeout");
}
