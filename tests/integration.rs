//! End-to-end integration tests.
//!
//! Each test spawns `sluice serve` as a real subprocess in a 0700
//! tempdir, exercises a runtime path the unit tests can't reach, then
//! kills the broker and cleans up.

use nix::sys::socket;
use sluicify::proto::{ERR_FDS, ERR_PROTO, MAGIC, VERSION};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, RawFd};
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
        let rules_text = rules_text_template.replace("$DIR", dir.to_string_lossy().as_ref());
        let rules_path = dir.join("rules");
        std::fs::write(&rules_path, rules_text).unwrap();
        let socket = dir.join("sock");
        let mut child = Command::new(SLUICE_BIN)
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
        let _ = child.kill();
        let _ = child.wait();
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
         echo #1\n  1 = ^[a-z_]+$\n",
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
         echo #1\n  1 = ^[a-z_]+$\n",
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
         /bin/sh -c #1\n  allow_any = 1\n  timeout = 1s\n",
    );
    let marker = broker.dir.join("gc.pid");
    let cmd = format!("sleep 30 & echo $! > {} ; wait", marker.display());
    let (code, _, stderr) = broker.call(&["/bin/sh", "-c", &cmd]);
    assert_eq!(code, 124, "timeout exits 124; stderr: {stderr}");
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
    let _ = Command::new("kill")
        .arg("-9")
        .arg(gc_pid.to_string())
        .status();
    panic!("grandchild pid {gc_pid} survived timeout");
}

fn raw_request(path: &std::path::Path, payload: &[u8], fds: &[RawFd]) -> i32 {
    let sock = socket::socket(
        socket::AddressFamily::Unix,
        socket::SockType::SeqPacket,
        socket::SockFlag::SOCK_CLOEXEC,
        None,
    )
    .unwrap();
    socket::connect(sock.as_raw_fd(), &socket::UnixAddr::new(path).unwrap()).unwrap();
    let cmsg = [socket::ControlMessage::ScmRights(fds)];
    socket::sendmsg::<socket::UnixAddr>(
        sock.as_raw_fd(),
        &[IoSlice::new(payload)],
        &cmsg,
        socket::MsgFlags::empty(),
        None,
    )
    .unwrap();
    let mut reply = [0u8; 12];
    let mut iov = [IoSliceMut::new(&mut reply)];
    let msg = socket::recvmsg::<socket::UnixAddr>(
        sock.as_raw_fd(),
        &mut iov,
        None,
        socket::MsgFlags::empty(),
    )
    .unwrap();
    assert_eq!(msg.bytes, 12);
    i32::from_le_bytes(reply[8..12].try_into().unwrap())
}

fn encode(argv: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(argv.len() as u32).to_le_bytes());
    for a in argv {
        out.extend_from_slice(&(a.len() as u32).to_le_bytes());
        out.extend_from_slice(a.as_bytes());
    }
    out
}

fn open_fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .count()
}

#[test]
fn rejected_requests_do_not_leak_passed_fds() {
    let broker = Broker::start("defaults:\n  audit = best-effort\n\necho #1\n  1 = ^[a-z_]+$\n");
    let pid = broker.child.id();
    let before = open_fd_count(pid);

    let mut bad_magic = encode(&["echo", "x"]);
    bad_magic[0] ^= 0xff;
    let valid = encode(&["echo", "x"]);
    for _ in 0..20 {
        assert_eq!(
            raw_request(&broker.socket, &bad_magic, &[0, 1, 2]),
            ERR_PROTO
        );
        assert_eq!(
            raw_request(&broker.socket, &valid, &[0, 1, 2, 0, 1]),
            ERR_FDS
        );
    }

    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(open_fd_count(pid), before);
}

#[test]
fn child_starts_with_default_signal_state() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  env = PATH\n  exec_path = inherit\n\n\
         /bin/sh -c #1\n  allow_any = 1\n",
    );
    let (code, stdout, _) = broker.call(&[
        "/bin/sh",
        "-c",
        "exec grep -E '^Sig(Blk|Ign):' /proc/self/status",
    ]);
    assert_eq!(code, 0);
    let field = |name: &str| -> u64 {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("{name} missing in {stdout:?}"));
        u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
    };
    assert_eq!(field("SigBlk:"), 0, "child inherited a blocked signal mask");
    let sigpipe_bit = 1u64 << (nix::libc::SIGPIPE - 1);
    assert_eq!(
        field("SigIgn:") & sigpipe_bit,
        0,
        "child inherited SIGPIPE ignored"
    );
}

const TEE_RULES: &str = "defaults:\n  audit = best-effort\n  env = PATH\n  exec_path = inherit\n\
     \x20\x20logfile = $DIR/manifest.jsonl\n\n\
     /bin/sh -c #1\n  allow_any = 1\n  stdoutfile = $DIR/c#$call.out\n";

fn call_timed(broker: &Broker, argv: &[&str]) -> (i32, Duration) {
    let caller_out = std::fs::File::create(broker.dir.join("caller.out")).unwrap();
    let started = Instant::now();
    let status = Command::new(SLUICIFY_BIN)
        .arg(&broker.socket)
        .args(argv)
        .stdout(caller_out)
        .status()
        .expect("run sluicify");
    (status.code().unwrap_or(-1), started.elapsed())
}

fn wait_for_exit_event(broker: &Broker, within: Duration) -> String {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(line) = broker.manifest().and_then(|m| {
            m.lines()
                .find(|l| l.contains("\"kind\":\"exit\""))
                .map(String::from)
        }) {
            return line;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no exit event within {within:?}: {:?}", broker.manifest());
}

#[test]
fn tee_mode_replies_when_direct_child_exits() {
    let broker = Broker::start(TEE_RULES);
    let (code, took) = call_timed(&broker, &["/bin/sh", "-c", "echo hi; sleep 2 &"]);
    assert_eq!(code, 0);
    assert!(
        took < Duration::from_millis(1500),
        "reply waited for the background sleep: {took:?}"
    );

    let exit = wait_for_exit_event(&broker, Duration::from_secs(5));
    assert!(exit.contains("\"stdout_bytes\":3"), "{exit}");
    assert!(!exit.contains("drain_timeout"), "{exit}");
    assert_eq!(std::fs::read(broker.dir.join("c1.out")).unwrap(), b"hi\n");
    assert_eq!(
        std::fs::read(broker.dir.join("caller.out")).unwrap(),
        b"hi\n"
    );
}

#[test]
fn tee_drain_is_cut_at_timeout_plus_grace() {
    let broker = Broker::start(&TEE_RULES.replace(
        "stdoutfile = $DIR/c#$call.out\n",
        "stdoutfile = $DIR/c#$call.out\n  timeout = 1s\n",
    ));
    let (code, took) = call_timed(&broker, &["/bin/sh", "-c", "echo hi; sleep 6 &"]);
    assert_eq!(code, 0);
    assert!(took < Duration::from_millis(1500), "{took:?}");

    let exit = wait_for_exit_event(&broker, Duration::from_secs(5));
    assert!(exit.contains("\"drain_timeout\":true"), "{exit}");
    assert!(exit.contains("\"stdout_bytes\":3"), "{exit}");
}

#[test]
fn signal_death_exits_128_plus_signo() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  env = PATH\n  exec_path = inherit\n\
         \x20\x20logfile = $DIR/manifest.jsonl\n\n\
         /bin/sh -c #1\n  allow_any = 1\n",
    );
    let (code, _, _) = broker.call(&["/bin/sh", "-c", "kill -KILL $$"]);
    assert_eq!(code, 137);
    let exit = wait_for_exit_event(&broker, Duration::from_secs(2));
    assert!(exit.contains("\"status\":137"), "{exit}");
    assert!(exit.contains("\"signal\":9"), "{exit}");
    assert!(!exit.contains("timed_out"), "{exit}");
}

#[test]
fn timeout_is_recorded_in_manifest() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  env = PATH\n  exec_path = inherit\n\
         \x20\x20logfile = $DIR/manifest.jsonl\n\n\
         /bin/sh -c #1\n  allow_any = 1\n  timeout = 300ms\n",
    );
    let (code, _, _) = broker.call(&["/bin/sh", "-c", "exec sleep 30"]);
    assert_eq!(code, 124);
    let exit = wait_for_exit_event(&broker, Duration::from_secs(2));
    assert!(exit.contains("\"timed_out\":true"), "{exit}");
    assert!(exit.contains("\"signal\":15"), "{exit}");
}

#[test]
fn start_event_records_resolved_binary() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  logfile = $DIR/manifest.jsonl\n\n\
         echo #1\n  1 = ^[a-z]+$\n",
    );
    let (code, _, _) = broker.call(&["/tmp/anything/echo", "hi"]);
    assert_eq!(code, 0);
    let manifest = broker.manifest().expect("manifest");
    let start = manifest
        .lines()
        .find(|l| l.contains("\"kind\":\"start\""))
        .expect("start event");
    assert!(
        start.contains("\"argv\":[\"/tmp/anything/echo\""),
        "{start}"
    );
    assert!(
        start.contains("\"resolved\":\"/bin/echo\"")
            || start.contains("\"resolved\":\"/usr/bin/echo\""),
        "{start}"
    );
}

#[test]
fn second_broker_refuses_live_socket() {
    let broker = Broker::start("defaults:\n  audit = best-effort\n\necho #1\n  1 = ^[a-z]+$\n");
    let out = Command::new(SLUICE_BIN)
        .arg("serve")
        .arg("--rules")
        .arg(broker.dir.join("rules"))
        .arg("--socket")
        .arg(&broker.socket)
        .output()
        .expect("run second sluice");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("another broker is listening"), "{stderr}");
    let (code, stdout, _) = broker.call(&["echo", "alive"]);
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "alive");
}

#[test]
fn option_like_value_rejected_with_reason() {
    let broker = Broker::start(
        "defaults:\n  audit = best-effort\n  logfile = $DIR/manifest.jsonl\n\n\
         echo #1\n  1 = ^[a-z=-]+$\n",
    );
    let (code, _, stderr) = broker.call(&["echo", "--output=x"]);
    assert_eq!(code, 129, "{stderr}");
    let manifest = broker.manifest().expect("manifest");
    assert!(
        manifest.contains("\"reason\":\"option_like: rule at line 5, slot #1\""),
        "{manifest}"
    );
    let (code, stdout, _) = broker.call(&["echo", "plain"]);
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "plain");
}
