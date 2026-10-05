//! `sluicify` — companion client. Reads as a verb: "sluicify this
//! command". A 100-line binary that does the `sendmsg` + `SCM_RIGHTS`
//! dance so callers in languages without ancillary-data support (Node,
//! shell, etc.) can reach the broker via `spawn` with stdio inherited.
//!
//! Languages that *can* do `SCM_RIGHTS` directly (Python, C, Go, Rust)
//! don't need this — see `examples/sluicify.py` for the reference
//! protocol. This binary is not required in the sandbox by sluice
//! itself; it's a convenience for clients that can't speak the wire
//! directly.
//!
//! Usage:
//!     sluicify <socket> <cmd> [args...]
//!     sluicify --version | --help
//!
//! Exit code:
//!     n in 0..=255  — the spawned child's exit code (128 + signo when
//!                     it was killed by a signal)
//!     124           — the rule's timeout fired (as GNU `timeout`)
//!     128 + |status|  — sluice rejected (ERR_NO_RULE etc); see proto.rs

use nix::sys::socket::{
    connect, recvmsg, sendmsg, socket, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
    UnixAddr,
};
use sluicify::proto::{
    ERR_AUDIT, ERR_FDS, ERR_NO_RULE, ERR_PEER, ERR_PROTO, ERR_SPAWN, ERR_TIMEOUT, MAGIC, VERSION,
};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;

/// Map a connect(2) failure to an ssh-style one-liner. ENOENT and
/// ECONNREFUSED are by far the most common real-world cases (broker not
/// running, stale socket file) — naming them explicitly turns a cryptic
/// errno into something a user can act on.
fn connect_hint(e: &nix::errno::Errno, sock_path: &str) -> String {
    use nix::errno::Errno;
    match e {
        Errno::ENOENT => format!("Broker not running: no socket at {sock_path}"),
        Errno::ECONNREFUSED => {
            format!("Connection refused at {sock_path} (broker not accepting connections)")
        }
        Errno::EACCES | Errno::EPERM => format!("Permission denied connecting to {sock_path}"),
        _ => format!("Could not connect to {sock_path}: {e}"),
    }
}

/// Map a sluice broker error status to a human-readable one-liner. The
/// command name is included where it makes the message actionable
/// (e.g. ERR_NO_RULE), since that's the field the user most often needs
/// to fix in their rules file.
fn broker_error_message(status: i32, cmd: &str) -> String {
    match status {
        ERR_NO_RULE => format!("No matching rule for command: {cmd}"),
        ERR_PROTO => "Protocol error: broker rejected request framing".to_string(),
        ERR_FDS => "Protocol error: expected 3 file descriptors (stdin/stdout/stderr)".to_string(),
        ERR_SPAWN => format!("Failed to spawn {cmd} (exec error)"),
        ERR_TIMEOUT => format!("{cmd} timed out (rule timeout) and was killed"),
        ERR_PEER => "Broker refused: could not identify the caller (SO_PEERCRED)".to_string(),
        ERR_AUDIT => "Broker refused: audit sink unwritable (audit=strict)".to_string(),
        n => format!("Broker error (status {n})"),
    }
}

fn main() -> ExitCode {
    const USAGE: &str =
        "usage: sluicify <socket> <cmd> [args...]\n       sluicify --version | --help";
    let mut args = std::env::args_os().skip(1);
    let Some(first) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match first.to_str() {
        Some("--version" | "-V") => {
            println!("sluicify {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    let sock_path = PathBuf::from(first);
    let mut argv: Vec<String> = Vec::new();
    for (i, a) in args.enumerate() {
        match a.into_string() {
            Ok(s) => argv.push(s),
            Err(a) => {
                eprintln!(
                    "sluicify: Argument {} is not valid UTF-8: {}",
                    i + 1,
                    a.to_string_lossy()
                );
                return ExitCode::from(2);
            }
        }
    }
    if argv.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let cmd = argv[0].as_str();
    let sock_display = sock_path.display().to_string();

    // Encode request payload.
    let mut buf = Vec::with_capacity(64 + argv.iter().map(|s| s.len() + 4).sum::<usize>());
    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&(argv.len() as u32).to_le_bytes());
    for a in &argv {
        let b = a.as_bytes();
        buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
        buf.extend_from_slice(b);
    }

    let sock: OwnedFd = match socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sluicify: Could not create unix socket: {e}");
            return ExitCode::from(2);
        }
    };
    let addr = match UnixAddr::new(&sock_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sluicify: Invalid socket path {sock_display}: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = connect(sock.as_raw_fd(), &addr) {
        eprintln!("sluicify: {}", connect_hint(&e, &sock_display));
        return ExitCode::from(2);
    }

    // Send payload + our 0/1/2 fds via SCM_RIGHTS.
    let fds = [0, 1, 2];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    if let Err(e) = sendmsg::<UnixAddr>(
        sock.as_raw_fd(),
        &[IoSlice::new(&buf)],
        &cmsg,
        MsgFlags::empty(),
        None,
    ) {
        eprintln!("sluicify: Failed to send request to broker: {e}");
        return ExitCode::from(2);
    }

    // Receive 12-byte reply.
    let mut reply = [0u8; 64];
    let mut iov = [IoSliceMut::new(&mut reply)];
    let msg = match recvmsg::<UnixAddr>(sock.as_raw_fd(), &mut iov, None, MsgFlags::empty()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("sluicify: Lost connection to broker: {e}");
            return ExitCode::from(2);
        }
    };
    if msg.bytes < 12 {
        eprintln!(
            "sluicify: Broker closed connection without reply ({} bytes)",
            msg.bytes
        );
        return ExitCode::from(2);
    }
    let magic = u32::from_le_bytes(reply[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(reply[4..8].try_into().unwrap());
    let status = i32::from_le_bytes(reply[8..12].try_into().unwrap());
    if magic != MAGIC || version != VERSION {
        eprintln!(
            "sluicify: Protocol mismatch with broker (got magic={magic:#x} version={version}, expected magic={MAGIC:#x} version={VERSION})"
        );
        return ExitCode::from(2);
    }

    if status >= 0 {
        return ExitCode::from(status.clamp(0, 255) as u8);
    }
    eprintln!("sluicify: {}", broker_error_message(status, cmd));
    if status == ERR_TIMEOUT {
        ExitCode::from(124)
    } else {
        ExitCode::from((128u32 + (-status) as u32).min(255) as u8)
    }
}
