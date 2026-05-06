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
//!
//! Exit code:
//!     n in 0..=255  — the spawned child's exit code
//!     128 + |status|  — sluice rejected (ERR_NO_RULE etc); see proto.rs

use nix::sys::socket::{
    connect, recvmsg, sendmsg, socket, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
    UnixAddr,
};
use sluicify::proto::{MAGIC, VERSION};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: sluicify <socket> <cmd> [args...]");
        return ExitCode::from(2);
    }
    let sock_path = &args[1];
    let argv = &args[2..];

    // Encode request payload.
    let mut buf = Vec::with_capacity(64 + argv.iter().map(|s| s.len() + 4).sum::<usize>());
    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&(argv.len() as u32).to_le_bytes());
    for a in argv {
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
            eprintln!("sluicify: socket: {e}");
            return ExitCode::from(2);
        }
    };
    let addr = match UnixAddr::new(sock_path.as_str()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sluicify: invalid socket path: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = connect(sock.as_raw_fd(), &addr) {
        eprintln!("sluicify: connect {sock_path}: {e}");
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
        eprintln!("sluicify: sendmsg: {e}");
        return ExitCode::from(2);
    }

    // Receive 12-byte reply.
    let mut reply = [0u8; 64];
    let mut iov = [IoSliceMut::new(&mut reply)];
    let msg = match recvmsg::<UnixAddr>(sock.as_raw_fd(), &mut iov, None, MsgFlags::empty()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("sluicify: recvmsg: {e}");
            return ExitCode::from(2);
        }
    };
    if msg.bytes < 12 {
        eprintln!("sluicify: short reply ({} bytes)", msg.bytes);
        return ExitCode::from(2);
    }
    let magic = u32::from_le_bytes(reply[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(reply[4..8].try_into().unwrap());
    let status = i32::from_le_bytes(reply[8..12].try_into().unwrap());
    if magic != MAGIC || version != VERSION {
        eprintln!("sluicify: bad reply magic/version: {magic:#x}/{version}");
        return ExitCode::from(2);
    }

    if status >= 0 {
        ExitCode::from(status.clamp(0, 255) as u8)
    } else {
        eprintln!("sluicify: sluice error status {status}");
        ExitCode::from((128u32 + (-status) as u32).min(255) as u8)
    }
}
