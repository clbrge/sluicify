//! Native Node.js addon for sluice.
//!
//! Same wire protocol as `examples/sluicify.py` and the `sluicify`
//! companion binary. Sends fds 0/1/2 of the calling Node process via
//! `SCM_RIGHTS`; the broker `dup2`s them onto the spawned child, so
//! stdio is end-to-end kernel passthrough — no buffer involvement, no
//! transformation.
//!
//! Exposed JS API:
//!
//!     const sluice = require('sluicify-native');
//!     const status = sluice.call('/run/sluice.sock', ['echo', 'hi']);
//!
//! `call` is **synchronous**: it blocks the calling JS thread until the
//! broker replies. The spawned child uses your Node process's stdio, so
//! the JS event loop continues serving other I/O while the child runs.
//! For long-running calls where you need the calling thread free,
//! invoke `call` from a `worker_threads` Worker.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use nix::sys::socket::{
    connect, recvmsg, sendmsg, socket, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
    UnixAddr,
};
use sluicify::proto::{MAGIC, VERSION};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, OwnedFd};

#[napi]
pub fn call(socket_path: String, argv: Vec<String>) -> Result<i32> {
    if argv.is_empty() {
        return Err(Error::from_reason("argv must be non-empty"));
    }

    // Encode request payload (matches src/proto.rs).
    let mut buf = Vec::with_capacity(64 + argv.iter().map(|s| s.len() + 4).sum::<usize>());
    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&(argv.len() as u32).to_le_bytes());
    for a in &argv {
        let b = a.as_bytes();
        buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
        buf.extend_from_slice(b);
    }

    let sock: OwnedFd = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| Error::from_reason(format!("socket: {e}")))?;
    let addr = UnixAddr::new(socket_path.as_str())
        .map_err(|e| Error::from_reason(format!("invalid socket path: {e}")))?;
    connect(sock.as_raw_fd(), &addr)
        .map_err(|e| Error::from_reason(format!("connect {socket_path}: {e}")))?;

    // 0/1/2 are the Node process's own stdio.
    let fds: [i32; 3] = [0, 1, 2];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<UnixAddr>(
        sock.as_raw_fd(),
        &[IoSlice::new(&buf)],
        &cmsg,
        MsgFlags::empty(),
        None,
    )
    .map_err(|e| Error::from_reason(format!("sendmsg: {e}")))?;

    let mut reply = [0u8; 64];
    let mut iov = [IoSliceMut::new(&mut reply)];
    let msg = recvmsg::<UnixAddr>(sock.as_raw_fd(), &mut iov, None, MsgFlags::empty())
        .map_err(|e| Error::from_reason(format!("recvmsg: {e}")))?;
    if msg.bytes < 12 {
        return Err(Error::from_reason(format!(
            "short reply: {} bytes",
            msg.bytes
        )));
    }
    let magic = u32::from_le_bytes(reply[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(reply[4..8].try_into().unwrap());
    let status = i32::from_le_bytes(reply[8..12].try_into().unwrap());
    if magic != MAGIC || version != VERSION {
        return Err(Error::from_reason(format!(
            "bad reply: magic={magic:#x} version={version}"
        )));
    }
    Ok(status)
}
