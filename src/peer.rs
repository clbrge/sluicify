//! Peer identification via SO_PEERCRED.
//!
//! Identity for authorization is "which socket the caller connected to"
//! (one socket per sandbox). The peer creds are recorded for audit logs
//! only.

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::os::unix::io::AsFd;

#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_of<F: AsFd>(fd: &F) -> nix::Result<PeerInfo> {
    let creds = getsockopt(fd, PeerCredentials)?;
    Ok(PeerInfo {
        pid: creds.pid(),
        uid: creds.uid(),
        gid: creds.gid(),
    })
}
