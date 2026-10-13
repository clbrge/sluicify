//! Wire protocol: request/reply framing.
//!
//! Transport: AF_UNIX SOCK_SEQPACKET. Each direction is exactly one
//! message. The kernel preserves message boundaries, so encode and
//! decode are total — no streaming reassembly.
//!
//! Request:
//!     u32  magic   = 0x534C4358   ("SLCX")
//!     u32  version = 1
//!     u32  argv_count
//!     for each arg:
//!         u32  byte_len
//!         bytes (UTF-8, no embedded NUL)
//!     ancillary: SCM_RIGHTS = [stdin_fd, stdout_fd, stderr_fd]
//!
//!   An argv_count of 0 asks what the socket allows instead of running
//!   anything, and needs no fds. A broker older than this request answers
//!   it ERR_PROTO.
//!
//! Reply (12 bytes total):
//!     u32  magic
//!     u32  version
//!     i32  status
//!         status >= 0  → child exit code (0..=255); 128 + signo when
//!                        the child was killed by a signal
//!         status <  0  → sluice error (see ERR_* below)
//!
//! Reply to a listing request, when status is 0, goes on:
//!     u32  byte_len (at most MAX_LISTING)
//!     bytes (UTF-8): what `Rules::listing` says

pub const MAGIC: u32 = 0x534C4358;
pub const VERSION: u32 = 1;

pub const MAX_ARGV: usize = 256;
pub const MAX_ARG_BYTES: usize = 16 * 1024;
pub const MAX_PAYLOAD: usize = 1 << 20; // 1 MiB

pub const ERR_NO_RULE: i32 = -1;
pub const ERR_PROTO: i32 = -2;
pub const ERR_FDS: i32 = -3; // wrong fd count
pub const ERR_SPAWN: i32 = -4;
pub const ERR_AUDIT: i32 = -6; // configured audit sink unwritable (strict)
pub const ERR_TIMEOUT: i32 = -7; // rule timeout fired; child was killed
pub const ERR_PEER: i32 = -8; // caller's SO_PEERCRED unreadable
pub const ERR_TOO_LARGE: i32 = -9; // the listing does not fit in one reply

pub const MAX_LISTING: usize = 64 * 1024;

#[derive(Debug)]
pub enum Request {
    Call { argv: Vec<String> },
    List,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ListReply {
    Listing(String),
    Refused(i32),
}

#[derive(Debug)]
pub enum DecodeError {
    BadMagic,
    BadVersion,
    BadArgc,
    ArgTooBig,
    ListingTooBig,
    BadStatus,
    Truncated,
    BadUtf8,
    EmbeddedNul,
    TrailingBytes,
}

pub fn decode_request(buf: &[u8]) -> Result<Request, DecodeError> {
    let mut p = Cursor::new(buf);
    let magic = p.read_u32().ok_or(DecodeError::Truncated)?;
    if magic != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = p.read_u32().ok_or(DecodeError::Truncated)?;
    if version != VERSION {
        return Err(DecodeError::BadVersion);
    }
    let count = p.read_u32().ok_or(DecodeError::Truncated)? as usize;
    if count == 0 {
        if p.pos != buf.len() {
            return Err(DecodeError::TrailingBytes);
        }
        return Ok(Request::List);
    }
    if count > MAX_ARGV {
        return Err(DecodeError::BadArgc);
    }
    let mut argv = Vec::with_capacity(count);
    for _ in 0..count {
        let n = p.read_u32().ok_or(DecodeError::Truncated)? as usize;
        if n > MAX_ARG_BYTES {
            return Err(DecodeError::ArgTooBig);
        }
        let bytes = p.read_n(n).ok_or(DecodeError::Truncated)?;
        if bytes.contains(&0) {
            return Err(DecodeError::EmbeddedNul);
        }
        let s = std::str::from_utf8(bytes)
            .map_err(|_| DecodeError::BadUtf8)?
            .to_string();
        argv.push(s);
    }
    if p.pos != buf.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(Request::Call { argv })
}

pub fn encode_list_request() -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&VERSION.to_le_bytes());
    out
}

/// `None` when the listing is longer than `MAX_LISTING`.
pub fn encode_listing(text: &str) -> Option<Vec<u8>> {
    if text.len() > MAX_LISTING {
        return None;
    }
    let mut out = Vec::with_capacity(16 + text.len());
    out.extend_from_slice(&encode_reply(0));
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Some(out)
}

pub fn decode_list_reply(buf: &[u8]) -> Result<ListReply, DecodeError> {
    let mut p = Cursor::new(buf);
    if p.read_u32().ok_or(DecodeError::Truncated)? != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if p.read_u32().ok_or(DecodeError::Truncated)? != VERSION {
        return Err(DecodeError::BadVersion);
    }
    let status = p.read_u32().ok_or(DecodeError::Truncated)? as i32;
    if status > 0 {
        return Err(DecodeError::BadStatus);
    }
    if status < 0 {
        if p.pos != buf.len() {
            return Err(DecodeError::TrailingBytes);
        }
        return Ok(ListReply::Refused(status));
    }
    let n = p.read_u32().ok_or(DecodeError::Truncated)? as usize;
    if n > MAX_LISTING {
        return Err(DecodeError::ListingTooBig);
    }
    let bytes = p.read_n(n).ok_or(DecodeError::Truncated)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| DecodeError::BadUtf8)?
        .to_string();
    if p.pos != buf.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(ListReply::Listing(text))
}

pub fn encode_reply(status: i32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&VERSION.to_le_bytes());
    out[8..12].copy_from_slice(&status.to_le_bytes());
    out
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn read_u32(&mut self) -> Option<u32> {
        let bytes = self.read_n(4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }
    fn read_n(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn roundtrip() {
        let buf = encode(&["git", "log", "-n", "5"]);
        let Request::Call { argv } = decode_request(&buf).unwrap() else {
            panic!("a call decoded as a listing request");
        };
        assert_eq!(argv, vec!["git", "log", "-n", "5"]);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = encode(&["x"]);
        buf[0] = 0;
        assert!(matches!(decode_request(&buf), Err(DecodeError::BadMagic)));
    }

    #[test]
    fn truncated_rejected() {
        let buf = encode(&["x"]);
        assert!(decode_request(&buf[..buf.len() - 1]).is_err());
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut buf = encode(&["x"]);
        buf.push(0);
        assert!(matches!(
            decode_request(&buf),
            Err(DecodeError::TrailingBytes)
        ));
    }

    #[test]
    fn empty_argv_asks_for_the_listing() {
        assert!(matches!(
            decode_request(&encode_list_request()),
            Ok(Request::List)
        ));
        let mut buf = encode_list_request().to_vec();
        buf.push(0);
        assert!(matches!(
            decode_request(&buf),
            Err(DecodeError::TrailingBytes)
        ));
    }

    #[test]
    fn too_many_args_rejected() {
        let args = vec!["x"; MAX_ARGV + 1];
        assert!(matches!(
            decode_request(&encode(&args)),
            Err(DecodeError::BadArgc)
        ));
    }

    #[test]
    fn listing_roundtrip() {
        let reply = encode_listing("echo <1>\n  1 matches [a-z]+\n").unwrap();
        assert_eq!(
            decode_list_reply(&reply).unwrap(),
            ListReply::Listing("echo <1>\n  1 matches [a-z]+\n".into())
        );
        assert_eq!(
            decode_list_reply(&encode_reply(ERR_PROTO)).unwrap(),
            ListReply::Refused(ERR_PROTO)
        );
        assert!(matches!(
            decode_list_reply(&reply[..reply.len() - 1]),
            Err(DecodeError::Truncated)
        ));
        assert!(matches!(
            decode_list_reply(&encode_reply(3)),
            Err(DecodeError::BadStatus)
        ));
    }

    #[test]
    fn listing_too_large_is_not_encoded() {
        assert!(encode_listing(&"x".repeat(MAX_LISTING)).is_some());
        assert!(encode_listing(&"x".repeat(MAX_LISTING + 1)).is_none());
    }

    #[test]
    fn embedded_nul_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC.to_le_bytes());
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(b"a\0b");
        assert!(matches!(
            decode_request(&buf),
            Err(DecodeError::EmbeddedNul)
        ));
    }

    #[test]
    fn reply_shape() {
        let r = encode_reply(42);
        assert_eq!(&r[0..4], &MAGIC.to_le_bytes());
        assert_eq!(&r[4..8], &VERSION.to_le_bytes());
        assert_eq!(&r[8..12], &42i32.to_le_bytes());
    }
}
