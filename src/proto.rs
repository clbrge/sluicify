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
//! Reply (12 bytes total):
//!     u32  magic
//!     u32  version
//!     i32  status
//!         status >= 0  → child exit code (0..=255)
//!         status <  0  → sluice error (see ERR_* below)

pub const MAGIC: u32 = 0x534C4358;
pub const VERSION: u32 = 1;

pub const MAX_ARGV: usize = 256;
pub const MAX_ARG_BYTES: usize = 16 * 1024;
pub const MAX_PAYLOAD: usize = 1 << 20; // 1 MiB

pub const ERR_NO_RULE: i32 = -1;
pub const ERR_PROTO: i32 = -2;
pub const ERR_FDS: i32 = -3; // wrong fd count
pub const ERR_SPAWN: i32 = -4;
pub const ERR_SIGNALED: i32 = -5; // child died from a signal
pub const ERR_AUDIT: i32 = -6; // configured audit sink unwritable (strict)

#[derive(Debug)]
pub struct Request {
    pub argv: Vec<String>,
}

#[derive(Debug)]
pub enum DecodeError {
    BadMagic,
    BadVersion,
    BadArgc,
    ArgTooBig,
    Truncated,
    BadUtf8,
    EmbeddedNul,
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
    if count == 0 || count > MAX_ARGV {
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
    Ok(Request { argv })
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
        let req = decode_request(&buf).unwrap();
        assert_eq!(req.argv, vec!["git", "log", "-n", "5"]);
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
    fn empty_argv_rejected() {
        let buf = encode(&[]);
        assert!(matches!(decode_request(&buf), Err(DecodeError::BadArgc)));
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
