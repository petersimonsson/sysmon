//! Optional payload compression and authenticated encryption.
//!
//! Both act on the bytes after the 4-byte preamble and are announced by bits
//! in its `flags` byte:
//!
//! ```text
//! plain:      [ "SM" ver flags ][ payload ]
//! compressed: [ "SM" ver flags|COMPRESSED ][ zstd(payload) ]
//! encrypted:  [ "SM" ver flags|ENCRYPTED  ][ nonce:24 ][ XChaCha20-Poly1305(payload) + tag:16 ]
//! ```
//!
//! The preamble is the AEAD's associated data, so flags can't be altered.
//! Nonces are random; with 192 bits there is no practical chance of reuse.
//! The monitor opens (decrypts) datagrams before recording them, so
//! recordings never need the key.

use std::borrow::Cow;
use std::path::Path;

use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::{Error, MAGIC, PREAMBLE_LEN, Result, VERSION, flags};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Bytes encryption adds to a datagram.
pub const SEAL_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
const ZSTD_LEVEL: i32 = 3;
/// Decompressed payloads are never larger than this.
const MAX_PAYLOAD: usize = 64 * 1024;

/// A 256-bit pre-shared key.
#[derive(Clone)]
pub struct Key([u8; 32]);

impl Key {
    pub fn generate() -> Self {
        let key = chacha20poly1305::Key::generate();
        Self(key.into())
    }

    /// Parse 64 hex digits (surrounding whitespace allowed).
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return None;
        }
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Self(key))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Read a key file: 64 hex digits, or exactly 32 raw bytes.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        if let Ok(raw) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(Self(raw));
        }
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(Self::from_hex)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}: expected 64 hex digits or 32 raw bytes", path.display()),
                )
            })
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

/// Sender side: compresses and/or encrypts encoded datagrams.
pub struct Sealer {
    cipher: Option<XChaCha20Poly1305>,
    compress: bool,
}

impl Sealer {
    pub fn new(key: Option<&Key>, compress: bool) -> Self {
        Self {
            cipher: key.map(Key::cipher),
            compress,
        }
    }

    /// Transform a datagram from [`crate::encode`]. The result is never
    /// larger than the input plus [`SEAL_OVERHEAD`].
    pub fn seal(&self, datagram: Vec<u8>) -> Result<Vec<u8>> {
        if !self.compress && self.cipher.is_none() {
            return Ok(datagram);
        }
        check_preamble(&datagram)?;
        let mut flags = datagram[3];
        let mut payload = Cow::Borrowed(&datagram[PREAMBLE_LEN..]);

        if self.compress {
            let c = zstd::bulk::compress(&payload, ZSTD_LEVEL).map_err(Error::Compression)?;
            if c.len() < payload.len() {
                payload = Cow::Owned(c);
                flags |= flags::COMPRESSED;
            }
        }

        let Some(cipher) = &self.cipher else {
            let mut out = Vec::with_capacity(PREAMBLE_LEN + payload.len());
            out.extend_from_slice(&datagram[..3]);
            out.push(flags);
            out.extend_from_slice(&payload);
            return Ok(out);
        };
        flags |= flags::ENCRYPTED;
        // Keep the datagram's own version; it's authenticated with the rest.
        let preamble = [MAGIC[0], MAGIC[1], datagram[2], flags];
        let nonce = XNonce::generate();
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &payload,
                    aad: &preamble,
                },
            )
            .map_err(|_| Error::Crypto)?;
        let mut out = Vec::with_capacity(PREAMBLE_LEN + NONCE_LEN + ct.len());
        out.extend_from_slice(&preamble);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

/// Receiver side: authenticates and decrypts datagrams.
pub struct Opener {
    cipher: Option<XChaCha20Poly1305>,
}

impl Opener {
    /// With a key, only datagrams encrypted with that key are accepted.
    /// Without one, encrypted datagrams are rejected.
    pub fn new(key: Option<&Key>) -> Self {
        Self {
            cipher: key.map(Key::cipher),
        }
    }

    /// Return the datagram with encryption removed (it may still be
    /// compressed; [`crate::decode`] handles that). This is what gets recorded.
    pub fn open<'a>(&self, buf: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        check_preamble(buf)?;
        let flags = buf[3];
        let encrypted = flags & flags::ENCRYPTED != 0;
        let Some(cipher) = &self.cipher else {
            return if encrypted {
                Err(Error::NeedsKey)
            } else {
                Ok(Cow::Borrowed(buf))
            };
        };
        if !encrypted {
            return Err(Error::Unauthenticated);
        }
        let body = &buf[PREAMBLE_LEN..];
        if body.len() < SEAL_OVERHEAD {
            return Err(Error::Truncated);
        }
        let (nonce, ct) = body.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).map_err(|_| Error::Truncated)?;
        let plain = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ct,
                    aad: &buf[..PREAMBLE_LEN],
                },
            )
            .map_err(|_| Error::Unauthenticated)?;
        let mut out = Vec::with_capacity(PREAMBLE_LEN + plain.len());
        out.extend_from_slice(&buf[..3]);
        out.push(flags & !flags::ENCRYPTED);
        out.extend_from_slice(&plain);
        Ok(Cow::Owned(out))
    }
}

/// Undo compression on a payload, if its flags say so.
pub(crate) fn decompress(flags: u8, payload: &[u8]) -> Result<Cow<'_, [u8]>> {
    if flags & flags::COMPRESSED == 0 {
        return Ok(Cow::Borrowed(payload));
    }
    zstd::bulk::decompress(payload, MAX_PAYLOAD)
        .map(Cow::Owned)
        .map_err(Error::Compression)
}

fn check_preamble(buf: &[u8]) -> Result<()> {
    if buf.len() < PREAMBLE_LEN {
        return Err(Error::Truncated);
    }
    if buf[..2] != MAGIC {
        return Err(Error::BadMagic);
    }
    if !(crate::MIN_VERSION..=VERSION).contains(&buf[2]) {
        return Err(Error::UnsupportedVersion(buf[2]));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Header, Msg, ProcSample, SystemSample, decode, encode, encode_sample};

    fn sample_datagrams() -> Vec<Vec<u8>> {
        let procs: Vec<_> = (0..300)
            .map(|pid| ProcSample {
                pid,
                ppid: 1,
                starttime: 99,
                state: b'S',
                utime: 1234,
                stime: 56,
                rss_pages: 789,
                threads: 2,
                comm: "kworker/u64:2".into(),
                vsize_bytes: Some(1 << 30),
                shared_pages: Some(100),
                kernel_thread: None,
            })
            .collect();
        encode_sample(1, 2, 3, &SystemSample::default(), &procs, &[]).unwrap()
    }

    #[test]
    fn compressed_round_trip_is_smaller() {
        let sealer = Sealer::new(None, true);
        for d in sample_datagrams() {
            let sealed = sealer.seal(d.clone()).unwrap();
            assert!(sealed.len() <= d.len());
            assert_eq!(decode(&sealed).unwrap(), decode(&d).unwrap());
        }
        let d = &sample_datagrams()[1];
        let sealed = sealer.seal(d.clone()).unwrap();
        assert!(sealed[3] & flags::COMPRESSED != 0);
        assert!(
            sealed.len() < d.len() / 2,
            "{} vs {}",
            sealed.len(),
            d.len()
        );
    }

    #[test]
    fn encrypted_round_trip() {
        let key = Key::generate();
        let sealer = Sealer::new(Some(&key), true);
        let opener = Opener::new(Some(&key));
        for d in sample_datagrams() {
            let sealed = sealer.seal(d.clone()).unwrap();
            assert!(sealed.len() <= crate::MAX_DATAGRAM);
            assert!(matches!(decode(&sealed), Err(Error::NeedsKey)));
            let opened = opener.open(&sealed).unwrap();
            assert_eq!(opened[3] & flags::ENCRYPTED, 0);
            assert_eq!(decode(&opened).unwrap(), decode(&d).unwrap());
        }
    }

    #[test]
    fn rejects_tampering_wrong_keys_and_plaintext() {
        let key = Key::generate();
        let sealer = Sealer::new(Some(&key), false);
        let opener = Opener::new(Some(&key));
        let d = encode(
            &Header {
                host_id: 1,
                boot_id: 2,
                seq: 3,
                chunk: 0,
                chunks: 1,
            },
            &Msg::Procs(vec![]),
        )
        .unwrap();
        let sealed = sealer.seal(d.clone()).unwrap();

        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(matches!(opener.open(&flipped), Err(Error::Unauthenticated)));

        let mut flags_changed = sealed.clone();
        flags_changed[3] |= flags::COMPRESSED;
        assert!(matches!(
            opener.open(&flags_changed),
            Err(Error::Unauthenticated)
        ));

        let other = Opener::new(Some(&Key::generate()));
        assert!(matches!(other.open(&sealed), Err(Error::Unauthenticated)));

        assert!(matches!(opener.open(&d), Err(Error::Unauthenticated)));
        assert!(matches!(
            Opener::new(None).open(&sealed),
            Err(Error::NeedsKey)
        ));
        assert!(Opener::new(None).open(&d).is_ok());
    }

    #[test]
    fn v1_datagrams_seal_and_open() {
        let h = Header {
            host_id: 1,
            boot_id: 2,
            seq: 3,
            chunk: 0,
            chunks: 1,
        };
        let d = crate::v1::encode(&h, &crate::v1::Msg::Procs(vec![])).unwrap();
        let key = Key::generate();
        let sealed = Sealer::new(Some(&key), true).seal(d).unwrap();
        assert_eq!(sealed[2], 1, "version byte kept");
        let opened = Opener::new(Some(&key)).open(&sealed).unwrap();
        assert_eq!(decode(&opened).unwrap(), (h, Msg::Procs(vec![])));
    }

    #[test]
    fn key_hex_round_trip() {
        let k = Key::generate();
        assert_eq!(Key::from_hex(&k.to_hex()).unwrap().0, k.0);
        assert!(Key::from_hex("abc").is_none());
    }
}
