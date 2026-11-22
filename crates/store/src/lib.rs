//! sysmon on-disk recordings.
//!
//! Received datagrams are stored verbatim, so the disk format is the wire
//! format and replay reuses the live decoder.
//!
//! ```text
//! <data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.seg
//!
//! file        := file_header block*
//! file_header := "SMSEG" version:u8
//! block       := len:u32le crc32:u32le zstd(record*)
//! record      := recv_ts_ns:u64le len:u16le datagram[len]
//! ```
//!
//! TODO: sparse `.idx` files for seeking, retention.

mod reader;
mod recorder;
mod writer;

pub use reader::SegmentReader;
pub use recorder::{Recorder, segment_path};
pub use writer::SegmentWriter;

pub const FILE_MAGIC: &[u8; 5] = b"SMSEG";
pub const FILE_VERSION: u8 = 1;
pub const FILE_HEADER_LEN: u64 = 6;
pub const BLOCK_HEADER_LEN: usize = 8;

/// One stored datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub recv_ts_ns: u64,
    pub datagram: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("not a sysmon segment file")]
    BadMagic,
    #[error("unsupported segment version {0}")]
    UnsupportedVersion(u8),
    #[error("corrupt block at offset {0}")]
    Corrupt(u64),
    #[error("datagram of {0} bytes is too large to store")]
    TooLarge(usize),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Decode the records in one decompressed block.
pub(crate) fn parse_records(mut buf: &[u8], out: &mut Vec<Record>) -> Option<()> {
    while !buf.is_empty() {
        let ts = u64::from_le_bytes(buf.get(..8)?.try_into().ok()?);
        let len = u16::from_le_bytes(buf.get(8..10)?.try_into().ok()?) as usize;
        let datagram = buf.get(10..10 + len)?.to_vec();
        out.push(Record {
            recv_ts_ns: ts,
            datagram,
        });
        buf = &buf[10 + len..];
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sysmon-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("test.seg")
    }

    fn records(n: u64) -> Vec<Record> {
        (0..n)
            .map(|i| Record {
                recv_ts_ns: i * 1_000_000_000,
                datagram: vec![i as u8; 100 + i as usize],
            })
            .collect()
    }

    #[test]
    fn round_trip() {
        let path = tmp("round-trip");
        let mut w = SegmentWriter::open(&path).unwrap();
        for r in records(50) {
            w.append(r.recv_ts_ns, &r.datagram).unwrap();
        }
        w.flush().unwrap();
        drop(w);

        let got: Vec<_> = SegmentReader::open(&path)
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(got, records(50));
    }

    #[test]
    fn torn_tail_is_truncated_on_reopen() {
        let path = tmp("torn-tail");
        let mut w = SegmentWriter::open(&path).unwrap();
        for r in records(10) {
            w.append(r.recv_ts_ns, &r.datagram).unwrap();
        }
        w.flush().unwrap();
        drop(w);

        // Simulate a crash in the middle of writing the next block.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&[0xff; 7]).unwrap();
        drop(f);

        let mut w = SegmentWriter::open(&path).unwrap();
        w.append(99, b"after").unwrap();
        w.flush().unwrap();
        drop(w);

        let got: Vec<_> = SegmentReader::open(&path)
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(got.len(), 11);
        assert_eq!(got[10].datagram, b"after");
    }
}
