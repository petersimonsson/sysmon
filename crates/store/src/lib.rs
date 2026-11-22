//! sysmon on-disk recordings.
//!
//! Received datagrams are stored verbatim, so the disk format is the wire
//! format and replay reuses the live decoder.
//!
//! ```text
//! <data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.seg   segment
//! <data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.idx   sparse index (see `index`)
//!
//! file        := file_header block*
//! file_header := "SMSEG" version:u8
//! block       := len:u32le crc32:u32le zstd(record*)
//! record      := recv_ts_ns:u64le len:u16le datagram[len]
//! ```

mod block;
pub mod catalog;
pub mod index;
mod reader;
mod recorder;
pub mod retention;
mod writer;

pub use catalog::{SegmentInfo, list_segments, segment_path};
pub use reader::SegmentReader;
pub use recorder::Recorder;
pub use retention::{PruneReport, Retention, prune};
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const SEC: u64 = 1_000_000_000;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sysmon-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn records(n: u64) -> Vec<Record> {
        (0..n)
            .map(|i| Record {
                recv_ts_ns: i * SEC,
                datagram: vec![i as u8; 100 + i as usize],
            })
            .collect()
    }

    fn write(path: &Path, recs: &[Record]) {
        let mut w = SegmentWriter::open(path).unwrap();
        for r in recs {
            w.append(r.recv_ts_ns, &r.datagram).unwrap();
        }
    }

    fn read_all(r: SegmentReader) -> Vec<Record> {
        r.collect::<Result<_>>().unwrap()
    }

    #[test]
    fn round_trip() {
        let path = tmp_dir("round-trip").join("t.seg");
        write(&path, &records(50));
        assert_eq!(read_all(SegmentReader::open(&path).unwrap()), records(50));
    }

    #[test]
    fn torn_tail_is_truncated_on_reopen() {
        let path = tmp_dir("torn-tail").join("t.seg");
        write(&path, &records(10));

        // Simulate a crash in the middle of writing the next block.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0xff; 7]).unwrap();
        drop(f);

        let mut w = SegmentWriter::open(&path).unwrap();
        w.append(99 * SEC, b"after").unwrap();
        drop(w);

        let got = read_all(SegmentReader::open(&path).unwrap());
        assert_eq!(got.len(), 11);
        assert_eq!(got[10].datagram, b"after");
        let idx = index::load_path(&path).unwrap();
        assert_eq!(idx.last().unwrap().last_ts, 99 * SEC);
    }

    #[test]
    fn index_tracks_blocks_and_seek_skips_ahead() {
        let path = tmp_dir("seek").join("t.seg");
        // 10 s per block, so 100 records make ~10 blocks.
        write(&path, &records(100));

        let on_disk = std::fs::read(index::index_path(&path)).unwrap();
        let entries = index::load_path(&path).unwrap();
        assert!(entries.len() >= 9);
        assert_eq!(on_disk.len(), entries.len() * index::ENTRY_LEN);

        let mut r = SegmentReader::open(&path).unwrap();
        assert_eq!(r.time_range().unwrap(), Some((0, 99 * SEC)));
        r.seek(42 * SEC + 1).unwrap();
        let got = read_all(r);
        assert_eq!(got.first().unwrap().recv_ts_ns, 43 * SEC);
        assert_eq!(got.len(), 57);

        let mut r = SegmentReader::open(&path).unwrap();
        r.seek(1000 * SEC).unwrap();
        assert!(read_all(r).is_empty());
    }

    #[test]
    fn missing_or_damaged_index_is_rebuilt() {
        let path = tmp_dir("rebuild").join("t.seg");
        write(&path, &records(100));
        let good = index::load_path(&path).unwrap();

        std::fs::remove_file(index::index_path(&path)).unwrap();
        assert_eq!(index::load_path(&path).unwrap(), good);

        std::fs::write(index::index_path(&path), [0xaa; 30]).unwrap();
        assert_eq!(index::load_path(&path).unwrap(), good);

        // Reopening for writing repairs the file on disk.
        drop(SegmentWriter::open(&path).unwrap());
        let on_disk = std::fs::read(index::index_path(&path)).unwrap();
        assert_eq!(on_disk.len(), good.len() * index::ENTRY_LEN);
    }

    #[test]
    fn recorder_layout_and_retention() {
        let dir = tmp_dir("retention");
        let hour = catalog::HOUR_NS;
        let base = 1_795_330_800 * SEC; // 2026-11-22T07:00Z
        let mut rec = Recorder::new(&dir);
        for h in 0..5u64 {
            for i in 0..10 {
                rec.append(1, 2, base + h * hour + i * SEC, &[0u8; 200]).unwrap();
            }
        }
        rec.append(3, 4, base, b"other host").unwrap();
        rec.maintain(base + 4 * hour).unwrap();

        let segs = list_segments(&dir).unwrap();
        assert_eq!(segs.len(), 6);
        assert!(segs.iter().all(|s| s.path.with_extension("idx").exists()));

        let now = base + 4 * hour + 30 * 60 * SEC;
        let by_age = Retention {
            max_age: Some(Duration::from_secs(2 * 3600)),
            max_bytes: None,
        };
        let report = prune(&dir, &by_age, now).unwrap();
        // Hours 07 and 08 (both hosts' 07) ended more than two hours ago.
        assert_eq!(report.removed_segments, 3);
        assert!(!dir.join(format!("{:016x}", 3)).exists(), "empty host dir removed");

        let by_size = Retention {
            max_age: None,
            max_bytes: Some(1),
        };
        prune(&dir, &by_size, now).unwrap();
        let left = list_segments(&dir).unwrap();
        assert_eq!(left.len(), 1, "the current hour is never removed");
        assert_eq!(left[0].hour_start_ns, base + 4 * hour);
    }
}
