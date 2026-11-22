//! Sparse per-segment index: one entry per block, so a reader can find the
//! block covering a time by binary search and decompress only that block.
//!
//! ```text
//! <name>.idx := entry*
//! entry      := first_ts:u64le last_ts:u64le offset:u64le len:u32le   (28 bytes)
//! ```
//!
//! The index is derived data. Readers trust only the prefix of entries that
//! chains contiguously through the segment, then scan any blocks after it, so
//! a missing, stale or damaged index costs time but never correctness. Only
//! the writer writes index files.

use std::fs::File;
use std::io::{BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};

use crate::block::{self, BlockRef};
use crate::{FILE_HEADER_LEN, Record, Result};

pub const ENTRY_LEN: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    pub first_ts: u64,
    pub last_ts: u64,
    pub block: BlockRef,
}

impl IndexEntry {
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        let mut b = [0u8; ENTRY_LEN];
        b[..8].copy_from_slice(&self.first_ts.to_le_bytes());
        b[8..16].copy_from_slice(&self.last_ts.to_le_bytes());
        b[16..24].copy_from_slice(&self.block.offset.to_le_bytes());
        b[24..].copy_from_slice(&self.block.len.to_le_bytes());
        b
    }

    fn from_bytes(b: &[u8]) -> Self {
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Self {
            first_ts: u64_at(0),
            last_ts: u64_at(8),
            block: BlockRef {
                offset: u64_at(16),
                len: u32::from_le_bytes(b[24..28].try_into().unwrap()),
            },
        }
    }

    /// Build an entry by decompressing a block.
    pub fn from_block(block: BlockRef, payload: &[u8]) -> Result<Option<Self>> {
        let mut records: Vec<Record> = Vec::new();
        block::decode_block(payload, block.offset, &mut records)?;
        Ok(match (records.first(), records.last()) {
            (Some(f), Some(l)) => Some(Self {
                first_ts: f.recv_ts_ns,
                last_ts: l.recv_ts_ns,
                block,
            }),
            _ => None,
        })
    }
}

pub fn index_path(segment: &Path) -> PathBuf {
    segment.with_extension("idx")
}

/// The index of a segment, and whether the on-disk `.idx` was already
/// complete and correct.
pub struct Loaded {
    pub entries: Vec<IndexEntry>,
    pub was_complete: bool,
}

/// Load the index for `segment`, completing it by scanning any blocks it
/// doesn't cover. `seg` must be positioned anywhere; it is seeked as needed.
pub fn load<R: Read + Seek>(segment: &Path, seg: &mut R) -> Result<Loaded> {
    let on_disk = std::fs::read(index_path(segment)).unwrap_or_default();
    let seg_len = seg.seek(std::io::SeekFrom::End(0))?;

    // Keep the prefix that chains contiguously from the file header.
    let mut entries = Vec::new();
    let mut expected = FILE_HEADER_LEN;
    let mut intact = on_disk.len().is_multiple_of(ENTRY_LEN);
    for chunk in on_disk.as_chunks::<ENTRY_LEN>().0 {
        let e = IndexEntry::from_bytes(chunk);
        if e.block.offset != expected || e.block.end() > seg_len || e.first_ts > e.last_ts {
            intact = false;
            break;
        }
        expected = e.block.end();
        entries.push(e);
    }

    // Cover whatever comes after the trusted prefix.
    let indexed = entries.len();
    block::scan_blocks(seg, expected, |b, payload| {
        if let Some(e) = IndexEntry::from_block(b, payload)? {
            entries.push(e);
        }
        Ok(())
    })?;

    Ok(Loaded {
        was_complete: intact && entries.len() == indexed,
        entries,
    })
}

/// Load the index for a segment file by path.
pub fn load_path(segment: &Path) -> Result<Vec<IndexEntry>> {
    let mut f = BufReader::new(File::open(segment)?);
    block::check_file_header(&mut f)?;
    Ok(load(segment, &mut f)?.entries)
}

pub fn write_all(segment: &Path, entries: &[IndexEntry]) -> Result<File> {
    let mut f = File::create(index_path(segment))?;
    let mut buf = Vec::with_capacity(entries.len() * ENTRY_LEN);
    for e in entries {
        buf.extend_from_slice(&e.to_bytes());
    }
    f.write_all(&buf)?;
    Ok(f)
}

/// Index of the first block that may contain records at or after `ts`.
pub fn find(entries: &[IndexEntry], ts: u64) -> usize {
    entries.partition_point(|e| e.last_ts < ts)
}
