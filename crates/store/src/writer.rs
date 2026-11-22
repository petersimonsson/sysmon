use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::block::{self, BlockRef};
use crate::index::{self, IndexEntry};
use crate::{BLOCK_HEADER_LEN, Error, FILE_HEADER_LEN, Result};

/// Flush a block when the uncompressed buffer reaches this size...
const BLOCK_MAX_BYTES: usize = 64 * 1024;
/// ...or when it spans this much time.
const BLOCK_MAX_SPAN_NS: u64 = 10_000_000_000;
const ZSTD_LEVEL: i32 = 3;

/// Append-only writer for one segment file and its index.
pub struct SegmentWriter {
    path: PathBuf,
    file: File,
    index: Option<File>,
    end: u64,
    buf: Vec<u8>,
    block_ts: Option<(u64, u64)>,
}

impl SegmentWriter {
    /// Create a segment, or reopen an existing one. A torn tail left by a
    /// crash is truncated, and the index is rebuilt if it is out of date.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let len = file.metadata()?.len();
        let (end, index) = if len == 0 {
            block::write_file_header(&mut file)?;
            (FILE_HEADER_LEN, index::write_all(path, &[])?)
        } else {
            file.seek(SeekFrom::Start(0))?;
            block::check_file_header(&mut file)?;
            let end = block::scan_blocks(&mut file, FILE_HEADER_LEN, |_, _| Ok(()))?;
            if end < len {
                report_truncation(path, len - end);
                file.set_len(end)?;
            }
            let loaded = index::load(path, &mut file)?;
            let index = if loaded.was_complete {
                OpenOptions::new()
                    .append(true)
                    .open(index::index_path(path))?
            } else {
                index::write_all(path, &loaded.entries)?
            };
            (end, index)
        };
        file.seek(SeekFrom::Start(end))?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            index: Some(index),
            end,
            buf: Vec::with_capacity(BLOCK_MAX_BYTES),
            block_ts: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, recv_ts_ns: u64, datagram: &[u8]) -> Result<()> {
        let len = u16::try_from(datagram.len()).map_err(|_| Error::TooLarge(datagram.len()))?;
        let (first, last) = self.block_ts.get_or_insert((recv_ts_ns, recv_ts_ns));
        *last = recv_ts_ns;
        let span = recv_ts_ns.saturating_sub(*first);

        self.buf.extend_from_slice(&recv_ts_ns.to_le_bytes());
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(datagram);

        if self.buf.len() >= BLOCK_MAX_BYTES || span >= BLOCK_MAX_SPAN_NS {
            self.flush()?;
        }
        Ok(())
    }

    /// Compress and write the pending block, fsync it, then record it in the index.
    pub fn flush(&mut self) -> Result<()> {
        let Some((first_ts, last_ts)) = self.block_ts.take() else {
            return Ok(());
        };
        let block = block::encode_block(&self.buf, ZSTD_LEVEL)?;
        self.buf.clear();
        self.file.write_all(&block)?;
        self.file.sync_data()?;

        let entry = IndexEntry {
            first_ts,
            last_ts,
            block: BlockRef {
                offset: self.end,
                len: (block.len() - BLOCK_HEADER_LEN) as u32,
            },
        };
        self.end += block.len() as u64;
        // The index is derived data; if it can't be written, readers rebuild it.
        if let Some(idx) = &mut self.index
            && idx.write_all(&entry.to_bytes()).is_err()
        {
            self.index = None;
        }
        Ok(())
    }
}

impl Drop for SegmentWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn report_truncation(path: &Path, bytes: u64) {
    // Avoid a logging dependency in the storage crate.
    eprintln!(
        "sysmon-store: truncating {bytes} torn bytes from {}",
        path.display()
    );
}
