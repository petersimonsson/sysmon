use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::{BLOCK_HEADER_LEN, Error, FILE_HEADER_LEN, FILE_MAGIC, FILE_VERSION, Result};

/// Flush a block when the uncompressed buffer reaches this size...
const BLOCK_MAX_BYTES: usize = 64 * 1024;
/// ...or when it spans this much time.
const BLOCK_MAX_SPAN_NS: u64 = 10_000_000_000;
const ZSTD_LEVEL: i32 = 3;

/// Append-only writer for one segment file.
pub struct SegmentWriter {
    file: File,
    buf: Vec<u8>,
    block_first_ts: Option<u64>,
}

impl SegmentWriter {
    /// Create a segment, or reopen an existing one, truncating any torn tail
    /// left by a crash.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let len = file.metadata()?.len();
        if len == 0 {
            file.write_all(FILE_MAGIC)?;
            file.write_all(&[FILE_VERSION])?;
        } else {
            let valid = valid_len(&mut file, len)?;
            if valid < len {
                report_truncation(path, len - valid);
                file.set_len(valid)?;
            }
        }
        file.seek(SeekFrom::End(0))?;

        Ok(Self {
            file,
            buf: Vec::with_capacity(BLOCK_MAX_BYTES),
            block_first_ts: None,
        })
    }

    pub fn append(&mut self, recv_ts_ns: u64, datagram: &[u8]) -> Result<()> {
        let len = u16::try_from(datagram.len()).map_err(|_| Error::TooLarge(datagram.len()))?;
        let first = *self.block_first_ts.get_or_insert(recv_ts_ns);

        self.buf.extend_from_slice(&recv_ts_ns.to_le_bytes());
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(datagram);

        if self.buf.len() >= BLOCK_MAX_BYTES
            || recv_ts_ns.saturating_sub(first) >= BLOCK_MAX_SPAN_NS
        {
            self.flush()?;
        }
        Ok(())
    }

    /// Compress and write the pending block, then fsync.
    pub fn flush(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let compressed = zstd::bulk::compress(&self.buf, ZSTD_LEVEL)?;
        let mut block = Vec::with_capacity(BLOCK_HEADER_LEN + compressed.len());
        block.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        block.extend_from_slice(&crc32fast::hash(&compressed).to_le_bytes());
        block.extend_from_slice(&compressed);
        self.file.write_all(&block)?;
        self.file.sync_data()?;

        self.buf.clear();
        self.block_first_ts = None;
        Ok(())
    }
}

impl Drop for SegmentWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Length of the valid prefix of a segment: its header plus every complete,
/// checksummed block.
fn valid_len(file: &mut File, len: u64) -> Result<u64> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; FILE_HEADER_LEN as usize];
    file.read_exact(&mut header)?;
    if &header[..5] != FILE_MAGIC {
        return Err(Error::BadMagic);
    }
    if header[5] != FILE_VERSION {
        return Err(Error::UnsupportedVersion(header[5]));
    }

    let mut pos = FILE_HEADER_LEN;
    let mut payload = Vec::new();
    loop {
        let mut bh = [0u8; BLOCK_HEADER_LEN];
        if pos + BLOCK_HEADER_LEN as u64 > len || file.read_exact(&mut bh).is_err() {
            return Ok(pos);
        }
        let size = u32::from_le_bytes(bh[..4].try_into().unwrap()) as u64;
        let crc = u32::from_le_bytes(bh[4..].try_into().unwrap());
        let end = pos + BLOCK_HEADER_LEN as u64 + size;
        if end > len {
            return Ok(pos);
        }
        payload.resize(size as usize, 0);
        file.read_exact(&mut payload)?;
        if crc32fast::hash(&payload) != crc {
            return Ok(pos);
        }
        pos = end;
    }
}

fn report_truncation(path: &Path, bytes: u64) {
    // Avoid a tracing dependency in the storage crate; callers can surface this.
    eprintln!(
        "sysmon-store: truncating {bytes} torn bytes from {}",
        path.display()
    );
}
