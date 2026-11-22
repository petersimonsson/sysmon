use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::block;
use crate::index::{self, IndexEntry};
use crate::{FILE_HEADER_LEN, Record, Result};

/// Reader over a segment file. Iteration stops at the first incomplete
/// block, which is a crash's torn tail or a block still being written.
pub struct SegmentReader {
    path: PathBuf,
    file: BufReader<File>,
    offset: u64,
    pending: std::vec::IntoIter<Record>,
    skip_before: u64,
    done: bool,
    payload: Vec<u8>,
}

impl SegmentReader {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(path)?);
        block::check_file_header(&mut file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            offset: FILE_HEADER_LEN,
            pending: Vec::new().into_iter(),
            skip_before: 0,
            done: false,
            payload: Vec::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The block index, completed by scanning if the `.idx` file is stale.
    pub fn index(&mut self) -> Result<Vec<IndexEntry>> {
        let entries = index::load(&self.path, &mut self.file)?.entries;
        self.file.seek(SeekFrom::Start(self.offset))?;
        Ok(entries)
    }

    /// First and last receive timestamps in the segment.
    pub fn time_range(&mut self) -> Result<Option<(u64, u64)>> {
        let entries = self.index()?;
        Ok(entries
            .first()
            .zip(entries.last())
            .map(|(f, l)| (f.first_ts, l.last_ts)))
    }

    /// Position the reader so the next record is the first one received at
    /// or after `ts`.
    pub fn seek(&mut self, ts: u64) -> Result<()> {
        let entries = self.index()?;
        self.pending = Vec::new().into_iter();
        self.skip_before = ts;
        match entries.get(index::find(&entries, ts)) {
            Some(e) => {
                self.offset = e.block.offset;
                self.done = false;
            }
            None => {
                self.offset = entries.last().map_or(FILE_HEADER_LEN, |e| e.block.end());
                self.done = true;
            }
        }
        self.file.seek(SeekFrom::Start(self.offset))?;
        Ok(())
    }

    fn next_block(&mut self) -> Result<bool> {
        let Some(b) = block::read_block(&mut self.file, self.offset, &mut self.payload) else {
            // Rewind so a later call can pick up a block that was still being written.
            self.file.seek(SeekFrom::Start(self.offset))?;
            return Ok(false);
        };
        let mut records = Vec::new();
        block::decode_block(&self.payload, b.offset, &mut records)?;
        if self.skip_before > 0 {
            records.retain(|r| r.recv_ts_ns >= self.skip_before);
        }
        self.pending = records.into_iter();
        self.offset = b.end();
        Ok(true)
    }

    /// The records of the block at `offset` (a marked block's), or none if
    /// there's no valid block there.
    pub fn block_at(&mut self, offset: u64) -> Result<Vec<Record>> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut records = Vec::new();
        if let Some(b) = block::read_block(&mut self.file, offset, &mut self.payload) {
            block::decode_block(&self.payload, b.offset, &mut records)?;
        }
        self.file.seek(SeekFrom::Start(self.offset))?;
        Ok(records)
    }

    /// Resume reading after the end was reached, e.g. to follow a segment
    /// that is still being written.
    pub fn resume(&mut self) {
        self.done = false;
    }
}

impl Iterator for SegmentReader {
    type Item = Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(r) = self.pending.next() {
                return Some(Ok(r));
            }
            if self.done {
                return None;
            }
            match self.next_block() {
                Ok(true) => {}
                Ok(false) => {
                    self.done = true;
                    return None;
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            }
        }
    }
}
