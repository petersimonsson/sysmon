use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::{
    BLOCK_HEADER_LEN, Error, FILE_HEADER_LEN, FILE_MAGIC, FILE_VERSION, Record, Result,
    parse_records,
};

/// Sequential reader over a segment file. Iteration stops at the first
/// incomplete block, which is a crash's torn tail or a block still being
/// written.
pub struct SegmentReader {
    file: BufReader<File>,
    offset: u64,
    pending: std::vec::IntoIter<Record>,
    done: bool,
}

impl SegmentReader {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(path)?);
        let mut header = [0u8; FILE_HEADER_LEN as usize];
        file.read_exact(&mut header)?;
        if &header[..5] != FILE_MAGIC {
            return Err(Error::BadMagic);
        }
        if header[5] != FILE_VERSION {
            return Err(Error::UnsupportedVersion(header[5]));
        }
        Ok(Self {
            file,
            offset: FILE_HEADER_LEN,
            pending: Vec::new().into_iter(),
            done: false,
        })
    }

    fn next_block(&mut self) -> Result<Option<Vec<Record>>> {
        let mut bh = [0u8; BLOCK_HEADER_LEN];
        if self.file.read_exact(&mut bh).is_err() {
            return Ok(None);
        }
        let size = u32::from_le_bytes(bh[..4].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(bh[4..].try_into().unwrap());
        let mut payload = vec![0u8; size];
        if self.file.read_exact(&mut payload).is_err() || crc32fast::hash(&payload) != crc {
            return Ok(None);
        }
        let raw = zstd::stream::decode_all(&payload[..])?;
        let mut records = Vec::new();
        parse_records(&raw, &mut records).ok_or(Error::Corrupt(self.offset))?;
        self.offset += (BLOCK_HEADER_LEN + size) as u64;
        Ok(Some(records))
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
                Ok(Some(records)) => self.pending = records.into_iter(),
                Ok(None) => {
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
