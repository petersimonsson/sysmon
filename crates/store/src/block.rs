//! Reading and writing the block framing shared by the writer, reader and index.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::{BLOCK_HEADER_LEN, Error, FILE_HEADER_LEN, FILE_MAGIC, FILE_VERSION, Record, Result};

/// Location of one block within a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    /// Offset of the block header.
    pub offset: u64,
    /// Length of the compressed payload (excluding the block header).
    pub len: u32,
}

impl BlockRef {
    pub fn end(&self) -> u64 {
        self.offset + BLOCK_HEADER_LEN as u64 + self.len as u64
    }
}

pub fn write_file_header(w: &mut impl Write) -> Result<()> {
    w.write_all(FILE_MAGIC)?;
    w.write_all(&[FILE_VERSION])?;
    Ok(())
}

pub fn check_file_header(r: &mut impl Read) -> Result<()> {
    let mut header = [0u8; FILE_HEADER_LEN as usize];
    r.read_exact(&mut header)?;
    if &header[..5] != FILE_MAGIC {
        return Err(Error::BadMagic);
    }
    if header[5] != FILE_VERSION {
        return Err(Error::UnsupportedVersion(header[5]));
    }
    Ok(())
}

pub fn encode_block(records: &[u8], level: i32) -> Result<Vec<u8>> {
    let compressed = zstd::bulk::compress(records, level)?;
    let mut block = Vec::with_capacity(BLOCK_HEADER_LEN + compressed.len());
    block.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    block.extend_from_slice(&crc32fast::hash(&compressed).to_le_bytes());
    block.extend_from_slice(&compressed);
    Ok(block)
}

/// Read the block at the reader's current position. Returns `None` at the end
/// of the file or at a torn/corrupt block, which is treated as the end.
pub fn read_block<R: Read>(r: &mut R, offset: u64, payload: &mut Vec<u8>) -> Option<BlockRef> {
    let mut bh = [0u8; BLOCK_HEADER_LEN];
    r.read_exact(&mut bh).ok()?;
    let len = u32::from_le_bytes(bh[..4].try_into().unwrap());
    let crc = u32::from_le_bytes(bh[4..].try_into().unwrap());
    // Blocks are at most a few hundred KiB; anything huge is garbage.
    if len > 64 * 1024 * 1024 {
        return None;
    }
    payload.resize(len as usize, 0);
    r.read_exact(payload).ok()?;
    (crc32fast::hash(payload) == crc).then_some(BlockRef { offset, len })
}

pub fn decode_block(payload: &[u8], offset: u64, out: &mut Vec<Record>) -> Result<()> {
    let raw = zstd::stream::decode_all(payload)?;
    let mut buf = &raw[..];
    while !buf.is_empty() {
        let parse = || -> Option<(Record, usize)> {
            let ts = u64::from_le_bytes(buf.get(..8)?.try_into().ok()?);
            let len = u16::from_le_bytes(buf.get(8..10)?.try_into().ok()?) as usize;
            let datagram = buf.get(10..10 + len)?.to_vec();
            Some((
                Record {
                    recv_ts_ns: ts,
                    datagram,
                },
                10 + len,
            ))
        };
        let (record, used) = parse().ok_or(Error::Corrupt(offset))?;
        out.push(record);
        buf = &buf[used..];
    }
    Ok(())
}

/// Visit every valid block from `start` onwards, stopping at the first torn
/// or corrupt one. Returns the offset just past the last valid block.
pub fn scan_blocks<R: Read + Seek>(
    r: &mut R,
    start: u64,
    mut visit: impl FnMut(BlockRef, &[u8]) -> Result<()>,
) -> Result<u64> {
    r.seek(SeekFrom::Start(start))?;
    let mut pos = start;
    let mut payload = Vec::new();
    while let Some(block) = read_block(r, pos, &mut payload) {
        visit(block, &payload)?;
        pos = block.end();
    }
    Ok(pos)
}
