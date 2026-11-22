//! Marked blocks: which blocks of a segment hold records the writer was told
//! to mark, so they can be found without reading the whole segment. sysmon
//! marks blocks with error log lines, for the timeline.
//!
//! ```text
//! <name>.marks := block_offset:u64le*
//! ```
//!
//! A marks file is created with its segment and appended to after each
//! marked block is written. Marks are hints for readers to check (one left
//! from a crash may point at a block that no longer holds the record), and
//! a segment without a marks file (recorded before marks existed) has to be
//! read in full.

use std::path::{Path, PathBuf};

pub fn marks_path(segment: &Path) -> PathBuf {
    segment.with_extension("marks")
}

/// The offsets of the segment's marked blocks, or `None` if it has no
/// marks file.
pub fn load(segment: &Path) -> Option<Vec<u64>> {
    let bytes = std::fs::read(marks_path(segment)).ok()?;
    let mut offsets: Vec<u64> = bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect();
    offsets.sort_unstable();
    offsets.dedup();
    Some(offsets)
}
