//! Deleting old recordings.

use std::path::Path;
use std::time::Duration;

use crate::catalog::{HOUR_NS, list_segments};
use crate::index::index_path;

#[derive(Debug, Clone, Copy, Default)]
pub struct Retention {
    /// Delete segments whose hour ended longer ago than this.
    pub max_age: Option<Duration>,
    /// Delete the oldest segments until the total is at most this many bytes.
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub removed_segments: usize,
    pub removed_bytes: u64,
    pub kept_bytes: u64,
}

/// Apply `policy` to everything under `data_dir`. Segments for the current
/// hour are never removed, since they may still be open for writing.
pub fn prune(data_dir: &Path, policy: &Retention, now_ns: u64) -> std::io::Result<PruneReport> {
    if !data_dir.exists() {
        return Ok(PruneReport::default());
    }
    let current_hour = now_ns / HOUR_NS * HOUR_NS;
    let mut segments: Vec<_> = list_segments(data_dir)?
        .into_iter()
        .map(|s| {
            let size = file_len(&s.path) + file_len(&index_path(&s.path));
            (s, size)
        })
        .collect();
    segments.sort_by_key(|(s, _)| s.hour_start_ns);

    let mut report = PruneReport {
        kept_bytes: segments.iter().map(|(_, size)| size).sum(),
        ..Default::default()
    };
    let age_cutoff = policy
        .max_age
        .map(|age| now_ns.saturating_sub(age.as_nanos() as u64));

    for (seg, size) in &segments {
        if seg.hour_start_ns >= current_hour {
            continue;
        }
        let too_old = age_cutoff.is_some_and(|cut| seg.hour_start_ns + HOUR_NS <= cut);
        let too_big = policy.max_bytes.is_some_and(|max| report.kept_bytes > max);
        if !(too_old || too_big) {
            continue;
        }
        std::fs::remove_file(&seg.path)?;
        let _ = std::fs::remove_file(index_path(&seg.path));
        report.removed_segments += 1;
        report.removed_bytes += size;
        report.kept_bytes -= size;

        // Tidy up the boot and host directories once they are empty.
        let mut dir = seg.path.parent();
        while let Some(d) = dir {
            if d == data_dir || std::fs::remove_dir(d).is_err() {
                break;
            }
            dir = d.parent();
        }
    }
    Ok(report)
}

fn file_len(p: &Path) -> u64 {
    std::fs::metadata(p).map_or(0, |m| m.len())
}
