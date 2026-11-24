//! What recordings a data directory holds: one entry per (host, boot), with
//! the machine's name, the time it covers and the gaps in it.

use std::path::{Path, PathBuf};

use sysmon_proto::Msg;
use sysmon_store::{SegmentInfo, SegmentReader};

/// Silences longer than this between stored blocks count as gaps (the
/// monitor wasn't running, or the host wasn't reachable). Blocks are written
/// about every 10 s, so shorter silences are just a quiet stretch.
pub const GAP_NS: u64 = 60_000_000_000;

/// One boot of one host, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    pub host_id: u64,
    /// From the newest `HostInfo` found, if any.
    pub hostname: Option<String>,
    pub boot_id: u128,
    /// The boot's directory, which replay opens as is.
    pub path: PathBuf,
    /// Receive times, nanoseconds since the Unix epoch: each stretch of
    /// recorded data, in order, with the gaps between them left out.
    pub spans: Vec<(u64, u64)>,
    pub segments: usize,
    pub bytes: u64,
}

impl Recording {
    pub fn start_ns(&self) -> u64 {
        self.spans.first().map_or(0, |s| s.0)
    }

    pub fn end_ns(&self) -> u64 {
        self.spans.last().map_or(0, |s| s.1)
    }

    /// Time between the stretches.
    pub fn missing_ns(&self) -> u64 {
        self.spans.windows(2).map(|w| w[1].0 - w[0].1).sum()
    }

    /// The host's name, or its id when no `HostInfo` was found.
    pub fn name(&self) -> String {
        self.hostname
            .clone()
            .unwrap_or_else(|| format!("{:016x}", self.host_id))
    }
}

/// Every recording under `dir`, newest first. Reads each segment's index
/// (rebuilding a stale one by scanning, as opening a replay does) and one
/// block for the host's name. Segments that can't be read are left out.
pub fn scan(dir: &Path) -> std::io::Result<Vec<Recording>> {
    let mut by_boot: std::collections::BTreeMap<(u64, u128), Vec<SegmentInfo>> = Default::default();
    for info in sysmon_store::list_segments(dir)? {
        by_boot
            .entry((info.host_id, info.boot_id))
            .or_default()
            .push(info);
    }
    let mut found: Vec<Recording> = by_boot
        .into_iter()
        .filter_map(|((host_id, boot_id), segs)| summarize(host_id, boot_id, &segs))
        .collect();
    found.sort_by_key(|r| std::cmp::Reverse(r.end_ns()));
    Ok(found)
}

fn summarize(host_id: u64, boot_id: u128, segs: &[SegmentInfo]) -> Option<Recording> {
    let mut spans: Vec<(u64, u64)> = Vec::new();
    let mut bytes = 0;
    let mut segments = 0;
    // The newest segment with data, for the host's name.
    let mut newest: Option<(&Path, u64)> = None;
    // `list_segments` sorts by hour, so blocks come in time order.
    for seg in segs {
        let Ok(entries) = SegmentReader::open(&seg.path).and_then(|mut r| r.index()) else {
            continue;
        };
        if entries.is_empty() {
            continue;
        }
        segments += 1;
        bytes += std::fs::metadata(&seg.path).map_or(0, |m| m.len());
        for e in &entries {
            match spans.last_mut() {
                Some(last) if e.first_ts <= last.1.saturating_add(GAP_NS) => {
                    last.1 = last.1.max(e.last_ts);
                }
                _ => spans.push((e.first_ts, e.last_ts)),
            }
        }
        newest = Some((&seg.path, entries.last().unwrap().block.offset));
    }
    let (path, last_block) = newest?;
    let hostname = hostname_in(path, last_block).or_else(|| {
        // An old segment from before the name was sent with every sample.
        segs.iter()
            .find_map(|s| hostname_in(&s.path, sysmon_store::FILE_HEADER_LEN))
    });
    Some(Recording {
        host_id,
        hostname,
        boot_id,
        path: segs[0].path.parent().unwrap_or(&segs[0].path).to_path_buf(),
        spans,
        segments,
        bytes,
    })
}

/// The last host name in the block at `offset` of a segment.
fn hostname_in(path: &Path, offset: u64) -> Option<String> {
    let records = SegmentReader::open(path).ok()?.block_at(offset).ok()?;
    records
        .iter()
        .rev()
        .find_map(|r| match sysmon_proto::decode(&r.datagram) {
            Ok((_, Msg::HostInfo(info))) => Some(info.hostname),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysmon_proto::{Header, HostInfo};

    const SEC: u64 = 1_000_000_000;
    const BASE: u64 = 1_795_330_800 * SEC; // 2026-11-22T07:00Z

    fn tmp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sysmon-catalog-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn host_info(host_id: u64, boot_id: u128, name: &str) -> Vec<u8> {
        let header = Header {
            host_id,
            boot_id,
            seq: 0,
            chunk: 0,
            chunks: 1,
        };
        let info = HostInfo {
            hostname: name.into(),
            kernel: "6.0".into(),
            cpu_count: 1,
            mem_total_kib: 1,
            clk_tck: 100,
            page_size: 4096,
            interval_ms: 1000,
            sends_threads: false,
        };
        sysmon_proto::encode(&header, &Msg::HostInfo(info)).unwrap()
    }

    #[test]
    fn lists_boots_with_names_spans_and_gaps() {
        let dir = tmp_dir("scan");
        let mut rec = sysmon_store::Recorder::new(&dir);
        // Host 1, boot 10: 07:00–07:05, then nothing until 08:30–08:31,
        // renamed meanwhile.
        for s in 0..300 {
            rec.append(1, 10, BASE + s * SEC, &host_info(1, 10, "old"))
                .unwrap();
        }
        rec.flush().unwrap();
        let later = BASE + 90 * 60 * SEC;
        for s in 0..60 {
            rec.append(1, 10, later + s * SEC, &host_info(1, 10, "web1"))
                .unwrap();
        }
        // Host 2, boot 20: one minute at 07:10, without any HostInfo.
        for s in 0..60 {
            rec.append(2, 20, BASE + (600 + s) * SEC, b"not a datagram")
                .unwrap();
        }
        drop(rec);

        let found = scan(&dir).unwrap();
        assert_eq!(found.len(), 2);
        let web = &found[0];
        assert_eq!((web.host_id, web.boot_id), (1, 10));
        assert_eq!(web.hostname.as_deref(), Some("web1"), "newest name wins");
        assert_eq!(web.segments, 2);
        assert_eq!(
            web.spans,
            [(BASE, BASE + 299 * SEC), (later, later + 59 * SEC)]
        );
        assert_eq!(web.missing_ns(), later - (BASE + 299 * SEC));
        assert_eq!(web.path, dir.join(format!("{:016x}/{:032x}", 1, 10)));
        assert!(web.bytes > 0);

        let other = &found[1];
        assert_eq!(other.hostname, None);
        assert_eq!(other.name(), "0000000000000002");
        assert_eq!(other.spans, [(BASE + 600 * SEC, BASE + 659 * SEC)]);
        assert_eq!(other.missing_ns(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_and_empty_segments_are_left_out() {
        let dir = tmp_dir("bad");
        let boot = dir.join(format!("{:016x}/{:032x}", 3, 4));
        std::fs::create_dir_all(&boot).unwrap();
        std::fs::write(boot.join("2026-11-22T07.seg"), b"garbage").unwrap();
        drop(sysmon_store::SegmentWriter::open(&boot.join("2026-11-22T08.seg")).unwrap());
        assert!(scan(&dir).unwrap().is_empty());
        assert!(scan(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
