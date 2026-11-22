//! Discovering recordings on disk.

use std::path::{Path, PathBuf};

pub const HOUR_NS: u64 = 3_600_000_000_000;

/// A segment file and what its location says about it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SegmentInfo {
    pub host_id: u64,
    pub boot_id: u128,
    /// Start of the hour the segment covers (UTC), from its file name.
    pub hour_start_ns: u64,
    pub path: PathBuf,
}

/// `<data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.seg`, in UTC.
pub fn segment_path(data_dir: &Path, host_id: u64, boot_id: u128, ts_ns: u64) -> PathBuf {
    let secs = ts_ns / 1_000_000_000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let h = (secs % 86_400) / 3_600;
    data_dir
        .join(format!("{host_id:016x}"))
        .join(format!("{boot_id:032x}"))
        .join(format!("{y:04}-{m:02}-{d:02}T{h:02}.seg"))
}

/// Parse a segment path laid out by [`segment_path`]. Files elsewhere get
/// zero ids and an hour of 0 if their names don't follow the layout.
pub fn parse_segment_path(path: &Path) -> SegmentInfo {
    let hour_start_ns = path
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(parse_hour)
        .unwrap_or(0);
    let boot_dir = path.parent();
    let boot_id = boot_dir
        .and_then(|p| p.file_name()?.to_str())
        .and_then(|s| u128::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let host_id = boot_dir
        .and_then(|p| p.parent()?.file_name()?.to_str())
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    SegmentInfo {
        host_id,
        boot_id,
        hour_start_ns,
        path: path.to_path_buf(),
    }
}

/// Every `.seg` file under `path` (or `path` itself if it is a file), sorted
/// by host, boot and hour.
pub fn list_segments(path: &Path) -> std::io::Result<Vec<SegmentInfo>> {
    let mut found = Vec::new();
    if path.is_file() {
        found.push(parse_segment_path(path));
        return Ok(found);
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "seg") {
                found.push(parse_segment_path(&p));
            }
        }
    }
    found.sort();
    Ok(found)
}

/// `YYYY-MM-DDTHH` to nanoseconds since the epoch.
fn parse_hour(s: &str) -> Option<u64> {
    let (date, hour) = s.split_once('T')?;
    let mut parts = date.splitn(3, '-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    let h: u64 = hour.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 {
        return None;
    }
    let days = u64::try_from(days_from_civil(y, m, d)).ok()?;
    Some((days * 86_400 + h * 3_600) * 1_000_000_000)
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// (year, month, day) to days since 1970-01-01. Howard Hinnant's algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_layout_round_trips() {
        // 2026-11-22T07:21:00Z
        let ts = 1_795_332_060u64 * 1_000_000_000;
        let p = segment_path(Path::new("/d"), 0xab, 0xcd, ts);
        assert_eq!(
            p,
            Path::new("/d/00000000000000ab/000000000000000000000000000000cd/2026-11-22T07.seg")
        );
        let info = parse_segment_path(&p);
        assert_eq!((info.host_id, info.boot_id), (0xab, 0xcd));
        assert_eq!(info.hour_start_ns, ts - 21 * 60 * 1_000_000_000);
    }

    #[test]
    fn civil_round_trip() {
        for days in [-1000, 0, 59, 60, 365, 11_016, 20_414, 100_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
