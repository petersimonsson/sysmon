use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::{Result, SegmentWriter};

/// Routes datagrams to per-host, per-boot, per-hour segment files.
pub struct Recorder {
    data_dir: PathBuf,
    writers: HashMap<(u64, u128), (u64, SegmentWriter)>,
}

impl Recorder {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            writers: HashMap::new(),
        }
    }

    pub fn append(
        &mut self,
        host_id: u64,
        boot_id: u128,
        recv_ts_ns: u64,
        datagram: &[u8],
    ) -> Result<()> {
        let hour = recv_ts_ns / 3_600_000_000_000;
        let key = (host_id, boot_id);
        let rotate = self.writers.get(&key).is_none_or(|(h, _)| *h != hour);
        if rotate {
            let path = segment_path(&self.data_dir, host_id, boot_id, recv_ts_ns);
            std::fs::create_dir_all(path.parent().unwrap())?;
            // Dropping the old writer flushes it.
            self.writers
                .insert(key, (hour, SegmentWriter::open(&path)?));
        }
        self.writers
            .get_mut(&key)
            .unwrap()
            .1
            .append(recv_ts_ns, datagram)
    }

    pub fn flush(&mut self) -> Result<()> {
        for (_, w) in self.writers.values_mut() {
            w.flush()?;
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_layout() {
        // 2026-11-22T07:21:00Z
        let ts = 1_795_332_060u64 * 1_000_000_000;
        let p = segment_path(Path::new("/d"), 0xab, 0xcd, ts);
        assert_eq!(
            p,
            Path::new("/d/00000000000000ab/000000000000000000000000000000cd/2026-11-22T07.seg")
        );
    }
}
