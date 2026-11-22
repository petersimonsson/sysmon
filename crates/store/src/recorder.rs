use std::collections::HashMap;
use std::path::PathBuf;

use crate::catalog::{HOUR_NS, segment_path};
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

    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    pub fn append(
        &mut self,
        host_id: u64,
        boot_id: u128,
        recv_ts_ns: u64,
        datagram: &[u8],
    ) -> Result<()> {
        let hour = recv_ts_ns / HOUR_NS;
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

    /// Flush every open segment, and close those for hours before `now_ns`'s,
    /// which will receive no more data.
    pub fn maintain(&mut self, now_ns: u64) -> Result<()> {
        let current = now_ns / HOUR_NS;
        for (_, w) in self.writers.values_mut() {
            w.flush()?;
        }
        self.writers.retain(|_, (hour, _)| *hour >= current);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        for (_, w) in self.writers.values_mut() {
            w.flush()?;
        }
        Ok(())
    }
}
