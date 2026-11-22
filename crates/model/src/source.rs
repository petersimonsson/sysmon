use std::path::PathBuf;
use std::time::{Duration, Instant};

use sysmon_ingest::{Assembler, Event};
use sysmon_store::SegmentReader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Live,
    Replay,
}

/// Where events come from. The UI drains a source without knowing which kind it is.
pub trait DataSource: Send {
    /// The next event, if one is available now. `None` means "nothing yet"
    /// for a live source and "end of recording" for a replay source.
    fn next_event(&mut self) -> Option<Event>;
    /// Jump to a time. A no-op for live sources.
    fn seek(&mut self, _ts_unix_ns: u64) {}
    fn kind(&self) -> SourceKind;
}

/// Events arriving from [`sysmon_ingest::spawn`].
pub struct LiveSource {
    rx: flume::Receiver<Event>,
}

impl LiveSource {
    pub fn new(rx: flume::Receiver<Event>) -> Self {
        Self { rx }
    }

    /// Access to the channel, for async draining (`recv_async`).
    pub fn receiver(&self) -> &flume::Receiver<Event> {
        &self.rx
    }
}

impl DataSource for LiveSource {
    fn next_event(&mut self) -> Option<Event> {
        self.rx.try_recv().ok()
    }

    fn kind(&self) -> SourceKind {
        SourceKind::Live
    }
}

/// Events read back from segment files, through the same decoder and
/// assembler as live traffic.
///
/// TODO: pacing by a playback clock (speed, pause), index-based seek, and
/// interleaving several hosts' segments by timestamp.
pub struct ReplaySource {
    segments: std::vec::IntoIter<PathBuf>,
    reader: Option<SegmentReader>,
    assembler: Assembler,
    epoch: Instant,
    pending: std::collections::VecDeque<Event>,
}

impl ReplaySource {
    /// Replay the given segment files in order.
    pub fn new(mut segments: Vec<PathBuf>) -> Self {
        segments.sort();
        Self {
            segments: segments.into_iter(),
            reader: None,
            assembler: Assembler::new(Duration::from_millis(1500)),
            epoch: Instant::now(),
            pending: Default::default(),
        }
    }

    /// Find every segment file under a directory, recursively.
    pub fn from_dir(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let mut found = Vec::new();
        let mut stack = vec![dir.into()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(d)? {
                let path = entry?.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "seg") {
                    found.push(path);
                }
            }
        }
        Ok(Self::new(found))
    }

    fn fill(&mut self) -> bool {
        loop {
            if self.reader.is_none() {
                let Some(path) = self.segments.next() else {
                    return false;
                };
                match SegmentReader::open(&path) {
                    Ok(r) => self.reader = Some(r),
                    Err(e) => {
                        eprintln!("skipping {}: {e}", path.display());
                        continue;
                    }
                }
            }
            match self.reader.as_mut().unwrap().next() {
                Some(Ok(record)) => {
                    // Map recorded receive times onto a synthetic clock so the
                    // assembler's timeouts behave as they did live.
                    let now = self.epoch + Duration::from_nanos(record.recv_ts_ns);
                    if let Ok((h, m)) = sysmon_proto::decode(&record.datagram) {
                        self.assembler.push(h, m, now);
                        self.assembler.flush_stale(now);
                    }
                    self.pending.extend(self.assembler.drain());
                    if !self.pending.is_empty() {
                        return true;
                    }
                }
                Some(Err(e)) => {
                    eprintln!("stopping segment early: {e}");
                    self.reader = None;
                }
                None => self.reader = None,
            }
        }
    }
}

impl DataSource for ReplaySource {
    fn next_event(&mut self) -> Option<Event> {
        if self.pending.is_empty() && !self.fill() {
            // End of data: emit whatever is still partial.
            self.assembler
                .flush_stale(Instant::now() + Duration::from_secs(1 << 40));
            self.pending.extend(self.assembler.drain());
        }
        self.pending.pop_front()
    }

    fn kind(&self) -> SourceKind {
        SourceKind::Replay
    }
}
