use std::path::Path;
use std::time::{Duration, Instant};

use sysmon_ingest::{Assembler, Event};
use sysmon_store::{Record, SegmentInfo, SegmentReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Live,
    Replay,
}

/// Where events come from.
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

/// Events read back from segment files through the same decoder and
/// assembler as live traffic. Every host's segments are merged by receive
/// time, so a multi-host recording replays as it happened.
pub struct ReplaySource {
    streams: Vec<Stream>,
    assembler: Assembler,
    range: Option<(u64, u64)>,
    epoch: Instant,
    pending: std::collections::VecDeque<Event>,
}

/// The segments of one (host, boot), in time order.
struct Stream {
    segments: Vec<(SegmentInfo, (u64, u64))>,
    next_segment: usize,
    reader: Option<SegmentReader>,
    peeked: Option<Record>,
}

impl Stream {
    fn peek(&mut self) -> Option<&Record> {
        while self.peeked.is_none() {
            if self.reader.is_none() {
                let (info, _) = self.segments.get(self.next_segment)?;
                self.next_segment += 1;
                match SegmentReader::open(&info.path) {
                    Ok(r) => self.reader = Some(r),
                    Err(e) => {
                        eprintln!("skipping {}: {e}", info.path.display());
                        continue;
                    }
                }
            }
            match self.reader.as_mut().unwrap().next() {
                Some(Ok(record)) => self.peeked = Some(record),
                Some(Err(e)) => {
                    eprintln!("stopping segment early: {e}");
                    self.reader = None;
                }
                None => self.reader = None,
            }
        }
        self.peeked.as_ref()
    }

    fn seek(&mut self, ts: u64) {
        self.peeked = None;
        self.reader = None;
        // The first segment that has anything at or after `ts`.
        let i = self.segments.partition_point(|(_, (_, last))| *last < ts);
        self.next_segment = i;
        if let Some((info, _)) = self.segments.get(i)
            && let Ok(mut r) = SegmentReader::open(&info.path)
            && r.seek(ts).is_ok()
        {
            self.reader = Some(r);
            self.next_segment = i + 1;
        }
    }
}

impl ReplaySource {
    /// Replay every segment under `path` (a data dir, host dir, boot dir or
    /// single `.seg` file).
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self::new(sysmon_store::list_segments(path)?))
    }

    pub fn new(segments: Vec<SegmentInfo>) -> Self {
        let mut by_stream: std::collections::BTreeMap<(u64, u128), Vec<_>> = Default::default();
        for info in segments {
            let range = SegmentReader::open(&info.path)
                .and_then(|mut r| r.time_range())
                .ok()
                .flatten();
            if let Some(range) = range {
                by_stream
                    .entry((info.host_id, info.boot_id))
                    .or_default()
                    .push((info, range));
            }
        }
        let streams: Vec<Stream> = by_stream
            .into_values()
            .map(|mut segments| {
                segments.sort_by_key(|(_, (first, _))| *first);
                Stream {
                    segments,
                    next_segment: 0,
                    reader: None,
                    peeked: None,
                }
            })
            .collect();
        let range = streams
            .iter()
            .flat_map(|s| s.segments.iter().map(|(_, r)| *r))
            .reduce(|a, b| (a.0.min(b.0), a.1.max(b.1)));
        Self {
            streams,
            assembler: new_assembler(),
            range,
            epoch: Instant::now(),
            pending: Default::default(),
        }
    }

    /// First and last receive timestamps in the recording.
    pub fn time_range(&self) -> Option<(u64, u64)> {
        self.range
    }

    /// Receive timestamp of the next record, without consuming it.
    pub fn peek_ts(&mut self) -> Option<u64> {
        self.streams
            .iter_mut()
            .filter_map(|s| s.peek().map(|r| r.recv_ts_ns))
            .min()
    }

    /// Feed the next record (in receive order across all hosts) through the
    /// assembler. Returns its timestamp, or `None` at the end of the
    /// recording; any resulting events are queued for [`Self::take_events`].
    pub fn step(&mut self) -> Option<u64> {
        let stream = self
            .streams
            .iter_mut()
            .filter_map(|s| s.peek().map(|r| r.recv_ts_ns).map(|ts| (ts, s)))
            .min_by_key(|(ts, _)| *ts)?
            .1;
        let record = stream.peeked.take().unwrap();
        let ts = record.recv_ts_ns;

        // Recorded receive times drive the assembler's timeouts, as they did live.
        let base = self.range.map_or(0, |r| r.0);
        let now = self.epoch + Duration::from_nanos(ts.saturating_sub(base));
        if let Ok((h, m)) = sysmon_proto::decode(&record.datagram) {
            self.assembler.push(h, m, now);
        }
        self.assembler.flush_stale(now);
        self.pending.extend(self.assembler.drain());
        Some(ts)
    }

    /// Emit whatever is still partial. Call at the end of the recording.
    pub fn finish(&mut self) {
        self.assembler
            .flush_stale(self.epoch + Duration::from_secs(1 << 40));
        self.pending.extend(self.assembler.drain());
    }

    pub fn take_events(&mut self) -> impl Iterator<Item = Event> + '_ {
        self.pending.drain(..)
    }

    /// Restart at the first record received at or after `ts`.
    pub fn seek_to(&mut self, ts: u64) {
        for s in &mut self.streams {
            s.seek(ts);
        }
        self.assembler = new_assembler();
        self.pending.clear();
    }

    pub fn host_count(&self) -> usize {
        let mut hosts: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|s| s.segments.first().map(|(i, _)| i.host_id))
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts.len()
    }
}

fn new_assembler() -> Assembler {
    Assembler::new(Duration::from_millis(1500))
}

impl DataSource for ReplaySource {
    /// Unpaced: returns events as fast as they can be read.
    fn next_event(&mut self) -> Option<Event> {
        loop {
            if let Some(e) = self.pending.pop_front() {
                return Some(e);
            }
            if self.step().is_none() {
                self.finish();
                return self.pending.pop_front();
            }
        }
    }

    fn seek(&mut self, ts_unix_ns: u64) {
        self.seek_to(ts_unix_ns);
    }

    fn kind(&self) -> SourceKind {
        SourceKind::Replay
    }
}
