//! Background threads feeding the UI: ingest plus recorder for live data, and
//! the model's replay engine for recordings.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use sysmon_ingest::{Event, RawDatagram, Rejections, Sinks};
use sysmon_model::{ReplayHandle, ReplaySource};
use sysmon_store::{Recorder, Retention};

const EVENT_QUEUE: usize = 4096;
const RAW_QUEUE: usize = 16 * 1024;
const FLUSH_EVERY: Duration = Duration::from_secs(10);
const PRUNE_EVERY: Duration = Duration::from_secs(600);

pub struct Recording {
    pub dir: PathBuf,
    pub retention: Retention,
}

/// Stops the recorder, writing out whatever it has buffered. Cheap to clone.
#[derive(Clone)]
pub struct RecorderHandle {
    stop: flume::Sender<flume::Sender<()>>,
}

impl RecorderHandle {
    /// Write everything received so far to disk and stop recording. Returns
    /// once that's done (or after `timeout`, if the disk is stuck).
    pub fn stop(&self, timeout: Duration) {
        let (done_tx, done_rx) = flume::bounded(1);
        if self.stop.send(done_tx).is_ok() {
            let _ = done_rx.recv_timeout(timeout);
        }
    }
}

/// What the UI gets from a running receiver.
pub struct Live {
    pub events: flume::Receiver<Event>,
    /// The address it listens on, to tell agents where to send.
    pub listen: SocketAddr,
    /// Whether it only accepts data encrypted with a key.
    pub keyed: bool,
    /// Datagrams it turned away, to say why an agent isn't showing up.
    pub rejections: Arc<Rejections>,
}

pub fn start_live(
    listen: SocketAddr,
    opener: sysmon_proto::Opener,
    recording: Option<Recording>,
) -> anyhow::Result<(Live, Option<RecorderHandle>)> {
    let (events_tx, events_rx) = flume::bounded(EVENT_QUEUE);
    let (raw, handle) = match recording {
        Some(rec) => {
            let (tx, rx) = flume::bounded(RAW_QUEUE);
            let (stop, stop_rx) = flume::bounded(1);
            std::thread::Builder::new()
                .name("sysmon-recorder".into())
                .spawn(move || record(rec, rx, stop_rx))?;
            (Some(tx), Some(RecorderHandle { stop }))
        }
        None => (None, None),
    };
    let rejections = Arc::new(Rejections::default());
    let keyed = opener.has_key();
    sysmon_ingest::spawn(
        listen,
        opener,
        Sinks {
            events: events_tx,
            raw,
            rejections: rejections.clone(),
        },
    )
    .with_context(|| format!("listening on {listen}"))?;
    let live = Live {
        events: events_rx,
        listen,
        keyed,
        rejections,
    };
    Ok((live, handle))
}

fn record(
    rec: Recording,
    rx: flume::Receiver<RawDatagram>,
    stop: flume::Receiver<flume::Sender<()>>,
) {
    tracing::info!(dir = %rec.dir.display(), ?rec.retention, "recording");
    let mut recorder = Recorder::new(&rec.dir);
    let mut last_flush = Instant::now();
    let mut last_prune: Option<Instant> = None;
    let append = |recorder: &mut Recorder, raw: RawDatagram| {
        // Stored decompressed: blocks of plain datagrams compress together
        // to about half the size of datagrams the agent compressed one by
        // one (11 vs 20 MB per host-hour). Decoding needs it anyway.
        let Ok(plain) = sysmon_proto::seal::decompressed(&raw.bytes) else {
            return;
        };
        // The header says which host and boot the datagram belongs to.
        // Blocks with error log lines are marked, so opening a recording
        // finds them for the timeline without reading all of it.
        if let Ok((h, msg)) = sysmon_proto::decode(&plain)
            && let Err(e) = recorder.append_marked(
                h.host_id,
                h.boot_id,
                raw.recv_ts_ns,
                &plain,
                sysmon_model::logs::has_errors(&msg),
            )
        {
            tracing::error!(error = %e, "recording failed");
        }
    };
    loop {
        if let Ok(done) = stop.try_recv() {
            // Take what's already queued, then write it all out.
            for raw in rx.try_iter() {
                append(&mut recorder, raw);
            }
            write_out(&mut recorder);
            let _ = done.send(());
            return;
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(raw) => append(&mut recorder, raw),
            Err(flume::RecvTimeoutError::Timeout) => {}
            Err(flume::RecvTimeoutError::Disconnected) => break,
        }
        if last_flush.elapsed() >= FLUSH_EVERY {
            if let Err(e) = recorder.maintain(sysmon_ingest::unix_now_ns()) {
                tracing::error!(error = %e, "flushing recording failed");
            }
            last_flush = Instant::now();
        }
        let has_policy = rec.retention.max_age.is_some() || rec.retention.max_bytes.is_some();
        if has_policy && last_prune.is_none_or(|t| t.elapsed() >= PRUNE_EVERY) {
            match sysmon_store::prune(&rec.dir, &rec.retention, sysmon_ingest::unix_now_ns()) {
                Ok(r) if r.removed_segments > 0 => tracing::info!(
                    removed = r.removed_segments,
                    freed_bytes = r.removed_bytes,
                    kept_bytes = r.kept_bytes,
                    "pruned recordings"
                ),
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "pruning recordings failed"),
            }
            last_prune = Some(Instant::now());
        }
    }
    write_out(&mut recorder);
}

/// Write out what the recorder still holds, saying whether that worked.
fn write_out(recorder: &mut Recorder) {
    match recorder.flush() {
        Ok(()) => tracing::info!("recording written"),
        Err(e) => tracing::error!(error = %e, "writing the recording failed"),
    }
}

/// Open a recording and start playing it.
pub fn open_replay(path: &Path, speed: f64) -> anyhow::Result<ReplayHandle> {
    let source = ReplaySource::open(path).with_context(|| format!("reading {}", path.display()))?;
    if source.time_range().is_none() {
        anyhow::bail!("no recorded data under {}", path.display());
    }
    Ok(sysmon_model::replay::spawn(source, speed)?)
}

#[cfg(test)]
mod tests {
    // Explicit imports: the gpui glob elsewhere would shadow `#[test]`.
    use super::{RecorderHandle, Recording, start_live};
    use std::net::{SocketAddr, UdpSocket};
    use std::path::PathBuf;
    use std::time::Duration;
    use sysmon_ingest::Event;
    use sysmon_model::ReplaySource;

    /// A receiver recording to its own directory, and an agent's socket to
    /// send it datagrams. The directory goes when it's dropped.
    struct Rig {
        dir: PathBuf,
        addr: SocketAddr,
        agent: UdpSocket,
        recorder: RecorderHandle,
        _live: super::Live,
    }

    impl Rig {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("sysmon-ui-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            // A free port for the receiver.
            let addr = UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let (live, recorder) = start_live(
                addr,
                sysmon_proto::Opener::new(None),
                Some(Recording {
                    dir: dir.clone(),
                    retention: Default::default(),
                }),
            )
            .unwrap();
            Self {
                dir,
                addr,
                agent: UdpSocket::bind("127.0.0.1:0").unwrap(),
                recorder: recorder.unwrap(),
                _live: live,
            }
        }

        fn send<D: AsRef<[u8]>>(&self, datagrams: impl IntoIterator<Item = D>) {
            for d in datagrams {
                self.agent.send_to(d.as_ref(), self.addr).unwrap();
            }
        }

        /// Give the receiver time to take what was sent, then stop recording.
        fn stop(&self) {
            std::thread::sleep(Duration::from_millis(300));
            self.recorder.stop(Duration::from_secs(2));
        }

        fn first_segment(&self) -> PathBuf {
            sysmon_store::list_segments(&self.dir).unwrap()[0]
                .path
                .clone()
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn stopping_writes_out_everything_received() {
        let rig = Rig::new("stop");
        // Three small samples: far less than a block, so nothing is written
        // until the recorder is stopped.
        let now = sysmon_ingest::unix_now_ns();
        for seq in 0..3u32 {
            let system = sysmon_proto::SystemSample {
                ts_unix_ns: now + seq as u64 * 1_000_000_000,
                ..Default::default()
            };
            rig.send(sysmon_proto::encode_sample(1, 2, seq, &system, &[], &[]).unwrap());
        }
        rig.stop();
        let mut src = ReplaySource::open(&rig.dir).unwrap();
        let frames = std::iter::from_fn(|| src.next_event())
            .filter(|e| matches!(e, Event::Frame(_)))
            .count();
        assert_eq!(frames, 3, "all samples on disk right after stop()");
    }

    #[test]
    fn compressed_datagrams_are_recorded_decompressed() {
        let rig = Rig::new("plain");
        let sealer = sysmon_proto::Sealer::new(None, true);
        let system = sysmon_proto::SystemSample {
            ts_unix_ns: 1,
            cpus: vec![sysmon_proto::CpuCounters::default(); 32],
            ..Default::default()
        };
        let sent: Vec<Vec<u8>> = sysmon_proto::encode_sample(1, 2, 0, &system, &[], &[])
            .unwrap()
            .into_iter()
            .map(|d| sealer.seal(d).unwrap())
            .collect();
        assert!(
            sent.iter()
                .all(|d| d[3] & sysmon_proto::flags::COMPRESSED != 0)
        );
        rig.send(&sent);
        rig.stop();

        let stored: Vec<_> = sysmon_store::SegmentReader::open(&rig.first_segment())
            .unwrap()
            .map(|r| r.unwrap().datagram)
            .collect();
        assert_eq!(stored.len(), sent.len());
        for (s, d) in stored.iter().zip(&sent) {
            assert_eq!(s[3] & sysmon_proto::flags::COMPRESSED, 0, "stored plain");
            assert_eq!(
                sysmon_proto::decode(s).unwrap(),
                sysmon_proto::decode(d).unwrap()
            );
        }
    }

    #[test]
    fn error_log_lines_are_marked_as_they_are_recorded() {
        let rig = Rig::new("marks");
        let line = |first_seq, priority| sysmon_proto::LogBatch {
            run: 1,
            first_seq,
            dropped: 0,
            entries: vec![sysmon_proto::LogEntry {
                ts_unix_ns: 1,
                priority,
                unit: None,
                ident: "t".into(),
                pid: None,
                message: "m".into(),
                truncated: false,
            }],
        };
        for (seq, priority) in [(0, 4), (1, 3)] {
            rig.send(sysmon_proto::encode_logs(1, 2, 0, &line(seq, priority)).unwrap());
        }
        rig.stop();
        let seg = rig.first_segment();
        assert_eq!(sysmon_store::marks::load(&seg).map(|m| m.len()), Some(1));
        assert_eq!(
            sysmon_model::logs::error_marks(&rig.dir).unwrap().len(),
            1,
            "the err line"
        );
    }
}
