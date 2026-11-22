//! Background threads feeding the UI: ingest plus recorder for live data, and
//! the model's replay engine for recordings.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use sysmon_ingest::{Event, RawDatagram, Sinks};
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

pub fn start_live(
    listen: SocketAddr,
    opener: sysmon_proto::Opener,
    recording: Option<Recording>,
) -> anyhow::Result<(flume::Receiver<Event>, Option<RecorderHandle>)> {
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
    sysmon_ingest::spawn(
        listen,
        opener,
        Sinks {
            events: events_tx,
            raw,
        },
    )
    .with_context(|| format!("listening on {listen}"))?;
    Ok((events_rx, handle))
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
        // The header says which host and boot the datagram belongs to.
        if let Ok((h, _)) = sysmon_proto::decode(&raw.bytes)
            && let Err(e) = recorder.append(h.host_id, h.boot_id, raw.recv_ts_ns, &raw.bytes)
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
            match recorder.flush() {
                Ok(()) => tracing::info!("recording written"),
                Err(e) => tracing::error!(error = %e, "writing the recording failed"),
            }
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
    let _ = recorder.flush();
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
    use super::{Recording, start_live};
    use std::time::Duration;
    use sysmon_model::ReplaySource;

    #[test]
    fn stopping_writes_out_everything_received() {
        let dir = std::env::temp_dir().join(format!("sysmon-ui-stop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // A free port for the receiver.
        let addr = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let (_events, recorder) = start_live(
            addr,
            sysmon_proto::Opener::new(None),
            Some(Recording {
                dir: dir.clone(),
                retention: Default::default(),
            }),
        )
        .unwrap();
        let recorder = recorder.unwrap();

        // Three small samples: far less than a block, so nothing is written
        // until the recorder is stopped.
        let agent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let now = sysmon_ingest::unix_now_ns();
        for seq in 0..3u32 {
            let system = sysmon_proto::SystemSample {
                ts_unix_ns: now + seq as u64 * 1_000_000_000,
                ..Default::default()
            };
            for d in sysmon_proto::encode_sample(1, 2, seq, &system, &[], &[]).unwrap() {
                agent.send_to(&d, addr).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(300));

        recorder.stop(Duration::from_secs(2));
        let mut src = ReplaySource::open(&dir).unwrap();
        let frames = std::iter::from_fn(|| src.next_event())
            .filter(|e| matches!(e, sysmon_ingest::Event::Frame(_)))
            .count();
        assert_eq!(frames, 3, "all samples on disk right after stop()");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
