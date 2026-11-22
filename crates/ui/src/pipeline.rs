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

pub fn start_live(
    listen: SocketAddr,
    opener: sysmon_proto::Opener,
    recording: Option<Recording>,
) -> anyhow::Result<flume::Receiver<Event>> {
    let (events_tx, events_rx) = flume::bounded(EVENT_QUEUE);
    let raw = match recording {
        Some(rec) => {
            let (tx, rx) = flume::bounded(RAW_QUEUE);
            std::thread::Builder::new()
                .name("sysmon-recorder".into())
                .spawn(move || record(rec, rx))?;
            Some(tx)
        }
        None => None,
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
    Ok(events_rx)
}

fn record(rec: Recording, rx: flume::Receiver<RawDatagram>) {
    tracing::info!(dir = %rec.dir.display(), ?rec.retention, "recording");
    let mut recorder = Recorder::new(&rec.dir);
    let mut last_flush = Instant::now();
    let mut last_prune: Option<Instant> = None;
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(raw) => {
                // The header says which host and boot the datagram belongs to.
                if let Ok((h, _)) = sysmon_proto::decode(&raw.bytes)
                    && let Err(e) =
                        recorder.append(h.host_id, h.boot_id, raw.recv_ts_ns, &raw.bytes)
                {
                    tracing::error!(error = %e, "recording failed");
                }
            }
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
