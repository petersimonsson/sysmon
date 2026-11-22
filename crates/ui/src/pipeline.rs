//! Background threads feeding the UI: ingest + recorder for live mode, a paced
//! reader for replay mode. Both end in the same `Receiver<Event>`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use sysmon_ingest::{Event, RawDatagram, Sinks};
use sysmon_model::{Feed, ReplaySource};
use sysmon_store::Recorder;

const EVENT_QUEUE: usize = 4096;
const RAW_QUEUE: usize = 16 * 1024;

pub fn start_live(
    listen: SocketAddr,
    data_dir: Option<PathBuf>,
) -> anyhow::Result<flume::Receiver<Event>> {
    let (events_tx, events_rx) = flume::bounded(EVENT_QUEUE);
    let raw = match data_dir {
        Some(dir) => {
            let (tx, rx) = flume::bounded(RAW_QUEUE);
            std::thread::Builder::new()
                .name("sysmon-recorder".into())
                .spawn(move || record(dir, rx))?;
            Some(tx)
        }
        None => None,
    };
    sysmon_ingest::spawn(
        listen,
        Sinks {
            events: events_tx,
            raw,
        },
    )
    .with_context(|| format!("listening on {listen}"))?;
    Ok(events_rx)
}

fn record(dir: PathBuf, rx: flume::Receiver<RawDatagram>) {
    tracing::info!(dir = %dir.display(), "recording");
    let mut recorder = Recorder::new(dir);
    let mut last_flush = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(raw) => {
                // Only record our own traffic; the header says where it belongs.
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
        if last_flush.elapsed() >= Duration::from_secs(10) {
            if let Err(e) = recorder.maintain(sysmon_ingest::unix_now_ns()) {
                tracing::error!(error = %e, "flushing recording failed");
            }
            last_flush = Instant::now();
        }
    }
    let _ = recorder.flush();
}

pub fn start_replay(path: &Path, speed: f64) -> anyhow::Result<flume::Receiver<Event>> {
    let source = ReplaySource::open(path).with_context(|| format!("reading {}", path.display()))?;
    let handle = sysmon_model::replay::spawn(source, speed)?;
    let (tx, rx) = flume::bounded(EVENT_QUEUE);
    std::thread::spawn(move || {
        for feed in handle.feed.iter() {
            if let Feed::Event(e) = feed
                && tx.send(e).is_err()
            {
                return;
            }
        }
    });
    Ok(rx)
}
