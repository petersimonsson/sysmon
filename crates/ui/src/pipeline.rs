//! Background threads feeding the UI: ingest + recorder for live mode, a paced
//! reader for replay mode. Both end in the same `Receiver<Event>`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use sysmon_ingest::{Event, RawDatagram, Sinks};
use sysmon_model::{DataSource, ReplaySource};
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
            if let Err(e) = recorder.flush() {
                tracing::error!(error = %e, "flushing recording failed");
            }
            last_flush = Instant::now();
        }
    }
    let _ = recorder.flush();
}

pub fn start_replay(path: &Path, speed: f64) -> anyhow::Result<flume::Receiver<Event>> {
    let mut source = if path.is_dir() {
        ReplaySource::from_dir(path).with_context(|| format!("reading {}", path.display()))?
    } else {
        ReplaySource::new(vec![path.to_path_buf()])
    };
    let speed = if speed > 0.0 { speed } else { 1.0 };
    let (tx, rx) = flume::bounded(EVENT_QUEUE);

    // TODO: move pacing into sysmon-model's PlaybackClock, with pause and seek.
    std::thread::Builder::new()
        .name("sysmon-replay".into())
        .spawn(move || {
            let mut last_ts: Option<u64> = None;
            while let Some(event) = source.next_event() {
                if let Event::Frame(f) = &event
                    && let Some(s) = &f.system
                {
                    if let Some(prev) = last_ts {
                        let gap = s.ts_unix_ns.saturating_sub(prev) as f64 / 1e9 / speed;
                        std::thread::sleep(Duration::from_secs_f64(gap.min(2.0)));
                    }
                    last_ts = Some(s.ts_unix_ns);
                }
                if tx.send(event).is_err() {
                    return;
                }
            }
            tracing::info!("end of recording");
        })?;
    Ok(rx)
}
