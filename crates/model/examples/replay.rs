//! Replay a recording headless and print a summary per frame.
//!
//! cargo run -p sysmon-model --example replay -- <data_dir | segment.seg>

use sysmon_ingest::Event;
use sysmon_model::{DataSource, HostModel, ReplaySource};

fn main() -> std::io::Result<()> {
    let path = std::path::PathBuf::from(std::env::args().nth(1).expect("usage: replay <path>"));
    let mut source = if path.is_dir() {
        ReplaySource::from_dir(&path)?
    } else {
        ReplaySource::new(vec![path])
    };
    let mut hosts = std::collections::HashMap::new();
    while let Some(event) = source.next_event() {
        let host_id = match &event {
            Event::Frame(f) => f.host_id,
            Event::HostInfo { host_id, .. } | Event::ProcMeta { host_id, .. } => *host_id,
        };
        let is_frame = matches!(event, Event::Frame(_));
        let host = hosts
            .entry(host_id)
            .or_insert_with(|| HostModel::new(host_id));
        host.apply(event);
        if is_frame {
            let s = &host.snapshot;
            let top = s
                .procs
                .iter()
                .max_by(|a, b| a.cpu_pct.total_cmp(&b.cpu_pct));
            println!(
                "{host_id:016x} ts {} cpu {:5.1}% procs {:4} top {:?}",
                s.ts_unix_ns,
                s.cpu_pct.first().copied().unwrap_or(0.0),
                s.procs.len(),
                top.map(|p| (&p.comm, p.cpu_pct)),
            );
        }
    }
    Ok(())
}
