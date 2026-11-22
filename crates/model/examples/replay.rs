//! Replay a recording headless and print a summary per frame.
//!
//! cargo run -p sysmon-model --example replay -- <data_dir | segment.seg> [--tree]
//!
//! With `--tree`, prints only the last sample of each host as a process tree.

use sysmon_ingest::Event;
use sysmon_model::{DataSource, HostModel, ReplaySource};

fn main() -> std::io::Result<()> {
    let path = std::path::PathBuf::from(std::env::args().nth(1).expect("usage: replay <path>"));
    let tree = std::env::args().nth(2).as_deref() == Some("--tree");
    let mut source = ReplaySource::open(&path)?;
    let mut hosts = std::collections::HashMap::new();
    while let Some(event) = source.next_event() {
        let host_id = event.host_id();
        let is_frame = matches!(event, Event::Frame(_));
        let host = hosts
            .entry(host_id)
            .or_insert_with(|| HostModel::new(host_id));
        host.apply(event);
        if is_frame && !tree {
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
    if tree {
        for host in hosts.values() {
            let mut rows = host.snapshot.procs.clone();
            rows.sort_by_key(|r| r.key.pid);
            println!("== {} ==", host.name());
            for line in sysmon_model::tree::build(&rows, None, &Default::default()) {
                let r = &rows[line.row];
                println!("{:>7} {:5.1}% {}{}", r.key.pid, r.cpu_pct, line.guides, r.comm);
            }
        }
    }
    Ok(())
}
