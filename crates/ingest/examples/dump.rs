//! Print everything received on a UDP port.
//!
//! cargo run -p sysmon-ingest --example dump -- 0.0.0.0:9876

fn main() -> anyhow::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:9876".into())
        .parse()?;
    let (tx, rx) = flume::bounded(1024);
    sysmon_ingest::spawn(
        addr,
        sysmon_ingest::Sinks {
            events: tx,
            raw: None,
        },
    )?;
    for event in rx {
        match event {
            sysmon_ingest::Event::Frame(f) => println!(
                "host {:016x} seq {:>6} procs {:>4} complete {}",
                f.host_id,
                f.seq,
                f.procs.len(),
                f.complete
            ),
            other => println!("{other:?}"),
        }
    }
    Ok(())
}
