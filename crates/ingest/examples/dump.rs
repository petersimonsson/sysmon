//! Print everything received on a UDP port.
//!
//! cargo run -p sysmon-ingest --example dump -- 0.0.0.0:9876 [key-file]

fn main() -> anyhow::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:9876".into())
        .parse()?;
    let key = match std::env::args().nth(2) {
        Some(path) => Some(sysmon_proto::Key::from_file(path.as_ref())?),
        None => None,
    };
    let (tx, rx) = flume::bounded(1024);
    sysmon_ingest::spawn(
        addr,
        sysmon_proto::Opener::new(key.as_ref()),
        sysmon_ingest::Sinks {
            events: tx,
            raw: None,
            rejections: Default::default(),
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
