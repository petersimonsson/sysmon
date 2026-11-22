//! sysmon-agent: samples `/proc` and pushes raw counters to one or more
//! monitors over UDP.

mod collect;

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use clap::Parser;
use sysmon_proto::{HostInfo, Key, Msg, ProcKey, Sealer, UserName};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Monitor address to send to, as host:port. Can be given more than once.
    #[arg(short, long = "target", required_unless_present = "generate_key")]
    targets: Vec<String>,
    /// Sampling interval in milliseconds.
    #[arg(short, long, default_value_t = 1000)]
    interval_ms: u32,
    /// Compress datagram payloads with zstd (roughly halves bandwidth).
    #[arg(short, long)]
    compress: bool,
    /// Encrypt and authenticate datagrams with this pre-shared key file
    /// (64 hex digits). The monitor needs the same key.
    #[arg(short, long)]
    key_file: Option<PathBuf>,
    /// Write a new random key to this file and exit.
    #[arg(long, value_name = "PATH", exclusive = true)]
    generate_key: Option<PathBuf>,
    /// Send HostInfo and user names every this many samples.
    #[arg(long, default_value_t = 10)]
    host_info_every: u32,
    /// Resend metadata for every process every this many samples.
    #[arg(long, default_value_t = 30)]
    meta_refresh_every: u32,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    if let Some(path) = &args.generate_key {
        return write_new_key(path);
    }

    let key = args
        .key_file
        .as_deref()
        .map(Key::from_file)
        .transpose()
        .context("reading key file")?;
    let sealer = Sealer::new(key.as_ref(), args.compress);

    let targets = resolve(&args.targets)?;
    let socket = UdpSocket::bind(("0.0.0.0", 0)).context("binding UDP socket")?;

    let host_id = collect::host_id();
    let boot_id = collect::boot_id();
    let info = collect::host_info(args.interval_ms);
    tracing::info!(
        host_id = format_args!("{host_id:016x}"),
        host = %info.hostname,
        ?targets,
        compress = args.compress,
        encrypted = key.is_some(),
        "starting"
    );

    let interval = Duration::from_millis(args.interval_ms.max(10) as u64);
    let host_info_every = args.host_info_every.max(1);
    let mut known: HashMap<ProcKey, u32> = HashMap::new();
    let mut passwd = collect::read_passwd();
    let mut procs = Vec::new();
    let mut next_tick = Instant::now();

    for seq in 0u32.. {
        let mut datagrams = Vec::new();
        let host_tick = seq % host_info_every == 0;

        let system = collect::system(unix_now_ns());
        collect::procs(&mut procs);

        // Metadata for new processes, or for all of them on a refresh tick.
        let refresh = seq % args.meta_refresh_every.max(1) == 0;
        let current: HashSet<ProcKey> = procs.iter().map(|p| p.key()).collect();
        known.retain(|k, _| current.contains(k));
        let meta: Vec<_> = current
            .iter()
            .filter(|k| refresh || !known.contains_key(k))
            .filter_map(|&k| collect::proc_meta(k))
            .collect();
        for m in &meta {
            known.insert(m.key, m.uid);
        }

        if host_tick {
            datagrams.push(host_info_datagram(host_id, boot_id, seq, &info)?);
            if seq % (host_info_every * 6) == 0 {
                passwd = collect::read_passwd();
            }
            let mut uids: Vec<u32> = known.values().copied().collect();
            uids.sort_unstable();
            uids.dedup();
            let users: Vec<UserName> = uids
                .into_iter()
                .filter_map(|uid| {
                    passwd.get(&uid).map(|name| UserName {
                        uid,
                        name: name.clone(),
                    })
                })
                .collect();
            datagrams.extend(sysmon_proto::encode_users(host_id, boot_id, seq, &users)?);
        }
        datagrams.extend(sysmon_proto::encode_proc_meta(
            host_id, boot_id, seq, &meta,
        )?);
        datagrams.extend(sysmon_proto::encode_sample(
            host_id, boot_id, seq, &system, &procs,
        )?);

        let mut bytes = 0;
        for d in datagrams.iter_mut() {
            *d = sealer.seal(std::mem::take(d))?;
            bytes += d.len();
        }
        for target in &targets {
            for d in &datagrams {
                if let Err(e) = socket.send_to(d, target) {
                    tracing::warn!(%target, error = %e, "send failed");
                    break;
                }
            }
        }
        tracing::debug!(
            seq,
            datagrams = datagrams.len(),
            bytes,
            procs = procs.len(),
            "sent"
        );

        next_tick += interval;
        let now = Instant::now();
        if next_tick > now {
            std::thread::sleep(next_tick - now);
        } else {
            // Fell behind (suspend, overload): skip missed ticks rather than burst.
            next_tick = now;
        }
    }
    unreachable!()
}

fn write_new_key(path: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    writeln!(f, "{}", Key::generate().to_hex())?;
    println!(
        "wrote a new key to {}; copy it to the monitor too",
        path.display()
    );
    Ok(())
}

fn host_info_datagram(
    host_id: u64,
    boot_id: u128,
    seq: u32,
    info: &HostInfo,
) -> anyhow::Result<Vec<u8>> {
    let header = sysmon_proto::Header {
        host_id,
        boot_id,
        seq,
        chunk: 0,
        chunks: 1,
    };
    Ok(sysmon_proto::encode(&header, &Msg::HostInfo(info.clone()))?)
}

fn resolve(targets: &[String]) -> anyhow::Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for t in targets {
        let addr = t
            .to_socket_addrs()
            .with_context(|| format!("resolving {t}"))?
            .next();
        match addr {
            Some(a) => out.push(a),
            None => bail!("{t} did not resolve to an address"),
        }
    }
    Ok(out)
}

fn unix_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
