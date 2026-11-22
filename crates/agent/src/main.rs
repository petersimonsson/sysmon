//! sysmon-agent: samples `/proc` and pushes raw counters to one or more
//! monitors over UDP.

mod collect;

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use clap::Parser;
use sysmon_proto::{HostInfo, Msg, ProcKey};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Monitor address to send to, as host:port. Can be given more than once.
    #[arg(short, long = "target", required = true)]
    targets: Vec<String>,
    /// Sampling interval in milliseconds.
    #[arg(short, long, default_value_t = 1000)]
    interval_ms: u32,
    /// Send HostInfo every this many samples.
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

    let targets = resolve(&args.targets)?;
    let socket = UdpSocket::bind(("0.0.0.0", 0)).context("binding UDP socket")?;

    let host_id = collect::host_id();
    let boot_id = collect::boot_id();
    let info = collect::host_info(args.interval_ms);
    tracing::info!(host_id = format_args!("{host_id:016x}"), host = %info.hostname, ?targets, "starting");

    let interval = Duration::from_millis(args.interval_ms.max(10) as u64);
    let mut known: HashSet<ProcKey> = HashSet::new();
    let mut procs = Vec::new();
    let mut next_tick = Instant::now();

    for seq in 0u32.. {
        let mut datagrams = Vec::new();

        if seq % args.host_info_every.max(1) == 0 {
            datagrams.push(host_info_datagram(host_id, boot_id, seq, &info)?);
        }

        let system = collect::system(unix_now_ns());
        collect::procs(&mut procs);

        // Metadata for new processes, or for all of them on a refresh tick.
        let refresh = seq % args.meta_refresh_every.max(1) == 0;
        let current: HashSet<ProcKey> = procs.iter().map(|p| p.key()).collect();
        let meta: Vec<_> = current
            .iter()
            .filter(|k| refresh || !known.contains(k))
            .filter_map(|&k| collect::proc_meta(k))
            .collect();
        known = current;

        datagrams.extend(sysmon_proto::encode_proc_meta(
            host_id, boot_id, seq, &meta,
        )?);
        datagrams.extend(sysmon_proto::encode_sample(
            host_id, boot_id, seq, &system, &procs,
        )?);

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
