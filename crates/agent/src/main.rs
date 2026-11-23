//! sysmon-agent: samples `/proc` and pushes raw counters to one or more
//! monitors over UDP.

mod collect;
mod journal;
mod send;
mod targets;
mod users;

/// License notices of everything linked into this binary (see build.rs).
static NOTICES: sysmon_notices::Notices = sysmon_notices::embed!();

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::Parser;
use sysmon_proto::{HostInfo, Key, Msg, ProcKey, Sealer, UserName};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Monitor address to send to, as host:port. Can be given more than once.
    #[arg(short, long = "target", required_unless_present_any = ["generate_key", "licenses"])]
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
    /// Print sysmon's license and the license notices of all third-party
    /// software in this binary, then exit.
    #[arg(long, exclusive = true)]
    licenses: bool,
    /// Send HostInfo and user names every this many samples. Every sample
    /// by default (about 150 bytes), so a monitor that starts or restarts
    /// knows the host's name, settings and users from its first sample.
    #[arg(long, default_value_t = 1)]
    host_info_every: u32,
    /// Resend metadata for every process every this many samples.
    #[arg(long, default_value_t = 30)]
    meta_refresh_every: u32,
    /// Also send every thread of every user process (off by default: about
    /// 3x the agent's CPU and 2.5x its bandwidth on a desktop with ~1750 threads).
    #[arg(long)]
    threads: bool,
    /// Also send journal lines (needs journalctl; to see system logs the
    /// agent must be in the systemd-journal group). Requires --key-file,
    /// as logs often hold sensitive details, unless --logs-unencrypted.
    #[arg(long)]
    logs: bool,
    /// Lowest priority sent: emerg, alert, crit, err, warning, notice,
    /// info, debug, or 0-7.
    #[arg(long, default_value = "warning", value_parser = journal::parse_priority, requires = "logs")]
    log_priority: u8,
    /// Only lines from this systemd unit. Can be given more than once.
    #[arg(long = "log-unit", value_name = "UNIT", requires = "logs")]
    log_units: Vec<String>,
    /// Where to keep the journal position, so a restarted agent carries on
    /// where it stopped. Default: journal-cursor in systemd's
    /// $STATE_DIRECTORY; without either, a restart starts with new lines.
    #[arg(long, value_name = "PATH", requires = "logs")]
    log_cursor_file: Option<PathBuf>,
    /// Allow --logs without --key-file, sending logs in plain text.
    #[arg(long, requires = "logs")]
    logs_unencrypted: bool,
}

/// Send a log batch at least this often, empty if nothing was logged, so
/// the monitor knows logs are on.
const LOG_HEARTBEAT_MS: u32 = 10_000;

fn main() -> anyhow::Result<()> {
    // Without RUST_LOG the filter would allow errors only, so the start-up
    // line and send failures would never reach the terminal or the journal.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    if args.licenses {
        return Ok(NOTICES.print()?);
    }
    if let Some(path) = &args.generate_key {
        return write_new_key(path);
    }

    check_log_encryption(&args)?;
    let key = args
        .key_file
        .as_deref()
        .map(Key::from_file)
        .transpose()
        .context("reading key file")?;
    let sealer = Sealer::new(key.as_ref(), args.compress);

    let targets = targets::Targets::spawn(args.targets.clone(), targets::RESOLVE_EVERY)?;
    let mut sender = send::Sender::default();

    let host_id = collect::host_id();
    let boot_id = collect::boot_id();
    let interval_ms = effective_interval_ms(args.interval_ms);
    if interval_ms != args.interval_ms {
        tracing::warn!(
            requested = args.interval_ms,
            used = interval_ms,
            "interval raised to the minimum"
        );
    }
    let info = collect::host_info(interval_ms, args.threads);
    tracing::info!(
        host_id = format_args!("{host_id:016x}"),
        host = %info.hostname,
        targets = ?args.targets,
        compress = args.compress,
        encrypted = key.is_some(),
        "starting"
    );

    let mut journal = if args.logs {
        Some(
            journal::Journal::spawn(journal::Config {
                program: "journalctl".into(),
                priority: args.log_priority,
                units: args.log_units.clone(),
                cursor_file: args
                    .log_cursor_file
                    .clone()
                    .or_else(journal::default_cursor_file),
            })
            .context("starting the journal reader")?,
        )
    } else {
        None
    };
    let log_heartbeat_every = (LOG_HEARTBEAT_MS / interval_ms).max(1);

    let interval = Duration::from_millis(interval_ms as u64);
    let host_info_every = args.host_info_every.max(1);
    let mut known: HashMap<ProcKey, u32> = HashMap::new();
    let mut users = users::UserNames::spawn();
    let mut sent_users: HashMap<u32, String> = HashMap::new();
    let mut collector = collect::Collector::new();
    let mut procs = Vec::new();
    let mut threads = Vec::new();
    let mut next_tick = Instant::now();
    let mut warnings = Warnings::default();

    // Wraps after 2^32 samples (497 days at the fastest 10 ms interval);
    // the monitor takes the new 0 as an agent restart and carries on.
    let mut seq: u32 = 0;
    loop {
        let mut datagrams = Vec::new();
        let host_tick = seq.is_multiple_of(host_info_every);

        let system = collect::system(unix_now_ns());
        collector.procs(&mut procs, args.threads.then_some(&mut threads));

        // Metadata for new processes, or for all of them on a refresh tick.
        let refresh = seq.is_multiple_of(args.meta_refresh_every.max(1));
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
            datagrams.extend(warnings.or_skip(
                "host info",
                host_info_datagram(host_id, boot_id, seq, &info),
            ));
        }
        if seq.is_multiple_of(USER_REFRESH_EVERY) {
            users.refresh();
        }
        // Names for the uids in use: with every HostInfo, and as soon as a
        // lookup brings a new one, so users don't show as numbers for long.
        let mut uids: Vec<u32> = known.values().copied().collect();
        uids.sort_unstable();
        uids.dedup();
        let names: Vec<UserName> = uids
            .into_iter()
            .filter_map(|uid| users.get(uid).map(|name| UserName { uid, name }))
            .collect();
        let news = names
            .iter()
            .any(|u| sent_users.get(&u.uid) != Some(&u.name));
        if host_tick || news {
            datagrams.extend(users_datagrams(
                host_id,
                boot_id,
                seq,
                &names,
                &mut warnings,
            ));
            sent_users = names.into_iter().map(|u| (u.uid, u.name)).collect();
        }
        datagrams.extend(
            warnings
                .or_skip(
                    "process metadata",
                    sysmon_proto::encode_proc_meta(host_id, boot_id, seq, &meta),
                )
                .unwrap_or_default(),
        );
        datagrams.extend(
            warnings
                .or_skip(
                    "sample",
                    sysmon_proto::encode_sample(host_id, boot_id, seq, &system, &procs, &threads),
                )
                .unwrap_or_default(),
        );

        if let Some(journal) = &mut journal {
            let batch = journal.take();
            if !batch.entries.is_empty()
                || batch.dropped > 0
                || seq.is_multiple_of(log_heartbeat_every)
            {
                datagrams.extend(
                    warnings
                        .or_skip(
                            "logs",
                            sysmon_proto::encode_logs(host_id, boot_id, seq, &batch),
                        )
                        .unwrap_or_default(),
                );
            }
        }

        let datagrams: Vec<Vec<u8>> = datagrams
            .into_iter()
            .filter_map(|d| warnings.or_skip("sealing", sealer.seal(d)))
            .collect();
        let bytes: usize = datagrams.iter().map(Vec::len).sum();
        for target in targets.current() {
            for d in &datagrams {
                if let Err(e) = sender.send_to(d, target) {
                    tracing::warn!(%target, error = %e, "send failed");
                    break;
                }
            }
        }
        // The lines are out: a restart can carry on after them.
        if let Some(journal) = &mut journal {
            journal.save_position();
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
        seq = seq.wrapping_add(1);
    }
}

/// Logs often hold sensitive details: don't send them in plain text by
/// accident.
fn check_log_encryption(args: &Args) -> anyhow::Result<()> {
    if args.logs && args.key_file.is_none() && !args.logs_unencrypted {
        anyhow::bail!(
            "--logs sends journal lines, which often hold sensitive details; \
             use --key-file to encrypt them, or --logs-unencrypted to send them in plain text"
        );
    }
    Ok(())
}

/// Shortest sampling interval. HostInfo reports the interval actually used,
/// since the monitor judges a host silent after a few missed intervals.
const MIN_INTERVAL_MS: u32 = 10;

fn effective_interval_ms(requested: u32) -> u32 {
    requested.max(MIN_INTERVAL_MS)
}

/// Longest user name sent; longer ones (only seen from odd directories) are
/// cut, so they can't make the whole `Users` message too large to send.
const MAX_USER_NAME: usize = 256;

/// The `Users` datagrams for `names`, with over-long names cut.
fn users_datagrams(
    host_id: u64,
    boot_id: u128,
    seq: u32,
    names: &[UserName],
    warnings: &mut Warnings,
) -> Vec<Vec<u8>> {
    let names: Vec<UserName> = names
        .iter()
        .map(|u| UserName {
            uid: u.uid,
            name: collect::cap(&u.name, MAX_USER_NAME),
        })
        .collect();
    warnings
        .or_skip(
            "user names",
            sysmon_proto::encode_users(host_id, boot_id, seq, &names),
        )
        .unwrap_or_default()
}

/// Encoding problems are logged once per kind of record and the affected
/// part of the sample skipped: one record that can't be sent mustn't stop
/// the agent. Keyed by `what` rather than the error text, which can differ
/// every tick (it holds the encoded size), so a lasting problem can neither
/// flood the log nor grow the set.
#[derive(Default)]
struct Warnings {
    seen: HashSet<String>,
}

impl Warnings {
    /// `r`'s value, or `None` (warned about) if it failed.
    fn or_skip<T, E: Into<anyhow::Error>>(&mut self, what: &str, r: Result<T, E>) -> Option<T> {
        r.map_err(|e| {
            if !self.seen.contains(what) {
                self.seen.insert(what.to_string());
                tracing::warn!("skipping {what}: {:#}", e.into());
            }
        })
        .ok()
    }
}

/// Look user names up again every this many samples (they rarely change,
/// and directory lookups shouldn't be hammered).
const USER_REFRESH_EVERY: u32 = 60;

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
) -> sysmon_proto::Result<Vec<u8>> {
    let header = sysmon_proto::Header {
        host_id,
        boot_id,
        seq,
        chunk: 0,
        chunks: 1,
    };
    sysmon_proto::encode(&header, &Msg::HostInfo(info.clone()))
}

fn unix_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        Args, NOTICES, Warnings, check_log_encryption, effective_interval_ms, users_datagrams,
    };
    use clap::Parser as _;

    #[test]
    fn logs_need_a_key_unless_explicitly_unencrypted() {
        let parse = |extra: &[&str]| {
            let mut a = vec!["sysmon-agent", "-t", "127.0.0.1:1"];
            a.extend(extra);
            Args::try_parse_from(a)
        };
        assert!(check_log_encryption(&parse(&["--logs"]).unwrap()).is_err());
        assert!(check_log_encryption(&parse(&["--logs", "--logs-unencrypted"]).unwrap()).is_ok());
        let keyed = parse(&["--logs", "-k", "/etc/sysmon/key"]).unwrap();
        assert!(check_log_encryption(&keyed).is_ok());
        assert_eq!(keyed.log_priority, 4, "warning and above by default");
        assert_eq!(
            parse(&["--logs", "--log-priority", "err"])
                .unwrap()
                .log_priority,
            3
        );
        // Log options without --logs are a mistake.
        assert!(parse(&["--log-priority", "err"]).is_err());
        assert!(check_log_encryption(&parse(&[]).unwrap()).is_ok());
    }

    #[test]
    fn host_info_reports_the_interval_used() {
        let args = Args::parse_from(["sysmon-agent", "-t", "127.0.0.1:1", "-i", "0"]);
        let used = effective_interval_ms(args.interval_ms);
        assert_eq!(used, 10);
        assert_eq!(crate::collect::host_info(used, false).interval_ms, 10);
        assert_eq!(effective_interval_ms(1000), 1000);
    }
    use sysmon_proto::{Msg, UserName};

    #[test]
    fn an_over_long_user_name_doesnt_stop_the_agent() {
        let names = [
            UserName {
                uid: 1000,
                name: "anna".into(),
            },
            UserName {
                uid: 1001,
                name: "x".repeat(5000),
            },
        ];
        // The uncut name alone is too large for a datagram.
        assert!(sysmon_proto::encode_users(1, 2, 3, &names).is_err());
        let mut warnings = Warnings::default();
        let datagrams = users_datagrams(1, 2, 3, &names, &mut warnings);
        let sent: Vec<UserName> = datagrams
            .iter()
            .flat_map(|d| match sysmon_proto::decode(d).unwrap().1 {
                Msg::Users(u) => u,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].name, "anna");
        assert_eq!(sent[1].name.len(), super::MAX_USER_NAME);

        // Anything else that fails is skipped and warned about once.
        let failed: Option<()> = warnings.or_skip("test", Err(anyhow::anyhow!("boom")));
        assert!(failed.is_none());
        warnings.or_skip::<(), _>("test", Err(anyhow::anyhow!("boom")));
        // Even when the error text changes, as a growing size does.
        warnings.or_skip::<(), _>("test", Err(anyhow::anyhow!("boom, bigger")));
        assert_eq!(warnings.seen.len(), 1);
    }

    #[test]
    fn notices_cover_the_agents_dependencies() {
        assert_eq!(NOTICES.product, "sysmon-agent");
        let names: Vec<&str> = NOTICES.crates.iter().map(|c| c.name).collect();
        for expected in [
            "clap",
            "libc",
            "chacha20poly1305",
            "postcard",
            "zstd-sys",
            "tracing",
        ] {
            assert!(names.contains(&expected), "{expected} missing");
        }
        // Not in the agent: the UI's dependencies, the build-only collector's
        // JSON parser, proc macros, and our own crates.
        for absent in [
            "gpui-kit",
            "jiff",
            "serde_json",
            "serde_derive",
            "sysmon-proto",
        ] {
            assert!(!names.contains(&absent), "{absent} shouldn't be listed");
        }
        assert!(NOTICES.crates.iter().all(|c| !c.files.is_empty()));
        let all = NOTICES.full_text();
        assert!(all.starts_with("sysmon-agent "));
        assert!(all.contains("Permission is hereby granted"));
    }
}
