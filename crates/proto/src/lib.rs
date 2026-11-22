//! sysmon wire protocol.
//!
//! Every UDP datagram is self-describing:
//!
//! ```text
//! [ b"SM" ][ version: u8 ][ flags: u8 ][ postcard(Header, Msg) ]
//! ```
//!
//! The agent sends raw cumulative kernel counters; rates are computed on the
//! monitor so that lost datagrams never corrupt data. See
//! `docs/architecture.md` for the full design.

use serde::{Deserialize, Serialize};

mod frame;
pub mod seal;
pub mod v1;
pub mod v2;
pub mod v3;
pub use frame::Frame;
pub use seal::{Key, Opener, Sealer};

/// Magic bytes at the start of every datagram.
pub const MAGIC: [u8; 2] = *b"SM";
/// Newest protocol version. v5 added [`Msg::Logs`]; only log datagrams are
/// sent as v5 (see [`version_of`]), so a v4 monitor still reads everything
/// else and just rejects the logs.
pub const VERSION: u8 = 5;
/// The version samples and every message older than v5 are sent as.
const BASE_VERSION: u8 = 4;
/// Oldest version [`decode`] still reads.
pub const MIN_VERSION: u8 = 1;
/// Upper bound on encoded datagram size, chosen to fit common path MTUs.
pub const MAX_DATAGRAM: usize = 1200;
/// Size of the fixed preamble (magic, version, flags).
pub const PREAMBLE_LEN: usize = 4;

/// Bits in the preamble `flags` byte; see [`crate::seal`].
pub mod flags {
    /// Payload is zstd-compressed.
    pub const COMPRESSED: u8 = 0b0000_0001;
    /// Payload is XChaCha20-Poly1305-encrypted with a pre-shared key.
    pub const ENCRYPTED: u8 = 0b0000_0010;
    pub const KNOWN: u8 = COMPRESSED | ENCRYPTED;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Stable per-machine identifier (e.g. hash of `/etc/machine-id`).
    pub host_id: u64,
    /// `/proc/sys/kernel/random/boot_id`; counters reset when this changes.
    pub boot_id: u128,
    /// Sample sequence number, shared by every chunk of one sample.
    pub seq: u32,
    /// Index of this datagram within the sample.
    pub chunk: u16,
    /// Total number of datagrams in the sample.
    pub chunks: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Msg {
    HostInfo(HostInfo),
    /// Chunk 0 of a sample.
    System(SystemSample),
    /// Chunks 1..n of a sample.
    Procs(Vec<ProcSample>),
    ProcMeta(Vec<ProcMeta>),
    /// Names for the uids of running processes. New variants go last so
    /// existing recordings keep decoding.
    Users(Vec<UserName>),
    /// Chunks after the processes of a sample, when the agent sends threads.
    Threads(Vec<ThreadSample>),
    /// Journal lines (`sysmon-agent --logs`), standalone like `ProcMeta`.
    /// Sent at least every few seconds, empty if nothing was logged, so the
    /// monitor knows logs are on.
    Logs(LogBatch),
}

/// The version a datagram carrying `msg` is sent as.
pub fn version_of(msg: &Msg) -> u8 {
    match msg {
        Msg::Logs(_) => VERSION,
        _ => BASE_VERSION,
    }
}

/// Longest log message sent, in bytes; longer ones are cut and marked
/// [`LogEntry::truncated`], so any entry fits in one datagram.
pub const MAX_LOG_MESSAGE: usize = 800;
/// Longest unit or identifier sent, in bytes.
pub const MAX_LOG_NAME: usize = 64;

/// Consecutive log lines from one agent run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogBatch {
    /// Random per agent start: line numbers restart with it, so a new run
    /// isn't mistaken for lost lines.
    pub run: u64,
    /// Number of `entries[0]` within the run; numbers count up by one per
    /// line, so a jump means datagrams were lost.
    pub first_seq: u64,
    /// Lines the agent dropped (over its rate limit) before these.
    pub dropped: u32,
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// When it was logged, by the agent's wall clock (the journal's
    /// `__REALTIME_TIMESTAMP`), nanoseconds since the Unix epoch.
    pub ts_unix_ns: u64,
    /// syslog priority: 0 emerg … 3 err, 4 warning, 5 notice, 6 info, 7 debug.
    pub priority: u8,
    /// `_SYSTEMD_UNIT`, if the line came from a unit.
    pub unit: Option<String>,
    /// `SYSLOG_IDENTIFIER`, else `_COMM`.
    pub ident: String,
    pub pid: Option<u32>,
    pub message: String,
    /// The message was cut to [`MAX_LOG_MESSAGE`].
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserName {
    pub uid: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub kernel: String,
    pub cpu_count: u16,
    pub mem_total_kib: u64,
    /// `sysconf(_SC_CLK_TCK)`, needed to turn jiffies into seconds.
    pub clk_tck: u32,
    pub page_size: u32,
    /// Agent sampling interval in milliseconds.
    pub interval_ms: u32,
    /// Whether samples include [`Msg::Threads`] (`sysmon-agent --threads`).
    pub sends_threads: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemSample {
    /// Wall-clock time of the sample on the agent, nanoseconds since the Unix epoch.
    pub ts_unix_ns: u64,
    /// Aggregate CPU line first, then one entry per core.
    pub cpus: Vec<CpuCounters>,
    pub mem: MemInfo,
    pub load: [f32; 3],
    pub net: Vec<NetIf>,
    pub disks: Vec<DiskStat>,
    /// `CLOCK_BOOTTIME` when the sample was taken: time since boot, counting
    /// suspend, and never stepped like the wall clock (NTP, date changes, VM
    /// resume). Monitors order samples and compute rates with it. `None`
    /// from agents older than v4.
    pub boottime_ns: Option<u64>,
}

/// Cumulative jiffies from `/proc/stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuCounters {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuCounters {
    /// Saturating: these come from the network, and a bogus value must not
    /// overflow (a panic in debug builds).
    pub fn total(&self) -> u64 {
        [
            self.user,
            self.nice,
            self.system,
            self.idle,
            self.iowait,
            self.irq,
            self.softirq,
            self.steal,
        ]
        .into_iter()
        .fold(0u64, u64::saturating_add)
    }

    pub fn busy(&self) -> u64 {
        self.total()
            .saturating_sub(self.idle)
            .saturating_sub(self.iowait)
    }
}

/// Values from `/proc/meminfo`, in KiB.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemInfo {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetIf {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskStat {
    pub name: String,
    pub sectors_read: u64,
    pub sectors_written: u64,
    pub io_ms: u64,
}

/// Per-process counters from `/proc/[pid]/stat`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcSample {
    pub pid: u32,
    pub ppid: u32,
    /// Start time in jiffies since boot; `(pid, starttime)` identifies a process.
    pub starttime: u64,
    pub state: u8,
    pub utime: u64,
    pub stime: u64,
    pub rss_pages: u64,
    pub threads: u32,
    /// `comm`, at most 16 bytes.
    pub comm: String,
    /// Virtual memory size (`vsize`); `None` from v1 agents.
    pub vsize_bytes: Option<u64>,
    /// Resident shared pages, from `/proc/[pid]/statm`; `None` from v1
    /// agents, or if the process exited between reading `stat` and `statm`.
    pub shared_pages: Option<u64>,
    /// The kernel's `PF_KTHREAD` flag; `None` from v1 and v2 agents.
    pub kernel_thread: Option<bool>,
}

/// One thread of a process, other than its main thread (which is the
/// process's own [`ProcSample`]). Memory is the process's, so it isn't sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadSample {
    /// The owning process's pid.
    pub tgid: u32,
    pub tid: u32,
    /// With `tid`, identifies the thread (thread ids share the pid space).
    pub starttime: u64,
    pub state: u8,
    pub utime: u64,
    pub stime: u64,
    /// The thread's name (`/proc/[pid]/task/[tid]/comm`).
    pub comm: String,
}

impl ThreadSample {
    /// Thread ids are unique among live pids, so `(tid, starttime)` makes a
    /// key that never collides with a process's.
    pub fn key(&self) -> ProcKey {
        ProcKey {
            pid: self.tid,
            starttime: self.starttime,
        }
    }
}

impl ProcSample {
    pub fn key(&self) -> ProcKey {
        ProcKey {
            pid: self.pid,
            starttime: self.starttime,
        }
    }
}

/// Rarely changing per-process data, sent separately from samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcMeta {
    pub key: ProcKey,
    pub uid: u32,
    pub cmdline: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcKey {
    pub pid: u32,
    pub starttime: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("datagram too short")]
    Truncated,
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported flags {0:#04x}")]
    UnsupportedFlags(u8),
    #[error("encoded message is {0} bytes, larger than MAX_DATAGRAM")]
    TooLarge(usize),
    #[error(transparent)]
    Postcard(#[from] postcard::Error),
    #[error("datagram is encrypted and no key is configured")]
    NeedsKey,
    #[error("datagram failed authentication")]
    Unauthenticated,
    #[error("encryption failed")]
    Crypto,
    #[error("compression: {0}")]
    Compression(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Encode one datagram.
pub fn encode(header: &Header, msg: &Msg) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(MAX_DATAGRAM);
    out.extend_from_slice(&MAGIC);
    out.push(version_of(msg));
    out.push(0); // flags
    let out = postcard::to_extend(&(header, msg), out)?;
    if out.len() > MAX_DATAGRAM {
        return Err(Error::TooLarge(out.len()));
    }
    Ok(out)
}

/// Decode one datagram.
pub fn decode(buf: &[u8]) -> Result<(Header, Msg)> {
    if buf.len() < PREAMBLE_LEN {
        return Err(Error::Truncated);
    }
    if buf[..2] != MAGIC {
        return Err(Error::BadMagic);
    }
    let version = buf[2];
    if !(MIN_VERSION..=VERSION).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }
    let flags = buf[3];
    if flags & !flags::KNOWN != 0 {
        return Err(Error::UnsupportedFlags(flags));
    }
    if flags & flags::ENCRYPTED != 0 {
        return Err(Error::NeedsKey);
    }
    let payload = seal::decompress(flags, &buf[PREAMBLE_LEN..])?;
    match version {
        1 => {
            let (h, m): (Header, v1::Msg) = postcard::from_bytes(&payload)?;
            return Ok((h, m.into()));
        }
        2 => {
            let (h, m): (Header, v2::Msg) = postcard::from_bytes(&payload)?;
            return Ok((h, m.into()));
        }
        3 => {
            let (h, m): (Header, v3::Msg) = postcard::from_bytes(&payload)?;
            return Ok((h, m.into()));
        }
        _ => {}
    }
    Ok(postcard::from_bytes(&payload)?)
}

/// Encode one sample as a `System` datagram followed by as many `Procs`
/// and then `Threads` datagrams as needed, each within [`MAX_DATAGRAM`].
pub fn encode_sample(
    host_id: u64,
    boot_id: u128,
    seq: u32,
    system: &SystemSample,
    procs: &[ProcSample],
    threads: &[ThreadSample],
) -> Result<Vec<Vec<u8>>> {
    let groups = pack(procs)?;
    let thread_groups = pack(threads)?;
    let chunks = u16::try_from(1 + groups.len() + thread_groups.len())
        .map_err(|_| Error::TooLarge(procs.len() + threads.len()))?;
    let header = |chunk| Header {
        host_id,
        boot_id,
        seq,
        chunk,
        chunks,
    };

    let mut out = Vec::with_capacity(chunks as usize);
    out.push(encode(&header(0), &Msg::System(system.clone()))?);
    let mut chunk = 1;
    for range in groups {
        out.push(encode(&header(chunk), &Msg::Procs(procs[range].to_vec()))?);
        chunk += 1;
    }
    for range in thread_groups {
        out.push(encode(
            &header(chunk),
            &Msg::Threads(threads[range].to_vec()),
        )?);
        chunk += 1;
    }
    Ok(out)
}

/// Encode process metadata as standalone datagrams (each `chunk 0 of 1`),
/// split so that each fits within [`MAX_DATAGRAM`].
pub fn encode_proc_meta(
    host_id: u64,
    boot_id: u128,
    seq: u32,
    meta: &[ProcMeta],
) -> Result<Vec<Vec<u8>>> {
    encode_standalone(host_id, boot_id, seq, meta, Msg::ProcMeta)
}

/// Encode a log batch as standalone datagrams, split so each fits in
/// [`MAX_DATAGRAM`] (with `first_seq` and `dropped` adjusted per part). An
/// empty batch is one datagram. Entries must respect [`MAX_LOG_MESSAGE`]
/// and [`MAX_LOG_NAME`].
pub fn encode_logs(
    host_id: u64,
    boot_id: u128,
    seq: u32,
    batch: &LogBatch,
) -> Result<Vec<Vec<u8>>> {
    let header = Header {
        host_id,
        boot_id,
        seq,
        chunk: 0,
        chunks: 1,
    };
    // run, first_seq and dropped as varints, on top of the usual overhead.
    let mut groups = pack_within(&batch.entries, ITEM_BUDGET - 25)?;
    if groups.is_empty() {
        groups.push(0..0);
    }
    groups
        .into_iter()
        .enumerate()
        .map(|(i, range)| {
            let part = LogBatch {
                run: batch.run,
                first_seq: batch.first_seq + range.start as u64,
                dropped: if i == 0 { batch.dropped } else { 0 },
                entries: batch.entries[range].to_vec(),
            };
            encode(&header, &Msg::Logs(part))
        })
        .collect()
}

/// Encode user names as standalone datagrams, like [`encode_proc_meta`].
pub fn encode_users(
    host_id: u64,
    boot_id: u128,
    seq: u32,
    users: &[UserName],
) -> Result<Vec<Vec<u8>>> {
    encode_standalone(host_id, boot_id, seq, users, Msg::Users)
}

fn encode_standalone<T: Serialize + Clone>(
    host_id: u64,
    boot_id: u128,
    seq: u32,
    items: &[T],
    wrap: fn(Vec<T>) -> Msg,
) -> Result<Vec<Vec<u8>>> {
    let header = Header {
        host_id,
        boot_id,
        seq,
        chunk: 0,
        chunks: 1,
    };
    pack(items)?
        .into_iter()
        .map(|range| encode(&header, &wrap(items[range].to_vec())))
        .collect()
}

/// Room for a message's items in one datagram: what's left after the
/// worst-case varint header (10+19+5+3+3), enum tag and vec length, and
/// room for encryption so sealed datagrams still fit.
const ITEM_BUDGET: usize = MAX_DATAGRAM - (PREAMBLE_LEN + 48 + seal::SEAL_OVERHEAD);

/// Split `items` into consecutive ranges whose encoding fits in one datagram.
fn pack<T: Serialize>(items: &[T]) -> Result<Vec<std::ops::Range<usize>>> {
    pack_within(items, ITEM_BUDGET)
}

/// [`pack`], with `budget` bytes for the items of each datagram.
fn pack_within<T: Serialize>(items: &[T], budget: usize) -> Result<Vec<std::ops::Range<usize>>> {
    let mut groups = Vec::new();
    let mut start = 0;
    let mut size = 0;
    for (i, item) in items.iter().enumerate() {
        let len = postcard::experimental::serialized_size(item)?;
        if len > budget {
            return Err(Error::TooLarge(len));
        }
        if size + len > budget && i > start {
            groups.push(start..i);
            start = i;
            size = 0;
        }
        size += len;
    }
    if start < items.len() {
        groups.push(start..items.len());
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32) -> ProcSample {
        ProcSample {
            pid,
            ppid: 1,
            starttime: 1000 + pid as u64,
            state: b'S',
            utime: 123_456,
            stime: 7_890,
            rss_pages: 4096,
            threads: 4,
            comm: "some-process".into(),
            vsize_bytes: Some(1 << 30),
            shared_pages: Some(100),
            kernel_thread: None,
        }
    }

    fn log_entry(i: usize, len: usize) -> LogEntry {
        LogEntry {
            ts_unix_ns: 1_000 + i as u64,
            priority: 4,
            unit: Some("x".repeat(MAX_LOG_NAME)),
            ident: "y".repeat(MAX_LOG_NAME),
            pid: Some(u32::MAX),
            message: "m".repeat(len),
            truncated: len == MAX_LOG_MESSAGE,
        }
    }

    #[test]
    fn log_batches_split_and_keep_their_numbering() {
        let batch = LogBatch {
            run: u64::MAX,
            first_seq: u64::MAX / 2,
            dropped: u32::MAX,
            entries: (0..20).map(|i| log_entry(i, MAX_LOG_MESSAGE)).collect(),
        };
        let datagrams = encode_logs(u64::MAX, u128::MAX, u32::MAX, &batch).unwrap();
        assert!(datagrams.len() > 1);
        let mut next = batch.first_seq;
        let mut entries = Vec::new();
        for (i, d) in datagrams.iter().enumerate() {
            // Sealed, the largest still fits.
            assert!(d.len() + seal::SEAL_OVERHEAD <= MAX_DATAGRAM, "{}", d.len());
            assert_eq!(d[2], VERSION, "logs go out as v5");
            let (h, Msg::Logs(part)) = decode(d).unwrap() else {
                panic!("not logs")
            };
            assert_eq!((h.chunk, h.chunks), (0, 1));
            assert_eq!(part.run, batch.run);
            assert_eq!(part.first_seq, next);
            assert_eq!(part.dropped, if i == 0 { u32::MAX } else { 0 });
            next += part.entries.len() as u64;
            entries.extend(part.entries);
        }
        assert_eq!(entries, batch.entries);
    }

    #[test]
    fn an_empty_log_batch_is_one_datagram_and_other_messages_stay_v4() {
        let batch = LogBatch {
            run: 1,
            first_seq: 7,
            dropped: 0,
            entries: vec![],
        };
        let d = encode_logs(1, 2, 3, &batch).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(decode(&d[0]).unwrap().1, Msg::Logs(batch));
        // So a v4 monitor keeps reading samples from a v5 agent.
        let sample = encode_sample(1, 2, 3, &SystemSample::default(), &[proc(1)], &[]).unwrap();
        assert!(sample.iter().all(|d| d[2] == 4));
        assert_eq!(encode_users(1, 2, 3, &[]).unwrap().len(), 0);
    }

    #[test]
    fn round_trip() {
        let header = Header {
            host_id: 1,
            boot_id: 2,
            seq: 3,
            chunk: 0,
            chunks: 1,
        };
        let msg = Msg::System(SystemSample {
            ts_unix_ns: 42,
            cpus: vec![CpuCounters::default(); 4],
            load: [0.5, 0.25, 0.125],
            ..Default::default()
        });
        let buf = encode(&header, &msg).unwrap();
        assert_eq!(decode(&buf).unwrap(), (header, msg));
    }

    #[test]
    fn rejects_foreign_traffic() {
        assert!(matches!(decode(b"XX\x01\x00"), Err(Error::BadMagic)));
        assert!(matches!(
            decode(b"SM\x09\x00"),
            Err(Error::UnsupportedVersion(9))
        ));
        assert!(matches!(
            decode(b"SM\x01\x80"),
            Err(Error::UnsupportedFlags(0x80))
        ));
        assert!(matches!(decode(b"S"), Err(Error::Truncated)));
    }

    #[test]
    fn v1_datagrams_still_decode() {
        let header = Header {
            host_id: 1,
            boot_id: 2,
            seq: 3,
            chunk: 1,
            chunks: 2,
        };
        let old = v1::ProcSample {
            pid: 7,
            ppid: 1,
            starttime: 9,
            state: b'S',
            utime: 10,
            stime: 20,
            rss_pages: 30,
            threads: 4,
            comm: "old".into(),
        };
        let buf = v1::encode(&header, &v1::Msg::Procs(vec![old])).unwrap();
        assert_eq!(buf[2], 1);
        let (h, msg) = decode(&buf).unwrap();
        assert_eq!(h, header);
        let Msg::Procs(procs) = msg else {
            panic!("not Procs")
        };
        assert_eq!(
            (procs[0].pid, procs[0].rss_pages, &procs[0].comm[..]),
            (7, 30, "old")
        );
        assert_eq!((procs[0].vsize_bytes, procs[0].shared_pages), (None, None));
    }

    #[test]
    fn versions_outside_the_supported_range_are_rejected() {
        assert!(matches!(
            decode(b"SM\x00\x00"),
            Err(Error::UnsupportedVersion(0))
        ));
        assert!(matches!(
            decode(b"SM\x06\x00"),
            Err(Error::UnsupportedVersion(6))
        ));
    }

    #[test]
    fn v2_datagrams_still_decode() {
        let header = Header {
            host_id: 1,
            boot_id: 2,
            seq: 3,
            chunk: 0,
            chunks: 1,
        };
        let old = v2::ProcSample {
            pid: 7,
            ppid: 1,
            starttime: 9,
            state: b'S',
            utime: 10,
            stime: 20,
            rss_pages: 30,
            threads: 4,
            comm: "v2".into(),
            vsize_bytes: Some(4096),
            shared_pages: Some(5),
        };
        let buf = v2::encode(&header, &v2::Msg::Procs(vec![old])).unwrap();
        let Msg::Procs(procs) = decode(&buf).unwrap().1 else {
            panic!("not Procs")
        };
        assert_eq!(
            (procs[0].vsize_bytes, procs[0].shared_pages),
            (Some(4096), Some(5))
        );
        assert_eq!(procs[0].kernel_thread, None);

        let info = v1::HostInfo {
            hostname: "h".into(),
            kernel: "k".into(),
            cpu_count: 1,
            mem_total_kib: 2,
            clk_tck: 100,
            page_size: 4096,
            interval_ms: 1000,
        };
        let buf = v2::encode(&header, &v2::Msg::HostInfo(info)).unwrap();
        let Msg::HostInfo(info) = decode(&buf).unwrap().1 else {
            panic!("not HostInfo")
        };
        assert!(!info.sends_threads);
    }

    #[test]
    fn v3_datagrams_still_decode() {
        let header = Header {
            host_id: 1,
            boot_id: 2,
            seq: 3,
            chunk: 0,
            chunks: 1,
        };
        let old = v1::SystemSample {
            ts_unix_ns: 42,
            load: [1.0, 2.0, 3.0],
            ..Default::default()
        };
        let buf = v3::encode(&header, &v3::Msg::System(old)).unwrap();
        assert_eq!(buf[2], 3);
        let Msg::System(s) = decode(&buf).unwrap().1 else {
            panic!("not System")
        };
        assert_eq!(
            (s.ts_unix_ns, s.load, s.boottime_ns),
            (42, [1.0, 2.0, 3.0], None)
        );

        // And v4 carries the boot-time clock.
        let new = SystemSample {
            ts_unix_ns: 42,
            boottime_ns: Some(7),
            ..Default::default()
        };
        let buf = encode(&header, &Msg::System(new.clone())).unwrap();
        assert_eq!(decode(&buf).unwrap().1, Msg::System(new));
    }

    #[test]
    fn threads_follow_processes_in_a_sample() {
        let procs: Vec<_> = (0..100).map(proc).collect();
        let thread = |i: u32| ThreadSample {
            tgid: i % 100,
            tid: 1000 + i,
            starttime: 5,
            state: b'S',
            utime: 1,
            stime: 2,
            comm: "worker".into(),
        };
        let threads: Vec<_> = (0..300).map(thread).collect();
        let dgrams = encode_sample(1, 2, 7, &SystemSample::default(), &procs, &threads).unwrap();
        let (mut got_p, mut got_t, mut seen_threads) = (Vec::new(), Vec::new(), false);
        for d in &dgrams {
            assert!(d.len() <= MAX_DATAGRAM);
            match decode(d).unwrap().1 {
                Msg::System(_) => {}
                Msg::Procs(p) => {
                    assert!(!seen_threads, "processes come first");
                    got_p.extend(p);
                }
                Msg::Threads(t) => {
                    seen_threads = true;
                    got_t.extend(t);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!((got_p, got_t), (procs, threads));
        assert_eq!(thread(1).key().pid, 1001, "a thread's key uses its tid");
    }

    #[test]
    fn chunking_preserves_every_process() {
        let procs: Vec<_> = (0..500).map(proc).collect();
        let dgrams = encode_sample(1, 2, 7, &SystemSample::default(), &procs, &[]).unwrap();
        assert!(dgrams.len() > 2);

        let mut seen = Vec::new();
        for (i, d) in dgrams.iter().enumerate() {
            assert!(d.len() <= MAX_DATAGRAM);
            let (h, msg) = decode(d).unwrap();
            assert_eq!(
                (h.seq, h.chunk as usize, h.chunks as usize),
                (7, i, dgrams.len())
            );
            match msg {
                Msg::System(_) => assert_eq!(i, 0),
                Msg::Procs(p) => seen.extend(p),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(seen, procs);
    }

    #[test]
    fn sample_without_procs_is_one_datagram() {
        let dgrams = encode_sample(1, 2, 0, &SystemSample::default(), &[], &[]).unwrap();
        assert_eq!(dgrams.len(), 1);
    }
}
