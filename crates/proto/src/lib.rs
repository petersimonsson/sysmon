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
pub use frame::Frame;

/// Magic bytes at the start of every datagram.
pub const MAGIC: [u8; 2] = *b"SM";
/// Current protocol version.
pub const VERSION: u8 = 1;
/// Upper bound on encoded datagram size, chosen to fit common path MTUs.
pub const MAX_DATAGRAM: usize = 1200;
/// Size of the fixed preamble (magic, version, flags).
pub const PREAMBLE_LEN: usize = 4;

/// Bits in the preamble `flags` byte. Reserved for future use.
pub mod flags {
    /// Payload is zstd-compressed (not yet implemented).
    pub const COMPRESSED: u8 = 0b0000_0001;
    /// Payload is AEAD-encrypted with a pre-shared key (not yet implemented).
    pub const ENCRYPTED: u8 = 0b0000_0010;
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
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    pub fn busy(&self) -> u64 {
        self.total() - self.idle - self.iowait
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
}

pub type Result<T> = std::result::Result<T, Error>;

/// Encode one datagram.
pub fn encode(header: &Header, msg: &Msg) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(MAX_DATAGRAM);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
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
    if buf[2] != VERSION {
        return Err(Error::UnsupportedVersion(buf[2]));
    }
    if buf[3] != 0 {
        return Err(Error::UnsupportedFlags(buf[3]));
    }
    Ok(postcard::from_bytes(&buf[PREAMBLE_LEN..])?)
}

/// Encode one sample as a `System` datagram followed by as many `Procs`
/// datagrams as needed, each within [`MAX_DATAGRAM`].
pub fn encode_sample(
    host_id: u64,
    boot_id: u128,
    seq: u32,
    system: &SystemSample,
    procs: &[ProcSample],
) -> Result<Vec<Vec<u8>>> {
    let groups = pack(procs)?;
    let chunks = u16::try_from(1 + groups.len()).map_err(|_| Error::TooLarge(procs.len()))?;
    let header = |chunk| Header {
        host_id,
        boot_id,
        seq,
        chunk,
        chunks,
    };

    let mut out = Vec::with_capacity(chunks as usize);
    out.push(encode(&header(0), &Msg::System(system.clone()))?);
    for (i, range) in groups.into_iter().enumerate() {
        out.push(encode(
            &header(i as u16 + 1),
            &Msg::Procs(procs[range].to_vec()),
        )?);
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
    let header = Header {
        host_id,
        boot_id,
        seq,
        chunk: 0,
        chunks: 1,
    };
    pack(meta)?
        .into_iter()
        .map(|range| encode(&header, &Msg::ProcMeta(meta[range].to_vec())))
        .collect()
}

/// Split `items` into consecutive ranges whose encoding fits in one datagram.
fn pack<T: Serialize>(items: &[T]) -> Result<Vec<std::ops::Range<usize>>> {
    // Worst-case varint header (10+19+5+3+3) + enum tag + vec length.
    const OVERHEAD: usize = PREAMBLE_LEN + 48;
    let budget = MAX_DATAGRAM - OVERHEAD;

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
        }
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
        assert!(matches!(decode(b"S"), Err(Error::Truncated)));
    }

    #[test]
    fn chunking_preserves_every_process() {
        let procs: Vec<_> = (0..500).map(proc).collect();
        let dgrams = encode_sample(1, 2, 7, &SystemSample::default(), &procs).unwrap();
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
        let dgrams = encode_sample(1, 2, 0, &SystemSample::default(), &[]).unwrap();
        assert_eq!(dgrams.len(), 1);
    }
}
