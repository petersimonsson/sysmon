//! Frozen protocol v1 types, kept so old agents and recordings stay readable.
//!
//! v1 is v2 without `ProcSample::vsize_bytes` and `ProcSample::shared_pages`.
//! Never change these types; add a new version instead.

use serde::{Deserialize, Serialize};

use crate::{Header, ProcMeta, SystemSample, UserName};

/// `HostInfo` as in v1 and v2 (before `sends_threads`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub kernel: String,
    pub cpu_count: u16,
    pub mem_total_kib: u64,
    pub clk_tck: u32,
    pub page_size: u32,
    pub interval_ms: u32,
}

impl From<HostInfo> for crate::HostInfo {
    fn from(i: HostInfo) -> Self {
        Self {
            hostname: i.hostname,
            kernel: i.kernel,
            cpu_count: i.cpu_count,
            mem_total_kib: i.mem_total_kib,
            clk_tck: i.clk_tck,
            page_size: i.page_size,
            interval_ms: i.interval_ms,
            sends_threads: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcSample {
    pub pid: u32,
    pub ppid: u32,
    pub starttime: u64,
    pub state: u8,
    pub utime: u64,
    pub stime: u64,
    pub rss_pages: u64,
    pub threads: u32,
    pub comm: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Msg {
    HostInfo(HostInfo),
    System(SystemSample),
    Procs(Vec<ProcSample>),
    ProcMeta(Vec<ProcMeta>),
    Users(Vec<UserName>),
}

impl From<ProcSample> for crate::ProcSample {
    fn from(p: ProcSample) -> Self {
        Self {
            pid: p.pid,
            ppid: p.ppid,
            starttime: p.starttime,
            state: p.state,
            utime: p.utime,
            stime: p.stime,
            rss_pages: p.rss_pages,
            threads: p.threads,
            comm: p.comm,
            vsize_bytes: None,
            shared_pages: None,
            kernel_thread: None,
        }
    }
}

impl From<Msg> for crate::Msg {
    fn from(m: Msg) -> Self {
        match m {
            Msg::HostInfo(i) => crate::Msg::HostInfo(i.into()),
            Msg::System(s) => crate::Msg::System(s),
            Msg::Procs(p) => crate::Msg::Procs(p.into_iter().map(Into::into).collect()),
            Msg::ProcMeta(m) => crate::Msg::ProcMeta(m),
            Msg::Users(u) => crate::Msg::Users(u),
        }
    }
}

/// Encode a datagram as a v1 agent did. Only for tests of v1 compatibility.
#[doc(hidden)]
pub fn encode(header: &Header, msg: &Msg) -> crate::Result<Vec<u8>> {
    let out = vec![crate::MAGIC[0], crate::MAGIC[1], 1, 0];
    Ok(postcard::to_extend(&(header, msg), out)?)
}
