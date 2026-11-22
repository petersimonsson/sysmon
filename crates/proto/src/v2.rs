//! Frozen protocol v2 types, kept so v2 agents and recordings stay readable.
//!
//! v2 is v3 without `ProcSample::kernel_thread`, `HostInfo::sends_threads`
//! and `Msg::Threads`. Never change these types; add a new version instead.

use serde::{Deserialize, Serialize};

use crate::v1::{HostInfo, SystemSample};
use crate::{Header, ProcMeta, UserName};

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
    pub vsize_bytes: Option<u64>,
    pub shared_pages: Option<u64>,
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
            vsize_bytes: p.vsize_bytes,
            shared_pages: p.shared_pages,
            kernel_thread: None,
        }
    }
}

impl From<Msg> for crate::Msg {
    fn from(m: Msg) -> Self {
        match m {
            Msg::HostInfo(i) => crate::Msg::HostInfo(i.into()),
            Msg::System(s) => crate::Msg::System(s.into()),
            Msg::Procs(p) => crate::Msg::Procs(p.into_iter().map(Into::into).collect()),
            Msg::ProcMeta(m) => crate::Msg::ProcMeta(m),
            Msg::Users(u) => crate::Msg::Users(u),
        }
    }
}

/// Encode a datagram as a v2 agent did. Only for tests of v2 compatibility.
#[doc(hidden)]
pub fn encode(header: &Header, msg: &Msg) -> crate::Result<Vec<u8>> {
    let out = vec![crate::MAGIC[0], crate::MAGIC[1], 2, 0];
    Ok(postcard::to_extend(&(header, msg), out)?)
}
