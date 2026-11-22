//! Frozen protocol v3 types, kept so v3 agents and recordings stay readable.
//!
//! v3 is v4 without `SystemSample::boottime_ns`. Never change these types;
//! add a new version instead.

use serde::{Deserialize, Serialize};

use crate::v1::SystemSample;
use crate::{Header, HostInfo, ProcMeta, ProcSample, ThreadSample, UserName};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Msg {
    HostInfo(HostInfo),
    System(SystemSample),
    Procs(Vec<ProcSample>),
    ProcMeta(Vec<ProcMeta>),
    Users(Vec<UserName>),
    Threads(Vec<ThreadSample>),
}

impl From<Msg> for crate::Msg {
    fn from(m: Msg) -> Self {
        match m {
            Msg::HostInfo(i) => crate::Msg::HostInfo(i),
            Msg::System(s) => crate::Msg::System(s.into()),
            Msg::Procs(p) => crate::Msg::Procs(p),
            Msg::ProcMeta(m) => crate::Msg::ProcMeta(m),
            Msg::Users(u) => crate::Msg::Users(u),
            Msg::Threads(t) => crate::Msg::Threads(t),
        }
    }
}

/// Encode a datagram as a v3 agent did. Only for tests of v3 compatibility.
#[doc(hidden)]
pub fn encode(header: &Header, msg: &Msg) -> crate::Result<Vec<u8>> {
    let out = vec![crate::MAGIC[0], crate::MAGIC[1], 3, 0];
    Ok(postcard::to_extend(&(header, msg), out)?)
}
