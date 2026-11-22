use crate::{ProcSample, SystemSample, ThreadSample};

/// A reassembled sample: everything that arrived for one `(host_id, seq)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub host_id: u64,
    pub boot_id: u128,
    pub seq: u32,
    /// `None` if chunk 0 was lost.
    pub system: Option<SystemSample>,
    pub procs: Vec<ProcSample>,
    /// Empty unless the agent sends threads (`HostInfo::sends_threads`).
    pub threads: Vec<ThreadSample>,
    /// `false` if any chunk was missing when the frame was emitted.
    pub complete: bool,
}
