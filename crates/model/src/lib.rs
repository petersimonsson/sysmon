//! sysmon state: turns raw counters into rates and history, independent of
//! whether frames come from the network or from a recording.

mod host;
mod source;

pub use host::{HistoryPoint, HostModel, ProcRow, Snapshot};
pub use source::{DataSource, LiveSource, ReplaySource, SourceKind};
