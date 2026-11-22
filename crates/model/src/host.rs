use std::collections::{HashMap, VecDeque};

use sysmon_ingest::Event;
use sysmon_proto::{CpuCounters, Frame, HostInfo, MemInfo, ProcKey, ProcMeta, SystemSample};

/// Number of history points kept for sparklines (10 minutes at 1 Hz).
const HISTORY_LEN: usize = 600;

/// Everything the UI shows for one host.
#[derive(Debug, Default)]
pub struct HostModel {
    pub host_id: u64,
    pub info: Option<HostInfo>,
    pub snapshot: Snapshot,
    pub history: VecDeque<HistoryPoint>,
    pub frames_received: u64,
    pub frames_incomplete: u64,
    /// Receive timestamp of the last frame (live), or sample timestamp (replay).
    pub last_seen_ns: u64,

    meta: HashMap<ProcKey, ProcMeta>,
    prev: Option<Prev>,
}

#[derive(Debug)]
struct Prev {
    boot_id: u128,
    system: SystemSample,
    proc_ticks: HashMap<ProcKey, u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub ts_unix_ns: u64,
    /// Aggregate first, then one entry per core, as 0..=100.
    pub cpu_pct: Vec<f32>,
    pub mem: MemInfo,
    pub load: [f32; 3],
    pub procs: Vec<ProcRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcRow {
    pub key: ProcKey,
    pub ppid: u32,
    pub state: char,
    pub cpu_pct: f32,
    pub rss_kib: u64,
    pub threads: u32,
    pub comm: String,
    pub cmdline: Option<String>,
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HistoryPoint {
    pub ts_unix_ns: u64,
    pub cpu_pct: f32,
    pub mem_used_kib: u64,
}

impl HostModel {
    pub fn new(host_id: u64) -> Self {
        Self {
            host_id,
            ..Default::default()
        }
    }

    pub fn apply(&mut self, event: Event) {
        match event {
            Event::HostInfo { info, .. } => self.info = Some(info),
            Event::ProcMeta { meta, .. } => {
                for m in meta {
                    self.meta.insert(m.key, m);
                }
            }
            Event::Frame(frame) => self.apply_frame(frame),
        }
    }

    fn apply_frame(&mut self, frame: Frame) {
        self.frames_received += 1;
        if !frame.complete {
            self.frames_incomplete += 1;
        }
        // Without the system chunk there is no timestamp to compute rates against.
        // TODO: carry forward rows for processes in lost chunks instead of dropping them.
        let Some(system) = frame.system else {
            return;
        };
        self.last_seen_ns = system.ts_unix_ns;

        let clk_tck = self.info.as_ref().map_or(100, |i| i.clk_tck) as f64;
        let page_kib = self.info.as_ref().map_or(4, |i| i.page_size / 1024) as u64;

        let prev = self.prev.take().filter(|p| p.boot_id == frame.boot_id);
        let dt_s = prev
            .as_ref()
            .map(|p| system.ts_unix_ns.saturating_sub(p.system.ts_unix_ns) as f64 / 1e9)
            .filter(|&dt| dt > 0.0);

        let cpu_pct = match &prev {
            Some(p) => system
                .cpus
                .iter()
                .zip(&p.system.cpus)
                .map(|(now, before)| cpu_busy_pct(before, now))
                .collect(),
            None => vec![0.0; system.cpus.len()],
        };

        let mut proc_ticks = HashMap::with_capacity(frame.procs.len());
        let procs = frame
            .procs
            .into_iter()
            .map(|p| {
                let key = p.key();
                let ticks = p.utime + p.stime;
                proc_ticks.insert(key, ticks);
                let cpu = match (&prev, dt_s) {
                    (Some(prev), Some(dt)) => prev.proc_ticks.get(&key).map_or(0.0, |&before| {
                        (ticks.saturating_sub(before) as f64 / clk_tck / dt * 100.0) as f32
                    }),
                    _ => 0.0,
                };
                let meta = self.meta.get(&key);
                ProcRow {
                    key,
                    ppid: p.ppid,
                    state: p.state as char,
                    cpu_pct: cpu,
                    rss_kib: p.rss_pages * page_kib,
                    threads: p.threads,
                    comm: p.comm,
                    cmdline: meta.map(|m| m.cmdline.clone()),
                    uid: meta.map(|m| m.uid),
                }
            })
            .collect();

        // Forget metadata for processes that have exited.
        self.meta.retain(|k, _| proc_ticks.contains_key(k));

        let mem = system.mem;
        self.history.push_back(HistoryPoint {
            ts_unix_ns: system.ts_unix_ns,
            cpu_pct: cpu_pct.first().copied().unwrap_or(0.0),
            mem_used_kib: mem.total.saturating_sub(mem.available),
        });
        while self.history.len() > HISTORY_LEN {
            self.history.pop_front();
        }

        self.snapshot = Snapshot {
            ts_unix_ns: system.ts_unix_ns,
            cpu_pct,
            mem,
            load: system.load,
            procs,
        };
        self.prev = Some(Prev {
            boot_id: frame.boot_id,
            system,
            proc_ticks,
        });
    }
}

fn cpu_busy_pct(before: &CpuCounters, now: &CpuCounters) -> f32 {
    let total = now.total().saturating_sub(before.total());
    if total == 0 {
        return 0.0;
    }
    let busy = now.busy().saturating_sub(before.busy());
    busy as f32 / total as f32 * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysmon_proto::ProcSample;

    fn frame(seq: u32, ts_s: u64, cpu_busy: u64, cpu_idle: u64, proc_ticks: u64) -> Event {
        Event::Frame(Frame {
            host_id: 1,
            boot_id: 1,
            seq,
            system: Some(SystemSample {
                ts_unix_ns: ts_s * 1_000_000_000,
                cpus: vec![CpuCounters {
                    user: cpu_busy,
                    idle: cpu_idle,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            procs: vec![ProcSample {
                pid: 10,
                ppid: 1,
                starttime: 5,
                state: b'R',
                utime: proc_ticks,
                stime: 0,
                rss_pages: 1,
                threads: 1,
                comm: "x".into(),
            }],
            complete: true,
        })
    }

    #[test]
    fn computes_rates_from_counter_deltas() {
        let mut m = HostModel::new(1);
        m.apply(frame(0, 100, 1000, 1000, 0));
        // 2 s later: 150 busy + 50 idle jiffies; the process used 100 ticks = 1 s.
        m.apply(frame(1, 102, 1150, 1050, 100));

        assert_eq!(m.snapshot.cpu_pct, vec![75.0]);
        assert_eq!(m.snapshot.procs[0].cpu_pct, 50.0);
        assert_eq!(m.history.len(), 2);
    }

    #[test]
    fn lost_frame_only_lengthens_interval() {
        let mut m = HostModel::new(1);
        m.apply(frame(0, 100, 0, 0, 0));
        // seq 1 lost; seq 2 arrives 2 s later.
        m.apply(frame(2, 102, 100, 100, 200));
        assert_eq!(m.snapshot.cpu_pct, vec![50.0]);
        assert_eq!(m.snapshot.procs[0].cpu_pct, 100.0);
    }
}
