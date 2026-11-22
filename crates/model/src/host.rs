use std::collections::{HashMap, VecDeque};

use crate::series::{self, Metric, ProcFrame, ProcPoint, SeriesTarget};

use sysmon_ingest::Event;
use sysmon_proto::{CpuCounters, Frame, HostInfo, MemInfo, ProcKey, ProcMeta, SystemSample};

/// Number of history points kept for sparklines and process graphs.
pub const HISTORY_LEN: usize = 600;
/// The time [`HISTORY_LEN`] covers at the default 1 Hz sampling.
pub const HISTORY_WINDOW_S: u64 = 600;
const SECTOR_BYTES: f64 = 512.0;

/// Everything the UI shows for one host.
#[derive(Debug, Default)]
pub struct HostModel {
    pub host_id: u64,
    pub info: Option<HostInfo>,
    pub snapshot: Snapshot,
    pub history: VecDeque<HistoryPoint>,
    /// Every process in each of the last [`HISTORY_LEN`] samples, for graphs.
    pub proc_history: VecDeque<ProcFrame>,
    pub frames_received: u64,
    pub frames_incomplete: u64,
    /// Sample timestamp of the last frame that had one.
    pub last_seen_ns: u64,

    meta: HashMap<ProcKey, ProcMeta>,
    users: HashMap<u32, String>,
    prev: Option<Prev>,
}

#[derive(Debug)]
struct Prev {
    boot_id: u128,
    system: SystemSample,
    /// CPU ticks per process and the sample time they were read at. Kept per
    /// process so rows carried over a lost chunk still get correct rates.
    proc_ticks: HashMap<ProcKey, (u64, u64)>,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub ts_unix_ns: u64,
    /// Aggregate first, then one entry per core, as 0..=100.
    pub cpu_pct: Vec<f32>,
    pub mem: MemInfo,
    pub load: [f32; 3],
    pub net: Vec<NetRate>,
    pub disks: Vec<DiskRate>,
    pub procs: Vec<ProcRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcRow {
    pub key: ProcKey,
    pub ppid: u32,
    pub state: char,
    pub cpu_pct: f32,
    /// Resident memory (RES in htop).
    pub rss_kib: u64,
    /// Virtual size (VIRT); `None` from v1 agents.
    pub virt_kib: Option<u64>,
    /// Resident shared memory (SHR); `None` from v1 agents, or if the agent
    /// couldn't read it.
    pub shr_kib: Option<u64>,
    pub threads: u32,
    pub comm: String,
    pub cmdline: Option<String>,
    pub uid: Option<u32>,
    pub user: Option<String>,
    /// Carried over from the previous sample because its chunk was lost.
    pub stale: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetRate {
    pub name: String,
    pub rx_bytes_per_s: f64,
    pub tx_bytes_per_s: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiskRate {
    pub name: String,
    pub read_bytes_per_s: f64,
    pub write_bytes_per_s: f64,
    /// Share of the interval the device was busy, 0..=100.
    pub busy_pct: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HistoryPoint {
    pub ts_unix_ns: u64,
    pub cpu_pct: f32,
    pub mem_used_kib: u64,
    pub net_rx_bytes_per_s: f64,
    pub net_tx_bytes_per_s: f64,
    pub disk_read_bytes_per_s: f64,
    pub disk_write_bytes_per_s: f64,
}

impl HostModel {
    pub fn new(host_id: u64) -> Self {
        Self {
            host_id,
            ..Default::default()
        }
    }

    pub fn name(&self) -> String {
        self.info
            .as_ref()
            .map(|i| i.hostname.clone())
            .unwrap_or_else(|| format!("{:016x}", self.host_id))
    }

    pub fn apply(&mut self, event: Event) {
        match event {
            Event::HostInfo { info, .. } => self.info = Some(info),
            Event::ProcMeta { meta, .. } => {
                for m in meta {
                    self.meta.insert(m.key, m);
                }
            }
            Event::Users { users, .. } => {
                for u in users {
                    self.users.insert(u.uid, u.name);
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
        let Some(system) = frame.system else {
            return;
        };
        let ts = system.ts_unix_ns;
        self.last_seen_ns = ts;

        let clk_tck = self.info.as_ref().map_or(100, |i| i.clk_tck) as f64;
        let page_kib = self.info.as_ref().map_or(4, |i| i.page_size / 1024) as u64;

        let prev = self.prev.take().filter(|p| p.boot_id == frame.boot_id);
        let dt_s = prev
            .as_ref()
            .map(|p| ts.saturating_sub(p.system.ts_unix_ns) as f64 / 1e9)
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
        let (net, disks) = match (&prev, dt_s) {
            (Some(p), Some(dt)) => (
                net_rates(&p.system, &system, dt),
                disk_rates(&p.system, &system, dt),
            ),
            _ => (Vec::new(), Vec::new()),
        };

        let mut proc_ticks = HashMap::with_capacity(frame.procs.len());
        let mut procs: Vec<ProcRow> = frame
            .procs
            .into_iter()
            .map(|p| {
                let key = p.key();
                let ticks = p.utime + p.stime;
                proc_ticks.insert(key, (ticks, ts));
                let cpu = prev
                    .as_ref()
                    .and_then(|prev| prev.proc_ticks.get(&key))
                    .map_or(0.0, |&(before, before_ts)| {
                        let dt = ts.saturating_sub(before_ts) as f64 / 1e9;
                        if dt <= 0.0 {
                            return 0.0;
                        }
                        (ticks.saturating_sub(before) as f64 / clk_tck / dt * 100.0) as f32
                    });
                let meta = self.meta.get(&key);
                let uid = meta.map(|m| m.uid);
                ProcRow {
                    key,
                    ppid: p.ppid,
                    state: p.state as char,
                    cpu_pct: cpu,
                    rss_kib: p.rss_pages * page_kib,
                    virt_kib: p.vsize_bytes.map(|b| b / 1024),
                    shr_kib: p.shared_pages.map(|s| s * page_kib),
                    threads: p.threads,
                    comm: p.comm,
                    cmdline: meta.map(|m| m.cmdline.clone()),
                    uid,
                    user: uid.and_then(|u| self.users.get(&u).cloned()),
                    stale: false,
                }
            })
            .collect();

        // Chunks were lost: keep the previous rows that didn't arrive, rather
        // than having processes flicker out of the table. A complete frame
        // drops them if they really exited.
        if !frame.complete
            && let Some(p) = &prev
        {
            for row in &self.snapshot.procs {
                if !proc_ticks.contains_key(&row.key)
                    && let Some(&t) = p.proc_ticks.get(&row.key)
                {
                    proc_ticks.insert(row.key, t);
                    procs.push(ProcRow {
                        stale: true,
                        ..row.clone()
                    });
                }
            }
        }

        // Forget metadata for processes that have exited.
        if frame.complete {
            self.meta.retain(|k, _| proc_ticks.contains_key(k));
        }

        // Rows carried over a lost chunk are left out, so graphs show a gap
        // rather than a repeated value.
        let mut points: Vec<ProcPoint> = procs
            .iter()
            .filter(|r| !r.stale)
            .map(|r| ProcPoint {
                key: r.key,
                ppid: r.ppid,
                cpu_pct: r.cpu_pct,
                rss_kib: r.rss_kib,
                virt_kib: r.virt_kib.unwrap_or(series::UNKNOWN),
                shr_kib: r.shr_kib.unwrap_or(series::UNKNOWN),
                threads: r.threads,
            })
            .collect();
        points.sort_by_key(|p| p.key);
        self.proc_history.push_back(ProcFrame {
            ts_unix_ns: ts,
            mem_total_kib: system.mem.total,
            procs: points,
        });
        while self.proc_history.len() > HISTORY_LEN {
            self.proc_history.pop_front();
        }

        let mem = system.mem;
        self.history.push_back(HistoryPoint {
            ts_unix_ns: ts,
            cpu_pct: cpu_pct.first().copied().unwrap_or(0.0),
            mem_used_kib: mem.total.saturating_sub(mem.available),
            net_rx_bytes_per_s: net.iter().map(|n| n.rx_bytes_per_s).sum(),
            net_tx_bytes_per_s: net.iter().map(|n| n.tx_bytes_per_s).sum(),
            disk_read_bytes_per_s: disks.iter().map(|d| d.read_bytes_per_s).sum(),
            disk_write_bytes_per_s: disks.iter().map(|d| d.write_bytes_per_s).sum(),
        });
        while self.history.len() > HISTORY_LEN {
            self.history.pop_front();
        }

        self.snapshot = Snapshot {
            ts_unix_ns: ts,
            cpu_pct,
            mem,
            load: system.load,
            net,
            disks,
            procs,
        };
        self.prev = Some(Prev {
            boot_id: frame.boot_id,
            system,
            proc_ticks,
        });
    }
}

impl HostModel {
    /// A graph line for `target` covering samples taken at or after `since_ns`.
    pub fn series(
        &self,
        target: SeriesTarget,
        metric: Metric,
        since_ns: u64,
    ) -> Vec<(u64, Option<f32>)> {
        let start = self
            .proc_history
            .partition_point(|f| f.ts_unix_ns < since_ns);
        series::series(self.proc_history.range(start..), target, metric)
    }

    /// The target's value and member count in the latest sample.
    pub fn latest(&self, target: SeriesTarget, metric: Metric) -> Option<(f32, usize)> {
        let f = self.proc_history.back()?;
        Some((f.sample(target, metric)?, f.members(target)))
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

fn net_rates(before: &SystemSample, now: &SystemSample, dt: f64) -> Vec<NetRate> {
    now.net
        .iter()
        .filter_map(|n| {
            let b = before.net.iter().find(|b| b.name == n.name)?;
            Some(NetRate {
                name: n.name.clone(),
                rx_bytes_per_s: n.rx_bytes.saturating_sub(b.rx_bytes) as f64 / dt,
                tx_bytes_per_s: n.tx_bytes.saturating_sub(b.tx_bytes) as f64 / dt,
            })
        })
        .collect()
}

fn disk_rates(before: &SystemSample, now: &SystemSample, dt: f64) -> Vec<DiskRate> {
    now.disks
        .iter()
        .filter_map(|d| {
            let b = before.disks.iter().find(|b| b.name == d.name)?;
            Some(DiskRate {
                name: d.name.clone(),
                read_bytes_per_s: d.sectors_read.saturating_sub(b.sectors_read) as f64
                    * SECTOR_BYTES
                    / dt,
                write_bytes_per_s: d.sectors_written.saturating_sub(b.sectors_written) as f64
                    * SECTOR_BYTES
                    / dt,
                busy_pct: (d.io_ms.saturating_sub(b.io_ms) as f64 / (dt * 1000.0) * 100.0)
                    .min(100.0) as f32,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysmon_proto::{DiskStat, NetIf, ProcSample};

    fn proc(pid: u32, ticks: u64) -> ProcSample {
        ProcSample {
            pid,
            ppid: 1,
            starttime: 5,
            state: b'R',
            utime: ticks,
            stime: 0,
            rss_pages: 1,
            threads: 1,
            comm: format!("p{pid}"),
            vsize_bytes: Some(1 << 30),
            shared_pages: Some(100),
        }
    }

    fn frame(
        seq: u32,
        ts_s: u64,
        busy: u64,
        idle: u64,
        procs: Vec<ProcSample>,
        complete: bool,
    ) -> Event {
        Event::Frame(Frame {
            host_id: 1,
            boot_id: 1,
            seq,
            system: Some(SystemSample {
                ts_unix_ns: ts_s * 1_000_000_000,
                cpus: vec![CpuCounters {
                    user: busy,
                    idle,
                    ..Default::default()
                }],
                net: vec![NetIf {
                    name: "eth0".into(),
                    rx_bytes: ts_s * 1000,
                    tx_bytes: ts_s * 10,
                    rx_packets: 0,
                    tx_packets: 0,
                }],
                disks: vec![DiskStat {
                    name: "sda".into(),
                    sectors_read: ts_s * 2,
                    sectors_written: 0,
                    io_ms: ts_s * 250,
                }],
                ..Default::default()
            }),
            procs,
            complete,
        })
    }

    #[test]
    fn computes_rates_from_counter_deltas() {
        let mut m = HostModel::new(1);
        m.apply(frame(0, 100, 1000, 1000, vec![proc(10, 0)], true));
        // 2 s later: 150 busy + 50 idle jiffies; the process used 100 ticks = 1 s.
        m.apply(frame(1, 102, 1150, 1050, vec![proc(10, 100)], true));

        let s = &m.snapshot;
        assert_eq!(s.cpu_pct, vec![75.0]);
        assert_eq!(s.procs[0].cpu_pct, 50.0);
        // 4 KiB pages without HostInfo; VIRT arrives in bytes.
        assert_eq!(s.procs[0].virt_kib, Some(1 << 20));
        assert_eq!(s.procs[0].shr_kib, Some(400));
        assert_eq!(s.net[0].rx_bytes_per_s, 1000.0);
        assert_eq!(s.net[0].tx_bytes_per_s, 10.0);
        assert_eq!(s.disks[0].read_bytes_per_s, 1024.0);
        assert_eq!(s.disks[0].busy_pct, 25.0);
        assert_eq!(m.history.len(), 2);
        assert_eq!(m.history[1].net_rx_bytes_per_s, 1000.0);
    }

    #[test]
    fn lost_frame_only_lengthens_interval() {
        let mut m = HostModel::new(1);
        m.apply(frame(0, 100, 0, 0, vec![proc(10, 0)], true));
        // seq 1 lost; seq 2 arrives 2 s later.
        m.apply(frame(2, 102, 100, 100, vec![proc(10, 200)], true));
        assert_eq!(m.snapshot.cpu_pct, vec![50.0]);
        assert_eq!(m.snapshot.procs[0].cpu_pct, 100.0);
    }

    #[test]
    fn proc_history_is_bounded_and_skips_stale_rows() {
        let mut m = HostModel::new(1);
        m.apply(frame(0, 100, 0, 0, vec![proc(10, 0), proc(11, 0)], true));
        m.apply(frame(1, 101, 0, 0, vec![proc(10, 100)], false));
        let target = SeriesTarget::Process(proc(11, 0).key());
        let s = m.series(target, Metric::Cpu, 0);
        assert_eq!(s.len(), 2);
        assert!(s[0].1.is_some());
        assert_eq!(s[1].1, None, "carried-over row is a gap, not a value");
        assert_eq!(m.series(target, Metric::Cpu, 101 * 1_000_000_000).len(), 1);

        for i in 0..(HISTORY_LEN as u64 + 50) {
            m.apply(frame(2 + i as u32, 102 + i, 0, 0, vec![proc(10, i)], true));
        }
        assert_eq!(m.proc_history.len(), HISTORY_LEN);
        let p10 = SeriesTarget::Process(proc(10, 0).key());
        assert_eq!(m.latest(p10, Metric::Threads), Some((1.0, 1)));
    }

    #[test]
    fn rows_in_lost_chunks_are_carried_forward() {
        let mut m = HostModel::new(1);
        m.apply(frame(0, 100, 0, 0, vec![proc(10, 0), proc(11, 0)], true));
        // Process 11's chunk is lost.
        m.apply(frame(1, 101, 0, 0, vec![proc(10, 50)], false));
        let rows: Vec<_> = m
            .snapshot
            .procs
            .iter()
            .map(|r| (r.key.pid, r.stale))
            .collect();
        assert_eq!(rows, vec![(10, false), (11, true)]);

        // It arrives again: its rate covers both intervals (100 ticks over 2 s).
        m.apply(frame(
            2,
            102,
            0,
            0,
            vec![proc(10, 100), proc(11, 100)],
            true,
        ));
        let p11 = m.snapshot.procs.iter().find(|r| r.key.pid == 11).unwrap();
        assert_eq!((p11.cpu_pct, p11.stale), (50.0, false));

        // A complete frame without it means it exited.
        m.apply(frame(3, 103, 0, 0, vec![proc(10, 150)], true));
        assert_eq!(m.snapshot.procs.len(), 1);
    }
}
