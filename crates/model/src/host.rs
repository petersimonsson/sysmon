use std::collections::{HashMap, VecDeque};

use crate::series::{self, Metric, ProcFrame, ProcPoint, SeriesTarget, ThreadPoint};

use sysmon_ingest::Event;
use sysmon_proto::{CpuCounters, Frame, HostInfo, MemInfo, ProcKey, ProcMeta, SystemSample};

/// A wall-clock change this much larger or smaller than the boot-time
/// clock's means the wall clock was stepped.
const CLOCK_STEP_NS: i128 = 2_000_000_000;

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
    /// Sample timestamp of the last frame that had one (the agent's clock).
    pub last_seen_ns: u64,
    /// When the monitor last received a sample from this host (the
    /// monitor's clock); what "silent" is judged by.
    pub last_received_ns: u64,

    meta: HashMap<ProcKey, ProcMeta>,
    users: HashMap<u32, String>,
    prev: Option<Prev>,
}

#[derive(Debug)]
struct Prev {
    boot_id: u128,
    system: SystemSample,
    /// The sample's clock: the agent's boot time when it sends one (v4),
    /// otherwise its wall clock. Ordering and rates use this.
    clock: u64,
    /// Whether `clock` is the boot-time clock.
    mono: bool,
    /// CPU ticks per process and the sample time they were read at. Kept per
    /// process so rows carried over a lost chunk still get correct rates.
    proc_ticks: HashMap<ProcKey, (u64, u64)>,
    thread_ticks: HashMap<ProcKey, (u64, u64)>,
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
    /// Empty unless the agent sends threads.
    pub threads: Vec<ThreadRow>,
}

/// A thread other than its process's main thread.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreadRow {
    /// `(tid, starttime)`.
    pub key: ProcKey,
    /// The owning process's pid.
    pub tgid: u32,
    pub state: char,
    pub cpu_pct: f32,
    /// The thread's name.
    pub comm: String,
    /// Carried over because its chunk was lost.
    pub stale: bool,
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
    /// A kernel thread: the agent's `PF_KTHREAD` flag, or for agents older
    /// than protocol v3, kthreadd (pid 2) and its children.
    pub kernel_thread: bool,
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

    /// Whether this host's agent sends threads (`sysmon-agent --threads`).
    pub fn sends_threads(&self) -> bool {
        self.info.as_ref().is_some_and(|i| i.sends_threads)
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
            // Kept by the model from the next change on.
            Event::Logs { .. } => {}
        }
    }

    fn apply_frame(&mut self, frame: Frame) {
        self.frames_received += 1;
        self.last_received_ns = self.last_received_ns.max(frame.received_ns);
        if !frame.complete {
            self.frames_incomplete += 1;
        }
        // Without the system chunk there is no timestamp to compute rates against.
        let Some(system) = frame.system else {
            return;
        };
        let ts = system.ts_unix_ns;
        // Order and rates go by the agent's boot-time clock, which is never
        // stepped; the wall clock (`ts`) is only for showing times. Agents
        // older than v4 don't send it, so their wall clock is used instead.
        let (clock, mono) = match system.boottime_ns {
            Some(b) => (b, true),
            None => (ts, false),
        };
        // The previous sample counts only if it's from this boot and on the
        // same kind of clock (an agent upgraded to v4 mid-boot switches).
        let comparable = |p: &Prev| p.boot_id == frame.boot_id && p.mono == mono;
        // A sample that isn't newer than the last one is a late duplicate;
        // applying it would put history out of order.
        if self
            .prev
            .as_ref()
            .is_some_and(|p| comparable(p) && clock <= p.clock)
        {
            return;
        }
        // The wall clock was stepped (NTP, a date change, a VM resume): the
        // graphs' time axis no longer lines up, so start their history again.
        if let Some(p) = self.prev.as_ref().filter(|p| comparable(p) && mono) {
            let wall = ts as i128 - p.system.ts_unix_ns as i128;
            let real = clock as i128 - p.clock as i128;
            if (wall - real).abs() > CLOCK_STEP_NS {
                self.history.clear();
                self.proc_history.clear();
            }
        }
        self.last_seen_ns = ts;

        let clk_tck = self.info.as_ref().map_or(100, |i| i.clk_tck) as f64;
        let page_kib = self.info.as_ref().map_or(4, |i| i.page_size / 1024) as u64;

        let prev = self.prev.take().filter(comparable);
        let dt_s = prev
            .as_ref()
            .map(|p| clock.saturating_sub(p.clock) as f64 / 1e9)
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

        // %CPU from the change in ticks since this key was last seen.
        let rate = |before: Option<&(u64, u64)>, ticks: u64| -> f32 {
            before.map_or(0.0, |&(before, before_clock)| {
                let dt = clock.saturating_sub(before_clock) as f64 / 1e9;
                if dt <= 0.0 {
                    return 0.0;
                }
                (ticks.saturating_sub(before) as f64 / clk_tck / dt * 100.0) as f32
            })
        };
        let mut proc_ticks = HashMap::with_capacity(frame.procs.len());
        let mut procs: Vec<ProcRow> = frame
            .procs
            .into_iter()
            .map(|p| {
                let key = p.key();
                // Values from the network: saturate rather than overflow.
                let ticks = p.utime.saturating_add(p.stime);
                proc_ticks.insert(key, (ticks, clock));
                let cpu = rate(
                    prev.as_ref().and_then(|prev| prev.proc_ticks.get(&key)),
                    ticks,
                );
                let meta = self.meta.get(&key);
                let uid = meta.map(|m| m.uid);
                ProcRow {
                    key,
                    ppid: p.ppid,
                    state: p.state as char,
                    cpu_pct: cpu,
                    rss_kib: p.rss_pages.saturating_mul(page_kib),
                    virt_kib: p.vsize_bytes.map(|b| b / 1024),
                    shr_kib: p.shared_pages.map(|s| s.saturating_mul(page_kib)),
                    threads: p.threads,
                    comm: p.comm,
                    cmdline: meta.map(|m| m.cmdline.clone()),
                    uid,
                    user: uid.and_then(|u| self.users.get(&u).cloned()),
                    stale: false,
                    kernel_thread: p.kernel_thread.unwrap_or(p.pid == 2 || p.ppid == 2),
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

        let mut thread_ticks = HashMap::with_capacity(frame.threads.len());
        let mut threads: Vec<ThreadRow> = frame
            .threads
            .into_iter()
            .map(|t| {
                let key = t.key();
                let ticks = t.utime.saturating_add(t.stime);
                thread_ticks.insert(key, (ticks, clock));
                ThreadRow {
                    key,
                    tgid: t.tgid,
                    state: t.state as char,
                    cpu_pct: rate(prev.as_ref().and_then(|p| p.thread_ticks.get(&key)), ticks),
                    comm: t.comm,
                    stale: false,
                }
            })
            .collect();
        if !frame.complete
            && let Some(p) = &prev
        {
            for row in &self.snapshot.threads {
                if !thread_ticks.contains_key(&row.key)
                    && let Some(&t) = p.thread_ticks.get(&row.key)
                {
                    thread_ticks.insert(row.key, t);
                    threads.push(ThreadRow {
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
            threads: {
                let mut t: Vec<ThreadPoint> = threads
                    .iter()
                    .filter(|t| !t.stale)
                    .map(|t| ThreadPoint {
                        key: t.key,
                        tgid: t.tgid,
                        cpu_pct: t.cpu_pct,
                    })
                    .collect();
                t.sort_by_key(|t| t.key);
                t
            },
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
            threads,
        };
        self.prev = Some(Prev {
            boot_id: frame.boot_id,
            system,
            clock,
            mono,
            proc_ticks,
            thread_ticks,
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
            kernel_thread: None,
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
            threads: Vec::new(),
            complete,
            received_ns: 0,
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

    fn thread(tgid: u32, tid: u32, ticks: u64) -> sysmon_proto::ThreadSample {
        sysmon_proto::ThreadSample {
            tgid,
            tid,
            starttime: 7,
            state: b'R',
            utime: ticks,
            stime: 0,
            comm: format!("t{tid}"),
        }
    }

    fn with_threads(e: Event, threads: Vec<sysmon_proto::ThreadSample>) -> Event {
        let Event::Frame(mut f) = e else {
            unreachable!()
        };
        f.threads = threads;
        Event::Frame(f)
    }

    #[test]
    fn thread_rows_get_their_own_rates_and_survive_lost_chunks() {
        let mut m = HostModel::new(1);
        m.apply(with_threads(
            frame(0, 100, 0, 0, vec![proc(10, 0)], true),
            vec![thread(10, 11, 0), thread(10, 12, 0)],
        ));
        // 2 s later: thread 11 used 100 ticks (1 s), thread 12 none.
        m.apply(with_threads(
            frame(1, 102, 0, 0, vec![proc(10, 100)], true),
            vec![thread(10, 11, 100), thread(10, 12, 0)],
        ));
        let t: Vec<_> = m
            .snapshot
            .threads
            .iter()
            .map(|t| (t.key.pid, t.tgid, t.cpu_pct))
            .collect();
        assert_eq!(t, [(11, 10, 50.0), (12, 10, 0.0)]);
        let s = m.series(
            SeriesTarget::Thread(m.snapshot.threads[0].key),
            Metric::Cpu,
            0,
        );
        assert_eq!(s.last().unwrap().1, Some(50.0));

        // Thread 12's chunk is lost: it's carried over, marked stale.
        m.apply(with_threads(
            frame(2, 103, 0, 0, vec![proc(10, 150)], false),
            vec![thread(10, 11, 150)],
        ));
        let stale: Vec<_> = m
            .snapshot
            .threads
            .iter()
            .map(|t| (t.key.pid, t.stale))
            .collect();
        assert_eq!(stale, [(11, false), (12, true)]);
    }

    #[test]
    fn kernel_threads_from_the_flag_or_the_kthreadd_rule() {
        let mut p2 = proc(2, 0);
        p2.ppid = 0;
        let mut kworker = proc(30, 0);
        kworker.ppid = 2;
        let mut flagged = proc(40, 0);
        flagged.kernel_thread = Some(true);
        let mut user_under_2 = proc(50, 0);
        user_under_2.ppid = 2;
        user_under_2.kernel_thread = Some(false);
        let mut m = HostModel::new(1);
        m.apply(frame(
            0,
            100,
            0,
            0,
            vec![p2, kworker, flagged, user_under_2, proc(10, 0)],
            true,
        ));
        let k: Vec<_> = m
            .snapshot
            .procs
            .iter()
            .map(|p| (p.key.pid, p.kernel_thread))
            .collect();
        assert_eq!(
            k,
            [(2, true), (30, true), (40, true), (50, false), (10, false)]
        );
    }

    /// `e` with the agent's boot-time clock at `secs`.
    fn at_boottime(e: Event, secs: u64) -> Event {
        let Event::Frame(mut f) = e else {
            unreachable!()
        };
        f.system.as_mut().unwrap().boottime_ns = Some(secs * 1_000_000_000);
        Event::Frame(f)
    }

    #[test]
    fn a_backward_wall_clock_step_doesnt_freeze_the_host() {
        let mut m = HostModel::new(1);
        // 10 s of samples, wall clock 10_000.., boot time 500..
        for i in 0..10u32 {
            let e = frame(
                i,
                10_000 + i as u64,
                0,
                0,
                vec![proc(10, i as u64 * 50)],
                true,
            );
            m.apply(at_boottime(e, 500 + i as u64));
        }
        assert_eq!(m.history.len(), 10);
        // The wall clock steps back an hour; the boot-time clock carries on.
        let mut applied = 0;
        for i in 0..60u32 {
            let before = m.snapshot.ts_unix_ns;
            let wall = 10_010 - 3600 + i as u64;
            let e = frame(
                10 + i,
                wall,
                0,
                0,
                vec![proc(10, (10 + i as u64) * 50)],
                true,
            );
            m.apply(at_boottime(e, 510 + i as u64));
            applied += (m.snapshot.ts_unix_ns != before) as u32;
        }
        assert_eq!(applied, 60, "every sample applied");
        // Rates follow the boot-time clock: 50 ticks per second is 50 %.
        assert_eq!(m.snapshot.procs[0].cpu_pct, 50.0);
        // History restarted at the step, so its times are in order.
        assert_eq!(m.history.len(), 60);
        assert!(
            m.history
                .iter()
                .zip(m.history.iter().skip(1))
                .all(|(a, b)| a.ts_unix_ns < b.ts_unix_ns)
        );
        assert_eq!(m.proc_history.len(), 60);
    }

    #[test]
    fn duplicates_by_boot_time_are_ignored_and_clocks_arent_mixed() {
        let mut m = HostModel::new(1);
        m.apply(at_boottime(
            frame(0, 10_000, 0, 0, vec![proc(10, 0)], true),
            500,
        ));
        m.apply(at_boottime(
            frame(1, 10_001, 0, 0, vec![proc(10, 100)], true),
            501,
        ));
        let before = m.history.len();
        // A late duplicate of sample 0, even with a newer-looking wall clock.
        m.apply(at_boottime(
            frame(0, 20_000, 0, 0, vec![proc(10, 0)], true),
            500,
        ));
        assert_eq!(m.history.len(), before);

        // An older agent (no boot time) then a v4 one, same boot: the first
        // v4 sample starts rates afresh instead of mixing the two clocks.
        let mut m = HostModel::new(1);
        m.apply(frame(0, 10_000, 0, 0, vec![proc(10, 0)], true));
        m.apply(at_boottime(
            frame(0, 10_001, 0, 0, vec![proc(10, 100)], true),
            500,
        ));
        assert_eq!(
            m.snapshot.procs[0].cpu_pct, 0.0,
            "no rate across clock kinds"
        );
        m.apply(at_boottime(
            frame(1, 10_002, 0, 0, vec![proc(10, 200)], true),
            501,
        ));
        assert_eq!(m.snapshot.procs[0].cpu_pct, 100.0);
    }

    #[test]
    fn samples_older_than_the_last_are_ignored() {
        let mut m = HostModel::new(1);
        m.apply(frame(0, 100, 0, 0, vec![proc(10, 0)], true));
        m.apply(frame(1, 101, 100, 0, vec![proc(10, 100)], true));
        let before = (m.snapshot.ts_unix_ns, m.history.len(), m.proc_history.len());
        // A late duplicate of sample 0 (e.g. mistaken for an agent restart).
        m.apply(frame(0, 100, 0, 0, vec![proc(10, 0)], true));
        assert_eq!(
            (m.snapshot.ts_unix_ns, m.history.len(), m.proc_history.len()),
            before
        );
        // Newer samples still apply, with rates against the last good one.
        m.apply(frame(2, 102, 200, 0, vec![proc(10, 150)], true));
        assert_eq!(m.snapshot.procs[0].cpu_pct, 50.0);
    }

    #[test]
    fn extreme_values_from_the_network_dont_panic() {
        let max = CpuCounters {
            user: u64::MAX,
            nice: u64::MAX,
            system: u64::MAX,
            idle: u64::MAX,
            iowait: u64::MAX,
            irq: u64::MAX,
            softirq: u64::MAX,
            steal: u64::MAX,
        };
        assert_eq!(max.total(), u64::MAX);
        let mut huge = proc(10, u64::MAX);
        huge.stime = u64::MAX;
        huge.rss_pages = u64::MAX;
        huge.shared_pages = Some(u64::MAX);
        let mut m = HostModel::new(1);
        for i in 0..3u32 {
            let Event::Frame(mut f) = frame(
                i,
                100 + i as u64,
                0,
                0,
                vec![huge.clone(), proc(11, 0)],
                true,
            ) else {
                unreachable!()
            };
            let sys = f.system.as_mut().unwrap();
            sys.cpus = vec![max];
            sys.mem.total = 1;
            sys.mem.available = u64::MAX;
            m.apply(Event::Frame(f));
        }
        assert_eq!(m.snapshot.procs[0].rss_kib, u64::MAX);
        let rows = m.snapshot.procs.clone();
        let collapsed = std::collections::HashSet::from([rows[0].key]);
        let _ = crate::tree::build(&rows, None, &collapsed);
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
