//! Per-process history and the time series graphed from it.
//!
//! History is kept frame-major: one [`ProcFrame`] per sample holding every
//! process seen in it. That makes a process's line and a subtree's total
//! both cheap to compute, since the subtree at each moment is taken from
//! that moment's parent links, so children that come and go are counted
//! only while they exist.

use std::collections::HashMap;

use sysmon_proto::ProcKey;

/// A table column that can be graphed over time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    Cpu,
    Rss,
    MemPct,
    Threads,
}

impl Metric {
    pub const ALL: [Metric; 4] = [Metric::Cpu, Metric::Rss, Metric::MemPct, Metric::Threads];

    pub fn label(self) -> &'static str {
        match self {
            Metric::Cpu => "%CPU",
            Metric::Rss => "RSS",
            Metric::MemPct => "%MEM",
            Metric::Threads => "Threads",
        }
    }
}

/// What a graph line shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeriesTarget {
    /// One process.
    Process(ProcKey),
    /// A process plus all of its descendants, summed.
    Subtree(ProcKey),
}

impl SeriesTarget {
    pub fn key(self) -> ProcKey {
        match self {
            SeriesTarget::Process(k) | SeriesTarget::Subtree(k) => k,
        }
    }
}

/// Every process in one sample.
#[derive(Debug, Clone, Default)]
pub struct ProcFrame {
    pub ts_unix_ns: u64,
    pub mem_total_kib: u64,
    /// Sorted by key.
    pub procs: Vec<ProcPoint>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProcPoint {
    pub key: ProcKey,
    pub ppid: u32,
    pub cpu_pct: f32,
    pub rss_kib: u64,
    pub threads: u32,
}

impl ProcFrame {
    fn get(&self, key: ProcKey) -> Option<&ProcPoint> {
        self.procs
            .binary_search_by(|p| p.key.cmp(&key))
            .ok()
            .map(|i| &self.procs[i])
    }

    fn value(&self, p: &ProcPoint, metric: Metric) -> f32 {
        match metric {
            Metric::Cpu => p.cpu_pct,
            Metric::Rss => p.rss_kib as f32,
            Metric::MemPct => {
                if self.mem_total_kib == 0 {
                    0.0
                } else {
                    p.rss_kib as f32 / self.mem_total_kib as f32 * 100.0
                }
            }
            Metric::Threads => p.threads as f32,
        }
    }

    /// The processes a target covers in this frame (a process, or a root
    /// and its descendants at this moment). `None` if the root isn't present:
    /// it hadn't started, had exited, or its chunk was lost.
    fn members_of(&self, target: SeriesTarget) -> Option<Vec<&ProcPoint>> {
        let root = self.get(target.key())?;
        if let SeriesTarget::Process(_) = target {
            return Some(vec![root]);
        }
        let mut children: HashMap<u32, Vec<&ProcPoint>> = HashMap::new();
        for p in &self.procs {
            if p.ppid != p.key.pid {
                children.entry(p.ppid).or_default().push(p);
            }
        }
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(p) = stack.pop() {
            out.push(p);
            if out.len() > self.procs.len() {
                break; // a ppid cycle; can't happen with real data
            }
            if let Some(kids) = children.get(&p.key.pid) {
                stack.extend(kids.iter().copied());
            }
        }
        Some(out)
    }

    /// The target's value in this frame (summed over a subtree), or `None`
    /// if it isn't present.
    pub fn sample(&self, target: SeriesTarget, metric: Metric) -> Option<f32> {
        self.members_of(target)
            .map(|ps| ps.iter().map(|p| self.value(p, metric)).sum())
    }

    /// How many processes the target covers in this frame.
    pub fn members(&self, target: SeriesTarget) -> usize {
        self.members_of(target).map_or(0, |m| m.len())
    }
}

/// One line: `(timestamp, value)` per frame in the history, with `None` for
/// frames where the target wasn't present (drawn as a gap).
pub fn series<'a>(
    frames: impl IntoIterator<Item = &'a ProcFrame>,
    target: SeriesTarget,
    metric: Metric,
) -> Vec<(u64, Option<f32>)> {
    frames
        .into_iter()
        .map(|f| (f.ts_unix_ns, f.sample(target, metric)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pid: u32) -> ProcKey {
        ProcKey { pid, starttime: 0 }
    }

    fn point(pid: u32, ppid: u32, cpu: f32, rss_kib: u64) -> ProcPoint {
        ProcPoint {
            key: key(pid),
            ppid,
            cpu_pct: cpu,
            rss_kib,
            threads: 2,
        }
    }

    fn frame(ts: u64, mem_total: u64, mut procs: Vec<ProcPoint>) -> ProcFrame {
        procs.sort_by_key(|p| p.key);
        ProcFrame {
            ts_unix_ns: ts,
            mem_total_kib: mem_total,
            procs,
        }
    }

    #[test]
    fn process_series_has_gaps_where_it_was_absent() {
        let frames = [
            frame(1, 1000, vec![point(10, 1, 5.0, 100)]),
            frame(2, 1000, vec![]),
            frame(3, 1000, vec![point(10, 1, 7.0, 100)]),
        ];
        let s = series(&frames, SeriesTarget::Process(key(10)), Metric::Cpu);
        assert_eq!(s, [(1, Some(5.0)), (2, None), (3, Some(7.0))]);
    }

    #[test]
    fn mem_pct_uses_each_frames_total() {
        let frames = [
            frame(1, 1000, vec![point(10, 1, 0.0, 100)]),
            frame(2, 2000, vec![point(10, 1, 0.0, 100)]),
        ];
        let s = series(&frames, SeriesTarget::Process(key(10)), Metric::MemPct);
        assert_eq!(s, [(1, Some(10.0)), (2, Some(5.0))]);
        let rss = series(&frames, SeriesTarget::Process(key(10)), Metric::Rss);
        assert_eq!(rss[0].1, Some(100.0));
        let thr = series(&frames, SeriesTarget::Process(key(10)), Metric::Threads);
        assert_eq!(thr[0].1, Some(2.0));
    }

    #[test]
    fn subtree_sums_descendants_present_at_each_moment() {
        // 10 ─┬─ 11 ── 12
        //     └─ 13          (13 only in the second frame; 99 is unrelated)
        let frames = [
            frame(
                1,
                1000,
                vec![
                    point(10, 1, 1.0, 10),
                    point(11, 10, 2.0, 10),
                    point(12, 11, 4.0, 10),
                    point(99, 1, 50.0, 10),
                ],
            ),
            frame(
                2,
                1000,
                vec![
                    point(10, 1, 1.0, 10),
                    point(11, 10, 2.0, 10),
                    point(12, 11, 4.0, 10),
                    point(13, 10, 8.0, 10),
                    point(99, 1, 50.0, 10),
                ],
            ),
            frame(3, 1000, vec![point(11, 1, 2.0, 10)]),
        ];
        let t = SeriesTarget::Subtree(key(10));
        assert_eq!(
            series(&frames, t, Metric::Cpu),
            [(1, Some(7.0)), (2, Some(15.0)), (3, None)]
        );
        assert_eq!(frames[1].members(t), 4);
        assert_eq!(frames[2].members(t), 0);
    }

    #[test]
    fn subtree_survives_cycles() {
        let frames = [frame(1, 1, vec![point(1, 2, 1.0, 0), point(2, 1, 1.0, 0)])];
        let s = series(&frames, SeriesTarget::Subtree(key(1)), Metric::Cpu);
        assert!(s[0].1.is_some());
    }
}
