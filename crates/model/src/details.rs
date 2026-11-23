//! Everything known about one process, gathered for the details pane.

use sysmon_proto::ProcKey;

use crate::host::{HostModel, ProcRow, ThreadRow};
use crate::logs::{LogKind, LogRow};

/// One process of the latest sample, with its relatives.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcDetails<'a> {
    pub row: &'a ProcRow,
    /// The thread asked about, when the key was a thread's.
    pub thread: Option<&'a ThreadRow>,
    /// The parent, if it's in the sample (pid 0 and filtered-out parents
    /// aren't).
    pub parent: Option<&'a ProcRow>,
    /// Direct children, by pid.
    pub children: Vec<&'a ProcRow>,
    /// Threads other than the main one, by tid; empty unless the agent
    /// sends threads.
    pub threads: Vec<&'a ThreadRow>,
    /// When it started, by the host's wall clock (agents v4 and newer).
    pub started_unix_ns: Option<u64>,
    /// RES as a share of the host's memory, 0..=100.
    pub mem_pct: Option<f32>,
}

impl HostModel {
    /// The process `key` in the latest sample, or for a thread's key, the
    /// process it belongs to.
    pub fn details(&self, key: ProcKey) -> Option<ProcDetails<'_>> {
        let s = &self.snapshot;
        let (row, thread) = match s.procs.iter().find(|r| r.key == key) {
            Some(row) => (row, None),
            None => {
                let t = s.threads.iter().find(|t| t.key == key)?;
                (s.procs.iter().find(|r| r.key.pid == t.tgid)?, Some(t))
            }
        };
        let pid = row.key.pid;
        let parent = (row.ppid != 0)
            .then(|| s.procs.iter().find(|r| r.key.pid == row.ppid))
            .flatten();
        let mut children: Vec<&ProcRow> = s.procs.iter().filter(|r| r.ppid == pid).collect();
        children.sort_by_key(|r| r.key.pid);
        let mut threads: Vec<&ThreadRow> = s.threads.iter().filter(|t| t.tgid == pid).collect();
        threads.sort_by_key(|t| t.key.pid);
        let clk_tck = self.info.as_ref().map_or(100, |i| i.clk_tck);
        let mem_pct = (s.mem.total > 0)
            .then(|| (row.rss_kib as f64 / s.mem.total as f64 * 100.0).min(100.0) as f32);
        Some(ProcDetails {
            row,
            thread,
            parent,
            children,
            threads,
            started_unix_ns: row.started_unix_ns(clk_tck, s.boot_unix_ns),
            mem_pct,
        })
    }
}

impl crate::logs::Logs {
    /// Journal lines logged by `pid`, oldest first. With the process's
    /// start time, lines from before it are left out: they're another
    /// process's that had the same pid.
    pub fn for_pid(
        &self,
        pid: u32,
        started_unix_ns: Option<u64>,
    ) -> impl DoubleEndedIterator<Item = &LogRow> {
        let since = started_unix_ns.unwrap_or(0);
        self.rows().iter().filter(move |r| {
            matches!(&r.kind, LogKind::Line(e) if e.pid == Some(pid)) && r.ts_unix_ns >= since
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysmon_ingest::Event;
    use sysmon_proto::{
        CpuCounters, Frame, HostInfo, LogBatch, LogEntry, MemInfo, ProcSample, SystemSample,
        ThreadSample,
    };

    const SEC: u64 = 1_000_000_000;

    fn proc(pid: u32, ppid: u32, starttime: u64) -> ProcSample {
        ProcSample {
            pid,
            ppid,
            starttime,
            state: b'S',
            utime: 0,
            stime: 0,
            rss_pages: 256, // 1 MiB at 4 KiB pages
            threads: 1,
            comm: format!("p{pid}"),
            vsize_bytes: None,
            shared_pages: None,
            kernel_thread: Some(false),
        }
    }

    fn thread(tgid: u32, tid: u32) -> ThreadSample {
        ThreadSample {
            tgid,
            tid,
            starttime: 7,
            state: b'R',
            utime: 0,
            stime: 0,
            comm: format!("t{tid}"),
        }
    }

    /// A host 1000 s after boot, wall clock 100_000 s, with these processes.
    fn host(procs: Vec<ProcSample>, threads: Vec<ThreadSample>) -> HostModel {
        let mut m = HostModel::new(1);
        m.apply(Event::HostInfo {
            host_id: 1,
            info: HostInfo {
                hostname: "h".into(),
                kernel: "k".into(),
                cpu_count: 1,
                mem_total_kib: 4 << 20,
                clk_tck: 100,
                page_size: 4096,
                interval_ms: 1000,
                sends_threads: !threads.is_empty(),
            },
        });
        m.apply(Event::Frame(Frame {
            host_id: 1,
            boot_id: 1,
            seq: 0,
            system: Some(SystemSample {
                ts_unix_ns: 100_000 * SEC,
                boottime_ns: Some(1000 * SEC),
                cpus: vec![CpuCounters::default()],
                mem: MemInfo {
                    total: 4 << 20, // 4 GiB in KiB
                    ..Default::default()
                },
                ..Default::default()
            }),
            procs,
            threads,
            complete: true,
            received_ns: 0,
        }));
        m
    }

    fn key(pid: u32, starttime: u64) -> ProcKey {
        ProcKey { pid, starttime }
    }

    #[test]
    fn finds_the_parent_children_and_threads() {
        let m = host(
            vec![
                proc(1, 0, 1),
                proc(10, 1, 100),
                proc(12, 10, 200),
                proc(11, 10, 150),
                proc(20, 1, 300),
            ],
            vec![thread(10, 14), thread(10, 13), thread(20, 21)],
        );
        let d = m.details(key(10, 100)).unwrap();
        assert_eq!(d.row.key.pid, 10);
        assert_eq!(d.thread, None);
        assert_eq!(d.parent.map(|p| p.key.pid), Some(1));
        let kids: Vec<u32> = d.children.iter().map(|r| r.key.pid).collect();
        assert_eq!(kids, [11, 12]);
        let tids: Vec<u32> = d.threads.iter().map(|t| t.key.pid).collect();
        assert_eq!(tids, [13, 14]);
        // 100 ticks at 100 Hz: 1 s after boot (at 99_000 s).
        assert_eq!(d.started_unix_ns, Some(99_001 * SEC));
        // 1 MiB of 4 GiB.
        assert_eq!(d.mem_pct, Some(100.0 / 4096.0));

        // pid 1's parent is pid 0, which isn't a process.
        assert_eq!(m.details(key(1, 1)).unwrap().parent, None);
    }

    #[test]
    fn a_threads_key_gives_its_process() {
        let m = host(vec![proc(10, 1, 100)], vec![thread(10, 13)]);
        let d = m.details(key(13, 7)).unwrap();
        assert_eq!(d.row.key, key(10, 100));
        assert_eq!(d.thread.map(|t| t.key.pid), Some(13));
    }

    #[test]
    fn a_process_that_isnt_running_has_no_details() {
        let m = host(vec![proc(10, 1, 100)], vec![]);
        // Same pid, another start: a different process.
        assert_eq!(m.details(key(10, 99)), None);
        assert_eq!(m.details(key(11, 100)), None);
    }

    #[test]
    fn log_lines_from_before_the_start_belong_to_someone_else() {
        let mut m = host(vec![proc(10, 1, 100)], vec![]);
        let line = |ts_s: u64, pid: u32, message: &str| LogEntry {
            ts_unix_ns: ts_s * SEC,
            priority: 6,
            unit: None,
            ident: "x".into(),
            pid: Some(pid),
            message: message.into(),
            truncated: false,
        };
        m.logs.apply(
            1,
            LogBatch {
                run: 1,
                first_seq: 0,
                dropped: 0,
                entries: vec![
                    line(98_000, 10, "an earlier pid 10"),
                    line(99_500, 11, "someone else"),
                    line(99_600, 10, "mine"),
                    line(99_700, 10, "mine too"),
                ],
            },
            0,
        );
        let d = m.details(key(10, 100)).unwrap();
        let mine: Vec<&str> = m
            .logs
            .for_pid(10, d.started_unix_ns)
            .map(|r| match &r.kind {
                LogKind::Line(e) => e.message.as_str(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(mine, ["mine", "mine too"]);
        // Without a start time, every line with the pid counts.
        assert_eq!(m.logs.for_pid(10, None).count(), 3);
    }
}
