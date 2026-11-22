use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use sysmon_proto::{Frame, Header, HostInfo, LogBatch, Msg, ProcMeta, UserName};

/// A sample this many behind the newest one seen means the agent restarted
/// (its first samples having been lost), rather than a late packet. UDP
/// reordering is a few packets at most.
const RESTART_GAP: u32 = 64;

/// Output of the assembler.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Frame(Frame),
    HostInfo {
        host_id: u64,
        info: HostInfo,
    },
    ProcMeta {
        host_id: u64,
        meta: Vec<ProcMeta>,
    },
    Users {
        host_id: u64,
        users: Vec<UserName>,
    },
    /// Journal lines. `received_ns` is the monitor's clock (the recorded
    /// receive time when replaying), which playback seeks by.
    Logs {
        host_id: u64,
        boot_id: u128,
        batch: LogBatch,
        received_ns: u64,
    },
}

impl Event {
    pub fn host_id(&self) -> u64 {
        match self {
            Event::Frame(f) => f.host_id,
            Event::HostInfo { host_id, .. }
            | Event::ProcMeta { host_id, .. }
            | Event::Users { host_id, .. }
            | Event::Logs { host_id, .. } => *host_id,
        }
    }
}

/// Reassembles chunked samples into [`Frame`]s.
///
/// A sample is emitted as soon as all its chunks have arrived. It is emitted
/// incomplete when a newer sample from the same host starts arriving, or
/// when it is older than `timeout`. Chunks for an already emitted sample are
/// dropped.
pub struct Assembler {
    timeout: Duration,
    hosts: HashMap<u64, HostState>,
    out: Vec<Event>,
}

struct HostState {
    boot_id: u128,
    /// Highest seq emitted so far; older chunks are late and dropped.
    emitted: Option<u32>,
    pending: BTreeMap<u32, Partial>,
}

struct Partial {
    first_seen: Instant,
    chunks: u16,
    received: Vec<bool>,
    frame: Frame,
}

impl Assembler {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            hosts: HashMap::new(),
            out: Vec::new(),
        }
    }

    /// Add a datagram received at `now` (for timeouts) and `recv_ns` (the
    /// monitor's clock, recorded on the frame).
    pub fn push(&mut self, h: Header, msg: Msg, now: Instant, recv_ns: u64) {
        match msg {
            Msg::HostInfo(info) => {
                self.out.push(Event::HostInfo {
                    host_id: h.host_id,
                    info,
                });
                return;
            }
            Msg::ProcMeta(meta) => {
                self.out.push(Event::ProcMeta {
                    host_id: h.host_id,
                    meta,
                });
                return;
            }
            Msg::Users(users) => {
                self.out.push(Event::Users {
                    host_id: h.host_id,
                    users,
                });
                return;
            }
            Msg::Logs(batch) => {
                self.out.push(Event::Logs {
                    host_id: h.host_id,
                    boot_id: h.boot_id,
                    batch,
                    received_ns: recv_ns,
                });
                return;
            }
            Msg::System(_) | Msg::Procs(_) | Msg::Threads(_) => {}
        }
        if h.chunk >= h.chunks {
            return;
        }

        let host = self.hosts.entry(h.host_id).or_insert_with(|| HostState {
            boot_id: h.boot_id,
            emitted: None,
            pending: BTreeMap::new(),
        });
        if host.boot_id != h.boot_id {
            // Host rebooted: sequence numbers and counters start over.
            flush(&mut self.out, host, u32::MAX, true);
            host.boot_id = h.boot_id;
            host.emitted = None;
        }
        // The agent restarted: same host and boot, but its numbering starts
        // again at 0. Seeing sample 0 again says so; a sample far behind the
        // last one does too, in case the new run's first packets were lost.
        // Anything else that's behind is a late or duplicated packet.
        let newest = host.pending.keys().next_back().copied().max(host.emitted);
        if let Some(newest) = newest
            && h.seq < newest
            && (h.seq == 0 || newest - h.seq > RESTART_GAP)
        {
            flush(&mut self.out, host, u32::MAX, true);
            host.emitted = None;
        }
        if host.emitted.is_some_and(|e| h.seq <= e) {
            return;
        }

        // A newer sample is arriving: whatever is older will not complete.
        flush(&mut self.out, host, h.seq, false);

        let partial = host.pending.entry(h.seq).or_insert_with(|| Partial {
            first_seen: now,
            chunks: h.chunks,
            received: vec![false; h.chunks as usize],
            frame: Frame {
                host_id: h.host_id,
                boot_id: h.boot_id,
                seq: h.seq,
                system: None,
                procs: Vec::new(),
                threads: Vec::new(),
                complete: false,
                received_ns: recv_ns,
            },
        });
        if h.chunks != partial.chunks || partial.received[h.chunk as usize] {
            return;
        }
        partial.received[h.chunk as usize] = true;
        partial.frame.received_ns = partial.frame.received_ns.max(recv_ns);
        match msg {
            Msg::System(s) => partial.frame.system = Some(s),
            Msg::Procs(p) => partial.frame.procs.extend(p),
            Msg::Threads(t) => partial.frame.threads.extend(t),
            _ => unreachable!(),
        }

        if partial.received.iter().all(|&r| r) {
            let mut p = host.pending.remove(&h.seq).unwrap();
            p.frame.complete = true;
            host.emitted = Some(h.seq);
            self.out.push(Event::Frame(p.frame));
        }
    }

    /// Emit samples that have waited longer than the timeout.
    pub fn flush_stale(&mut self, now: Instant) {
        for host in self.hosts.values_mut() {
            let stale: Vec<u32> = host
                .pending
                .iter()
                .filter(|(_, p)| now.duration_since(p.first_seen) >= self.timeout)
                .map(|(&seq, _)| seq)
                .collect();
            if let Some(&newest) = stale.last() {
                flush(&mut self.out, host, newest.saturating_add(1), false);
            }
        }
    }

    pub fn drain(&mut self) -> std::vec::Drain<'_, Event> {
        self.out.drain(..)
    }
}

/// Emit every pending sample with `seq < before` (or all of them if `all`).
fn flush(out: &mut Vec<Event>, host: &mut HostState, before: u32, all: bool) {
    let keep = if all {
        BTreeMap::new()
    } else {
        host.pending.split_off(&before)
    };
    for (seq, p) in std::mem::replace(&mut host.pending, keep) {
        host.emitted = Some(host.emitted.map_or(seq, |e| e.max(seq)));
        out.push(Event::Frame(p.frame));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysmon_proto::{ProcSample, SystemSample, decode, encode_sample};

    fn procs(n: u32) -> Vec<ProcSample> {
        (0..n)
            .map(|pid| ProcSample {
                pid,
                ppid: 1,
                starttime: pid as u64,
                state: b'R',
                utime: 1,
                stime: 1,
                rss_pages: 1,
                threads: 1,
                comm: "a-fairly-long-comm".into(),
                vsize_bytes: Some(1 << 30),
                shared_pages: Some(100),
                kernel_thread: None,
            })
            .collect()
    }

    fn datagrams(seq: u32, boot_id: u128) -> Vec<(Header, Msg)> {
        encode_sample(9, boot_id, seq, &SystemSample::default(), &procs(200), &[])
            .unwrap()
            .iter()
            .map(|d| decode(d).unwrap())
            .collect()
    }

    fn frames(a: &mut Assembler) -> Vec<Frame> {
        a.drain()
            .filter_map(|e| match e {
                Event::Frame(f) => Some(f),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn complete_sample_is_emitted_once() {
        let now = Instant::now();
        let mut a = Assembler::new(Duration::from_secs(1));
        let dgrams = datagrams(1, 0);
        for (h, m) in dgrams.iter().cloned() {
            a.push(h, m, now, 0);
        }
        let out = frames(&mut a);
        assert_eq!(out.len(), 1);
        assert!(out[0].complete);
        assert_eq!(out[0].procs.len(), 200);

        // Duplicates arriving late are ignored.
        let (h, m) = dgrams[1].clone();
        a.push(h, m, now, 0);
        assert!(frames(&mut a).is_empty());
    }

    #[test]
    fn threads_are_collected_into_the_frame() {
        let now = Instant::now();
        let threads: Vec<_> = (0..300)
            .map(|i| sysmon_proto::ThreadSample {
                tgid: i % 10,
                tid: 1000 + i,
                starttime: 1,
                state: b'S',
                utime: 1,
                stime: 1,
                comm: "worker".into(),
            })
            .collect();
        let dgrams: Vec<_> = encode_sample(9, 0, 1, &SystemSample::default(), &procs(50), &threads)
            .unwrap()
            .iter()
            .map(|d| decode(d).unwrap())
            .collect();
        let mut a = Assembler::new(Duration::from_secs(1));
        for (h, m) in dgrams.iter().cloned() {
            a.push(h, m, now, 0);
        }
        let out = frames(&mut a);
        assert_eq!(out.len(), 1);
        assert!(out[0].complete);
        assert_eq!((out[0].procs.len(), out[0].threads.len()), (50, 300));

        // Losing a thread chunk makes the sample incomplete.
        let mut a = Assembler::new(Duration::from_secs(1));
        for (h, m) in dgrams.iter().take(dgrams.len() - 1).cloned() {
            a.push(h, m, now, 0);
        }
        a.flush_stale(now + Duration::from_secs(2));
        let out = frames(&mut a);
        assert!(!out[0].complete);
        assert!(out[0].threads.len() < 300);
    }

    #[test]
    fn lost_chunk_is_flushed_by_next_sample() {
        let now = Instant::now();
        let mut a = Assembler::new(Duration::from_secs(1));
        for (h, m) in datagrams(1, 0).into_iter().skip(1) {
            a.push(h, m, now, 0);
        }
        assert!(frames(&mut a).is_empty());

        let (h, m) = datagrams(2, 0).remove(0);
        a.push(h, m, now, 0);
        let out = frames(&mut a);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq, 1);
        assert!(!out[0].complete);
        assert!(out[0].system.is_none());
    }

    #[test]
    fn stale_sample_is_flushed_by_timeout() {
        let now = Instant::now();
        let mut a = Assembler::new(Duration::from_secs(1));
        let (h, m) = datagrams(1, 0).remove(0);
        a.push(h, m, now, 0);
        a.flush_stale(now + Duration::from_millis(500));
        assert!(frames(&mut a).is_empty());
        a.flush_stale(now + Duration::from_secs(2));
        assert_eq!(frames(&mut a).len(), 1);
    }

    #[test]
    fn log_batches_pass_straight_through() {
        let mut a = Assembler::new(Duration::from_secs(1));
        let batch = sysmon_proto::LogBatch {
            run: 9,
            first_seq: 0,
            dropped: 0,
            entries: vec![],
        };
        let d = sysmon_proto::encode_logs(1, 2, 3, &batch).unwrap();
        let (h, m) = sysmon_proto::decode(&d[0]).unwrap();
        a.push(h, m, Instant::now(), 77);
        assert_eq!(
            a.drain().collect::<Vec<_>>(),
            [Event::Logs {
                host_id: 1,
                boot_id: 2,
                batch,
                received_ns: 77
            }]
        );
    }

    #[test]
    fn frames_record_when_the_monitor_received_them() {
        let now = Instant::now();
        let mut a = Assembler::new(Duration::from_secs(1));
        let dgrams = datagrams(1, 0);
        let n = dgrams.len() as u64;
        // Chunks arriving at monitor times 100, 101, ...; the frame keeps the newest.
        for (i, (h, m)) in dgrams.into_iter().enumerate() {
            a.push(h, m, now, 100 + i as u64);
        }
        assert_eq!(frames(&mut a)[0].received_ns, 100 + n - 1);
    }

    #[test]
    fn agent_restart_is_picked_up() {
        let now = Instant::now();
        let mut a = Assembler::new(Duration::from_secs(1));
        for seq in 0..500 {
            for (h, m) in datagrams(seq, 1) {
                a.push(h, m, now, 0);
            }
        }
        assert_eq!(frames(&mut a).len(), 500);

        // Same host and boot, numbering starts again at 0.
        for seq in 0..5 {
            for (h, m) in datagrams(seq, 1) {
                a.push(h, m, now, 0);
            }
        }
        let out = frames(&mut a);
        assert_eq!(
            out.iter().map(|f| f.seq).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4]
        );
        assert!(out.iter().all(|f| f.complete));
    }

    #[test]
    fn restart_is_picked_up_even_if_its_first_samples_are_lost() {
        let now = Instant::now();
        let mut a = Assembler::new(Duration::from_secs(1));
        for seq in 0..500 {
            for (h, m) in datagrams(seq, 1) {
                a.push(h, m, now, 0);
            }
        }
        frames(&mut a);
        // Samples 0-2 of the new run are lost; 3 is far behind 499.
        for (h, m) in datagrams(3, 1) {
            a.push(h, m, now, 0);
        }
        assert_eq!(
            frames(&mut a).iter().map(|f| f.seq).collect::<Vec<_>>(),
            [3]
        );
    }

    #[test]
    fn slightly_late_samples_are_still_dropped() {
        let now = Instant::now();
        let mut a = Assembler::new(Duration::from_secs(1));
        for seq in 0..100 {
            for (h, m) in datagrams(seq, 1) {
                a.push(h, m, now, 0);
            }
        }
        frames(&mut a);
        // A duplicate of sample 98 turning up late is not a restart.
        for (h, m) in datagrams(98, 1) {
            a.push(h, m, now, 0);
        }
        assert!(frames(&mut a).is_empty());
    }

    #[test]
    fn reboot_resets_sequence() {
        let now = Instant::now();
        let mut a = Assembler::new(Duration::from_secs(1));
        for (h, m) in datagrams(100, 1) {
            a.push(h, m, now, 0);
        }
        for (h, m) in datagrams(0, 2) {
            a.push(h, m, now, 0);
        }
        let out = frames(&mut a);
        assert_eq!(out.len(), 2);
        assert_eq!((out[1].boot_id, out[1].seq), (2, 0));
    }
}
