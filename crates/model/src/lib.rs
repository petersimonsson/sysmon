//! sysmon state: turns raw counters into rates and history, independent of
//! whether frames come from the network or from a recording.

mod clock;
mod host;
pub mod replay;
pub mod series;
mod source;
pub mod tree;

pub use clock::PlaybackClock;
pub use host::{
    DiskRate, HISTORY_LEN, HISTORY_WINDOW_S, HistoryPoint, HostModel, NetRate, ProcRow, Snapshot,
    ThreadRow,
};
pub use replay::{Control, Feed, ReplayHandle, ReplayStatus};
pub use series::{Metric, SeriesTarget};
pub use source::ReplaySource;
pub use tree::TreeLine;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;
    use sysmon_proto::{CpuCounters, SystemSample};

    const SEC: u64 = 1_000_000_000;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sysmon-model-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Two hosts sampling once a second for a minute, recorded as the monitor would.
    fn record(dir: &std::path::Path, base: u64) {
        let mut rec = sysmon_store::Recorder::new(dir);
        for s in 0..60u64 {
            for host in [1u64, 2] {
                let system = SystemSample {
                    ts_unix_ns: base + s * SEC,
                    cpus: vec![CpuCounters {
                        user: s * 50 * host,
                        idle: s * 100,
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                let recv = base + s * SEC + host * 1000;
                for d in sysmon_proto::encode_sample(host, 7, s as u32, &system, &[], &[]).unwrap()
                {
                    rec.append(host, 7, recv, &d).unwrap();
                }
            }
        }
    }

    #[test]
    fn replay_merges_hosts_in_receive_order_and_seeks() {
        let dir = tmp_dir("merge");
        let base = 1_795_330_800 * SEC;
        record(&dir, base);

        let mut src = ReplaySource::open(&dir).unwrap();
        assert_eq!(src.host_count(), 2);
        let (start, end) = src.time_range().unwrap();
        assert_eq!((start, end), (base + 1000, base + 59 * SEC + 2000));

        let mut order = Vec::new();
        while let Some(e) = src.next_event() {
            if let sysmon_ingest::Event::Frame(f) = e {
                order.push((f.seq, f.host_id));
            }
        }
        assert_eq!(order.len(), 120);
        assert_eq!(&order[..4], &[(0, 1), (0, 2), (1, 1), (1, 2)]);

        src.seek_to(base + 30 * SEC);
        let first = std::iter::from_fn(|| src.next_event()).find_map(|e| match e {
            sysmon_ingest::Event::Frame(f) => Some(f.seq),
            _ => None,
        });
        assert_eq!(first, Some(30));
    }

    #[test]
    fn engine_paces_pauses_and_seeks() {
        let dir = tmp_dir("engine");
        let base = 1_795_330_800 * SEC;
        record(&dir, base);

        // 60 s of data at 30x is about 2 s of wall time.
        let handle = replay::spawn(ReplaySource::open(&dir).unwrap(), 30.0).unwrap();
        let frames_within = |d: Duration| {
            let deadline = std::time::Instant::now() + d;
            let mut n = 0;
            while let Ok(f) = handle.feed.recv_deadline(deadline) {
                if matches!(f, Feed::Event(sysmon_ingest::Event::Frame(_))) {
                    n += 1;
                }
            }
            n
        };
        let early = frames_within(Duration::from_millis(500));
        assert!((10..90).contains(&early), "paced, not instant: {early}");

        handle.send(Control::SetPaused(true));
        let _ = frames_within(Duration::from_millis(150));
        assert_eq!(frames_within(Duration::from_millis(300)), 0);
        assert!(handle.status().paused);

        handle.send(Control::Seek(base + 50 * SEC));
        assert!(matches!(handle.feed.recv().unwrap(), Feed::Reset));
        // Paused at 50 s, the whole lead-in up to the target is delivered at
        // once: everything from the start, both hosts (51 samples each).
        let lead_in = frames_within(Duration::from_millis(300));
        assert!((100..=104).contains(&lead_in), "{lead_in}");
        let st = handle.status();
        assert_eq!(st.position_ns, base + 50 * SEC);

        handle.send(Control::SetSpeed(100.0));
        handle.send(Control::SetPaused(false));
        frames_within(Duration::from_millis(800));
        assert!(handle.status().finished);
    }

    #[test]
    fn recordings_from_v1_agents_still_replay() {
        let dir = tmp_dir("v1");
        let base = 1_795_330_800 * SEC;
        let mut rec = sysmon_store::Recorder::new(&dir);
        for seq in 0..3u32 {
            let h = |chunk| sysmon_proto::Header {
                host_id: 5,
                boot_id: 6,
                seq,
                chunk,
                chunks: 2,
            };
            let system = sysmon_proto::v1::SystemSample {
                ts_unix_ns: base + seq as u64 * SEC,
                ..Default::default()
            };
            let proc = sysmon_proto::v1::ProcSample {
                pid: 42,
                ppid: 1,
                starttime: 1,
                state: b'R',
                utime: seq as u64 * 100,
                stime: 0,
                rss_pages: 10,
                threads: 1,
                comm: "v1".into(),
            };
            let ts = base + seq as u64 * SEC;
            for (chunk, msg) in [
                sysmon_proto::v1::Msg::System(system),
                sysmon_proto::v1::Msg::Procs(vec![proc]),
            ]
            .into_iter()
            .enumerate()
            {
                let d = sysmon_proto::v1::encode(&h(chunk as u16), &msg).unwrap();
                rec.append(5, 6, ts, &d).unwrap();
            }
        }
        drop(rec);

        let mut src = ReplaySource::open(&dir).unwrap();
        let mut host = HostModel::new(5);
        let mut frames = 0;
        while let Some(e) = src.next_event() {
            frames += matches!(e, sysmon_ingest::Event::Frame(_)) as usize;
            host.apply(e);
        }
        assert_eq!(frames, 3);
        let p = &host.snapshot.procs[0];
        assert_eq!((p.key.pid, p.cpu_pct), (42, 100.0));
        assert_eq!((p.virt_kib, p.shr_kib), (None, None), "v1 has no VIRT/SHR");
    }
}
