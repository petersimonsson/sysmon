//! A host's journal lines (`sysmon-agent --logs`), in the agent's order.
//!
//! Batches are numbered, so lost datagrams show as a gap: a batch that
//! arrives ahead of one still missing waits up to [`REORDER_WAIT_NS`] for it
//! (UDP can reorder), then the missing lines are recorded as
//! [`LogKind::Lost`]. A new agent run (or boot) restarts the numbering.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

use sysmon_proto::{LogBatch, LogEntry, Msg};

/// Lines kept per host; older ones are dropped. About 5 MB at typical
/// line lengths.
pub const MAX_LOG_ROWS: usize = 20_000;
/// How long a batch ahead of a missing one waits before the gap is called lost.
pub const REORDER_WAIT_NS: u64 = 2_000_000_000;

#[derive(Debug, Clone, PartialEq)]
pub struct LogRow {
    /// Unique per host model and increasing, for selection.
    pub id: u64,
    /// When the monitor received it (its clock; the recorded receive time
    /// when replaying): what playback seeks to.
    pub received_ns: u64,
    /// When it was logged, by the agent's clock (for lost and dropped rows,
    /// the next line's time).
    pub ts_unix_ns: u64,
    pub kind: LogKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogKind {
    Line(LogEntry),
    /// This many lines didn't arrive (lost datagrams).
    Lost(u64),
    /// The agent dropped this many lines, over its rate limit.
    Dropped(u64),
}

#[derive(Debug, Default)]
pub struct Logs {
    rows: VecDeque<LogRow>,
    next_id: u64,
    /// The (boot, run) being followed, and the number of its next line.
    run: Option<(u128, u64)>,
    next_seq: u64,
    /// Batches ahead of a gap, by first line, with when they arrived.
    waiting: BTreeMap<u64, (u64, LogBatch)>,
    enabled: bool,
}

impl Logs {
    /// Whether the host sends logs (any batch, including heartbeats, seen).
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn rows(&self) -> &VecDeque<LogRow> {
        &self.rows
    }

    pub fn apply(&mut self, boot_id: u128, batch: LogBatch, received_ns: u64) {
        self.enabled = true;
        if self.run != Some((boot_id, batch.run)) {
            // A new agent run (or the first batch seen): whatever was
            // waiting for the old one won't come.
            self.release_waiting(u64::MAX);
            self.run = Some((boot_id, batch.run));
            // A monitor that starts mid-run picks up from here, not "lost".
            self.next_seq = batch.first_seq;
        }
        if batch.first_seq > self.next_seq {
            // Keep the first arrival: a repeat (like the heartbeats sent
            // while nothing is logged) mustn't restart the wait.
            self.waiting
                .entry(batch.first_seq)
                .or_insert((received_ns, batch));
        } else {
            self.append(batch, received_ns);
            self.drain_contiguous();
        }
        self.tick(received_ns);
    }

    /// Give up on gaps older than [`REORDER_WAIT_NS`] at monitor time `now_ns`.
    pub fn tick(&mut self, now_ns: u64) {
        self.release_waiting(now_ns.saturating_sub(REORDER_WAIT_NS));
    }

    /// Append batches that arrived before `cutoff_ns`, recording the gaps
    /// before them as lost.
    fn release_waiting(&mut self, cutoff_ns: u64) {
        while let Some(entry) = self.waiting.first_entry() {
            if entry.get().0 > cutoff_ns {
                break;
            }
            let (first, (received, batch)) = entry.remove_entry();
            if first > self.next_seq {
                let ts = batch.entries.first().map_or(received, |e| e.ts_unix_ns);
                self.push(received, ts, LogKind::Lost(first - self.next_seq));
                self.next_seq = first;
            }
            self.append(batch, received);
            self.drain_contiguous();
        }
    }

    fn drain_contiguous(&mut self) {
        while let Some(entry) = self.waiting.first_entry()
            && *entry.key() <= self.next_seq
        {
            let (received, batch) = entry.remove();
            self.append(batch, received);
        }
    }

    /// Append the part of `batch` not already seen.
    fn append(&mut self, batch: LogBatch, received_ns: u64) {
        let end = batch.first_seq + batch.entries.len() as u64;
        if end <= self.next_seq && !(batch.entries.is_empty() && batch.first_seq == self.next_seq) {
            return; // A duplicate, or late after its gap was called lost.
        }
        let skip = self.next_seq.saturating_sub(batch.first_seq) as usize;
        if batch.dropped > 0 && skip == 0 {
            let ts = batch.entries.first().map_or(received_ns, |e| e.ts_unix_ns);
            self.push(received_ns, ts, LogKind::Dropped(batch.dropped as u64));
        }
        for entry in batch.entries.into_iter().skip(skip) {
            self.push(received_ns, entry.ts_unix_ns, LogKind::Line(entry));
        }
        self.next_seq = self.next_seq.max(end);
    }

    fn push(&mut self, received_ns: u64, ts_unix_ns: u64, kind: LogKind) {
        if self.rows.len() == MAX_LOG_ROWS {
            self.rows.pop_front();
        }
        self.rows.push_back(LogRow {
            id: self.next_id,
            received_ns,
            ts_unix_ns,
            kind,
        });
        self.next_id += 1;
    }
}

/// A batch with an error (or worse) in a recording, for the timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogMark {
    pub host_id: u64,
    /// The recorded receive time, the timeline's clock.
    pub received_ns: u64,
}

/// Whether `msg` is a log batch with an error (err or worse) in it: what
/// the timeline marks, and what the recorder marks blocks for.
pub fn has_errors(msg: &Msg) -> bool {
    matches!(msg, Msg::Logs(batch) if batch.entries.iter().any(|e| e.priority <= 3))
}

/// The marks in `records`.
fn marks_in(records: impl IntoIterator<Item = sysmon_store::Record>, out: &mut Vec<LogMark>) {
    for record in records {
        // Only log datagrams are v5 or later: skip the rest undecoded.
        if record.datagram.get(2).is_none_or(|&v| v < 5) {
            continue;
        }
        if let Ok((h, msg)) = sysmon_proto::decode(&record.datagram)
            && has_errors(&msg)
        {
            out.push(LogMark {
                host_id: h.host_id,
                received_ns: record.recv_ts_ns,
            });
        }
    }
}

/// Where the recording under `path` has errors, in time order.
///
/// Segments record which of their blocks hold errors as they're written
/// (`sysmon_store::marks`), so only those blocks are read. A segment from
/// before that has no marks and is read in full, which takes 0.3-0.7 s per
/// host-day; run this in the background.
pub fn error_marks(path: &Path) -> std::io::Result<Vec<LogMark>> {
    let mut marks = Vec::new();
    for info in sysmon_store::list_segments(path)? {
        let Ok(mut reader) = sysmon_store::SegmentReader::open(&info.path) else {
            continue;
        };
        match sysmon_store::marks::load(&info.path) {
            Some(blocks) => {
                for offset in blocks {
                    if let Ok(records) = reader.block_at(offset) {
                        marks_in(records, &mut marks);
                    }
                }
            }
            None => marks_in(reader.map_while(Result::ok), &mut marks),
        }
    }
    marks.sort_by_key(|m| m.received_ns);
    Ok(marks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(msg: &str) -> LogEntry {
        LogEntry {
            ts_unix_ns: 5,
            priority: 4,
            unit: None,
            ident: "t".into(),
            pid: None,
            message: msg.into(),
            truncated: false,
        }
    }

    fn batch(run: u64, first_seq: u64, msgs: &[&str]) -> LogBatch {
        LogBatch {
            run,
            first_seq,
            dropped: 0,
            entries: msgs.iter().map(|m| entry(m)).collect(),
        }
    }

    fn shown(logs: &Logs) -> Vec<String> {
        logs.rows()
            .iter()
            .map(|r| match &r.kind {
                LogKind::Line(e) => e.message.clone(),
                LogKind::Lost(n) => format!("lost {n}"),
                LogKind::Dropped(n) => format!("dropped {n}"),
            })
            .collect()
    }

    const S: u64 = 1_000_000_000;

    #[test]
    fn heartbeats_turn_logs_on_without_adding_rows() {
        let mut l = Logs::default();
        assert!(!l.enabled());
        l.apply(1, batch(1, 0, &[]), S);
        assert!(l.enabled());
        assert!(l.rows().is_empty());
    }

    #[test]
    fn reordered_batches_are_put_back_in_order() {
        let mut l = Logs::default();
        l.apply(1, batch(1, 0, &["a"]), S);
        l.apply(1, batch(1, 2, &["c"]), S + 1);
        l.apply(1, batch(1, 1, &["b"]), S + 2);
        assert_eq!(shown(&l), ["a", "b", "c"]);
        let ids: Vec<u64> = l.rows().iter().map(|r| r.id).collect();
        assert_eq!(ids, [0, 1, 2]);
    }

    #[test]
    fn a_gap_that_isnt_filled_in_time_is_lost() {
        let mut l = Logs::default();
        l.apply(1, batch(1, 0, &["a"]), S);
        l.apply(1, batch(1, 4, &["e"]), 2 * S);
        assert_eq!(shown(&l), ["a"], "waits for the missing lines");
        l.tick(2 * S + REORDER_WAIT_NS);
        assert_eq!(shown(&l), ["a", "lost 3", "e"]);
        // Too late now.
        l.apply(1, batch(1, 1, &["b", "c", "d"]), 5 * S);
        assert_eq!(shown(&l), ["a", "lost 3", "e"]);
    }

    #[test]
    fn repeated_heartbeats_dont_hold_off_a_gap() {
        let mut l = Logs::default();
        l.apply(1, batch(1, 0, &["a"]), S);
        // Line 1 is lost; heartbeats keep saying "next is 2".
        l.apply(1, batch(1, 2, &[]), 2 * S);
        l.apply(1, batch(1, 2, &[]), 2 * S + REORDER_WAIT_NS - 1);
        l.tick(2 * S + REORDER_WAIT_NS);
        assert_eq!(shown(&l), ["a", "lost 1"]);
    }

    #[test]
    fn duplicates_are_dropped_and_dropped_lines_shown() {
        let mut l = Logs::default();
        let mut b = batch(1, 0, &["a", "b"]);
        b.dropped = 7;
        l.apply(1, b.clone(), S);
        l.apply(1, b, S + 1);
        assert_eq!(shown(&l), ["dropped 7", "a", "b"]);
    }

    #[test]
    fn a_new_run_restarts_the_numbering() {
        let mut l = Logs::default();
        l.apply(1, batch(1, 10, &["a"]), S);
        // Agent restarted: numbering from 0 under a new run, nothing lost.
        l.apply(1, batch(2, 0, &["b"]), 2 * S);
        // A reboot can reuse a run ID only by chance; the boot tells them apart.
        l.apply(2, batch(2, 0, &["c"]), 3 * S);
        assert_eq!(shown(&l), ["a", "b", "c"]);
    }

    #[test]
    fn error_marks_come_from_the_recordings_log_datagrams() {
        let dir = std::env::temp_dir().join(format!("sysmon-marks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut rec = sysmon_store::Recorder::new(&dir);
        let t = 1_700_000_000 * S;
        let mut put = |host: u64, at: u64, d: Vec<u8>| rec.append(host, 9, at, &d).unwrap();
        let sample = sysmon_proto::encode_sample(1, 9, 0, &Default::default(), &[], &[]).unwrap();
        put(1, t, sample[0].clone());
        let mut warn = batch(1, 0, &["just a warning"]);
        let logs =
            |b: &LogBatch, host| sysmon_proto::encode_logs(host, 9, 0, b).unwrap()[0].clone();
        put(1, t + S, logs(&warn, 1));
        warn.entries[0].priority = 3;
        warn.first_seq = 1;
        put(1, t + 2 * S, logs(&warn, 1));
        put(2, t + 3 * S, logs(&warn, 2));
        rec.flush().unwrap();
        drop(rec);
        // Recorded without marks: every segment is read in full.
        for seg in sysmon_store::list_segments(&dir).unwrap() {
            assert_eq!(
                sysmon_store::marks::load(&seg.path).as_deref(),
                Some(&[][..])
            );
            std::fs::remove_file(sysmon_store::marks::marks_path(&seg.path)).unwrap();
        }
        let marks = error_marks(&dir).unwrap();
        assert_eq!(
            marks,
            [
                LogMark {
                    host_id: 1,
                    received_ns: t + 2 * S
                },
                LogMark {
                    host_id: 2,
                    received_ns: t + 3 * S
                }
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn marked_recordings_are_read_only_where_marked() {
        let dir = std::env::temp_dir().join(format!("sysmon-marked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut rec = sysmon_store::Recorder::new(&dir);
        let t = 1_700_000_000 * S;
        let mut err = batch(1, 0, &["broke"]);
        err.entries[0].priority = 3;
        let d = sysmon_proto::encode_logs(1, 9, 0, &err).unwrap().remove(0);
        let msg = sysmon_proto::decode(&d).unwrap().1;
        assert!(has_errors(&msg));
        let quiet = sysmon_proto::encode_logs(1, 9, 0, &batch(1, 1, &["fine"]))
            .unwrap()
            .remove(0);
        assert!(!has_errors(&sysmon_proto::decode(&quiet).unwrap().1));
        // The error is recorded marked; another error, recorded unmarked in
        // a block of its own, shows that only marked blocks are read.
        rec.append_marked(1, 9, t, &quiet, false).unwrap();
        rec.append_marked(1, 9, t + S, &d, true).unwrap();
        rec.flush().unwrap();
        rec.append_marked(1, 9, t + 2 * S, &d, false).unwrap();
        rec.flush().unwrap();
        drop(rec);
        assert_eq!(
            error_marks(&dir).unwrap(),
            [LogMark {
                host_id: 1,
                received_ns: t + S
            }]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_rows_go_past_the_limit() {
        let mut l = Logs::default();
        for i in 0..MAX_LOG_ROWS as u64 + 5 {
            l.apply(1, batch(1, i, &["x"]), S + i);
        }
        assert_eq!(l.rows().len(), MAX_LOG_ROWS);
        assert_eq!(l.rows().front().unwrap().id, 5);
    }
}
