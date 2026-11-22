//! Journal lines for `--logs`, read by following `journalctl -o export`.
//!
//! Running journalctl, rather than linking libsystemd or reading journal
//! files, keeps the agent free of extra dependencies (a static build still
//! works) and leaves journal access rules to systemd: the agent needs to be
//! in the `systemd-journal` group to see system logs.
//!
//! A reader thread parses entries into a queue that the sampling loop
//! drains once per tick. Lines over [`MAX_LINES_PER_S`] or [`MAX_BYTES_PER_S`]
//! are dropped and counted, so a busy journal can't swamp the network. The
//! journal position of the last line handed over is saved, so a restarted
//! agent carries on after it instead of skipping or repeating lines.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sysmon_proto::{LogBatch, LogEntry, MAX_LOG_MESSAGE, MAX_LOG_NAME};

use crate::collect::cap;

/// Lines and bytes (of message text) passed on per second; the rest are
/// dropped and counted.
pub const MAX_LINES_PER_S: u32 = 200;
pub const MAX_BYTES_PER_S: usize = 256 * 1024;
/// Most lines queued between ticks; more are dropped (the loop is stuck).
const MAX_QUEUED: usize = 10_000;
/// Wait before starting journalctl again after it exits.
const RESTART_AFTER: Duration = Duration::from_secs(10);

pub struct Config {
    /// The journalctl to run (a stand-in in tests).
    pub program: PathBuf,
    /// Lowest priority passed on: 0 emerg … 4 warning … 7 debug.
    pub priority: u8,
    /// Only these units, if any.
    pub units: Vec<String>,
    /// Where the journal position is kept between runs.
    pub cursor_file: Option<PathBuf>,
}

#[derive(Default)]
struct Shared {
    queue: VecDeque<LogEntry>,
    dropped: u32,
    /// Position of the newest line read (passed on or dropped).
    cursor: Option<String>,
}

pub struct Journal {
    shared: Arc<Mutex<Shared>>,
    cursor_file: Option<PathBuf>,
    saved: Option<String>,
    /// Saving failed and was warned about; not repeated every tick.
    warned: bool,
    run: u64,
    next_seq: u64,
}

impl Journal {
    pub fn spawn(config: Config) -> std::io::Result<Self> {
        let saved = config
            .cursor_file
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let shared = Arc::new(Mutex::new(Shared {
            cursor: saved.clone(),
            ..Default::default()
        }));
        let cursor_file = config.cursor_file.clone();
        let reader = shared.clone();
        std::thread::Builder::new()
            .name("journal".into())
            .spawn(move || follow(config, reader))?;
        Ok(Self {
            shared,
            cursor_file,
            saved,
            warned: false,
            run: random_u64(),
            next_seq: 0,
        })
    }

    /// The lines read since the last call, as the next batch (empty if
    /// there were none), numbered on from the last.
    pub fn take(&mut self) -> LogBatch {
        let mut s = self.shared.lock().unwrap();
        let entries: Vec<LogEntry> = s.queue.drain(..).collect();
        let batch = LogBatch {
            run: self.run,
            first_seq: self.next_seq,
            dropped: std::mem::take(&mut s.dropped),
            entries,
        };
        self.next_seq += batch.entries.len() as u64;
        batch
    }

    /// Remember the position of the lines taken so far, once they're sent.
    pub fn save_position(&mut self) {
        let cursor = self.shared.lock().unwrap().cursor.clone();
        let Some(path) = &self.cursor_file else {
            return;
        };
        if cursor.is_none() || cursor == self.saved {
            return;
        }
        let cursor = cursor.unwrap();
        // Write and rename, so a crash never leaves half a cursor.
        let tmp = path.with_extension("tmp");
        let result =
            std::fs::write(&tmp, format!("{cursor}\n")).and_then(|()| std::fs::rename(&tmp, path));
        if let Err(e) = result
            && !std::mem::replace(&mut self.warned, true)
        {
            tracing::warn!(path = %path.display(), error = %e, "can't save the journal position; a restart may skip or repeat lines");
        }
        self.saved = Some(cursor);
    }
}

/// Run journalctl, again whenever it exits, feeding `shared`.
fn follow(config: Config, shared: Arc<Mutex<Shared>>) {
    let mut limit = RateLimit::new(Instant::now());
    loop {
        let after = shared.lock().unwrap().cursor.clone();
        let mut cmd = Command::new(&config.program);
        cmd.args(["--follow", "--output=export", "--no-pager", "--quiet"])
            .arg(format!("--priority={}", config.priority))
            .arg("--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_COMM,_PID");
        for unit in &config.units {
            cmd.arg(format!("--unit={unit}"));
        }
        match &after {
            Some(c) => cmd.arg(format!("--after-cursor={c}")),
            // First run: only what's logged from now on.
            None => cmd.arg("--lines=0"),
        };
        let started = cmd.stdout(Stdio::piped()).stdin(Stdio::null()).spawn();
        let mut child = match started {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(program = %config.program.display(), error = %e, "can't run journalctl; no logs");
                std::thread::sleep(RESTART_AFTER);
                continue;
            }
        };
        let mut read = 0usize;
        for fields in Entries::new(BufReader::new(child.stdout.take().unwrap())) {
            read += 1;
            let mut s = shared.lock().unwrap();
            if let Some(c) = fields.get("__CURSOR") {
                s.cursor = Some(String::from_utf8_lossy(c).into_owned());
            }
            let Some(entry) = to_entry(&fields) else {
                continue;
            };
            if s.queue.len() < MAX_QUEUED && limit.allow(Instant::now(), entry.message.len()) {
                s.queue.push_back(entry);
            } else {
                s.dropped = s.dropped.saturating_add(1);
            }
        }
        let status = child.wait();
        let failed = !status.as_ref().is_ok_and(|s| s.success());
        tracing::warn!(?status, "journalctl stopped; starting it again in 10 s");
        // A saved position the journal no longer has (vacuumed, or from
        // another machine's image) makes journalctl fail at once: start
        // from new lines instead.
        if failed && read == 0 && after.is_some() {
            shared.lock().unwrap().cursor = None;
        }
        std::thread::sleep(RESTART_AFTER);
    }
}

/// Lines and bytes per second, refilled continuously up to one second's worth.
struct RateLimit {
    lines: f64,
    bytes: f64,
    last: Instant,
}

impl RateLimit {
    fn new(now: Instant) -> Self {
        Self {
            lines: MAX_LINES_PER_S as f64,
            bytes: MAX_BYTES_PER_S as f64,
            last: now,
        }
    }

    fn allow(&mut self, now: Instant, bytes: usize) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.lines = (self.lines + dt * MAX_LINES_PER_S as f64).min(MAX_LINES_PER_S as f64);
        self.bytes = (self.bytes + dt * MAX_BYTES_PER_S as f64).min(MAX_BYTES_PER_S as f64);
        if self.lines < 1.0 || self.bytes < bytes as f64 {
            return false;
        }
        self.lines -= 1.0;
        self.bytes -= bytes as f64;
        true
    }
}

/// The entry to send for a journal record, or `None` without a message.
fn to_entry(fields: &HashMap<String, Vec<u8>>) -> Option<LogEntry> {
    let text = |k: &str| {
        fields
            .get(k)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    };
    let num = |k: &str| text(k).and_then(|v| v.trim().parse::<u64>().ok());
    let message = text("MESSAGE")?;
    let message = message.trim_end_matches(['\n', '\r']);
    let truncated = message.len() > MAX_LOG_MESSAGE;
    Some(LogEntry {
        ts_unix_ns: num("__REALTIME_TIMESTAMP")
            .unwrap_or(0)
            .saturating_mul(1000),
        priority: num("PRIORITY").map_or(6, |p| p.min(7) as u8),
        unit: text("_SYSTEMD_UNIT").map(|u| cap(&u, MAX_LOG_NAME)),
        ident: cap(
            &text("SYSLOG_IDENTIFIER")
                .or_else(|| text("_COMM"))
                .unwrap_or_else(|| "?".into()),
            MAX_LOG_NAME,
        ),
        pid: num("_PID").and_then(|p| u32::try_from(p).ok()),
        message: cap(message, MAX_LOG_MESSAGE),
        truncated,
    })
}

/// Records of journalctl's export format: `KEY=value` lines, or for binary
/// values (and ones with newlines) `KEY`, a little-endian u64 length, the
/// bytes and a newline; a blank line ends each record.
struct Entries<R> {
    input: R,
}

impl<R: BufRead> Entries<R> {
    fn new(input: R) -> Self {
        Self { input }
    }

    fn read_record(&mut self) -> std::io::Result<Option<HashMap<String, Vec<u8>>>> {
        let mut fields = HashMap::new();
        let mut line = Vec::new();
        loop {
            line.clear();
            if self.input.read_until(b'\n', &mut line)? == 0 {
                // End of output: a record cut off by it is incomplete.
                return Ok(None);
            }
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.is_empty() {
                if fields.is_empty() {
                    continue;
                }
                return Ok(Some(fields));
            }
            match line.iter().position(|&b| b == b'=') {
                Some(eq) => {
                    let key = String::from_utf8_lossy(&line[..eq]).into_owned();
                    fields.insert(key, line[eq + 1..].to_vec());
                }
                None => {
                    let key = String::from_utf8_lossy(&line).into_owned();
                    let mut len = [0u8; 8];
                    self.input.read_exact(&mut len)?;
                    let len = u64::from_le_bytes(len);
                    // Journal fields are far smaller; anything bigger is garbage.
                    if len > 64 << 20 {
                        return Err(std::io::Error::other("oversized journal field"));
                    }
                    let mut value = vec![0u8; len as usize];
                    self.input.read_exact(&mut value)?;
                    let mut nl = [0u8; 1];
                    self.input.read_exact(&mut nl)?;
                    fields.insert(key, value);
                }
            }
        }
    }
}

impl<R: BufRead> Iterator for Entries<R> {
    type Item = HashMap<String, Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_record().ok().flatten()
    }
}

/// A priority given by name (`warning`, `err`, …) or number (0–7).
pub fn parse_priority(s: &str) -> Result<u8, String> {
    const NAMES: [&str; 8] = [
        "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
    ];
    if let Ok(n) = s.parse::<u8>()
        && n <= 7
    {
        return Ok(n);
    }
    let lower = s.to_ascii_lowercase();
    let alias = match lower.as_str() {
        "error" => "err",
        "warn" => "warning",
        "panic" => "emerg",
        "critical" => "crit",
        other => other,
    };
    NAMES
        .iter()
        .position(|&n| n == alias)
        .map(|p| p as u8)
        .ok_or_else(|| {
            format!(
                "unknown priority {s:?}; use one of {} or 0-7",
                NAMES.join(", ")
            )
        })
}

/// Default place for the journal position: systemd's `StateDirectory=`.
pub fn default_cursor_file() -> Option<PathBuf> {
    let dir = std::env::var_os("STATE_DIRECTORY")?;
    // Several directories are separated by ':'; the first is ours.
    let first = dir.to_string_lossy().split(':').next()?.to_string();
    Some(Path::new(&first).join("journal-cursor"))
}

fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    // SAFETY: getrandom writes at most buf.len() bytes into buf.
    let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n != buf.len() as isize {
        // No getrandom (very old kernel): time and pid still differ per run.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        return t ^ ((std::process::id() as u64) << 32);
    }
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(records: &[&[(&str, &[u8])]]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in records {
            for (k, v) in *r {
                if v.contains(&b'\n') || std::str::from_utf8(v).is_err() {
                    out.extend_from_slice(k.as_bytes());
                    out.push(b'\n');
                    out.extend_from_slice(&(v.len() as u64).to_le_bytes());
                    out.extend_from_slice(v);
                    out.push(b'\n');
                } else {
                    out.extend_from_slice(format!("{k}=").as_bytes());
                    out.extend_from_slice(v);
                    out.push(b'\n');
                }
            }
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn parses_text_and_binary_fields() {
        let data = export(&[
            &[
                ("__CURSOR", b"s=1"),
                ("__REALTIME_TIMESTAMP", b"1700000000123456"),
                ("PRIORITY", b"3"),
                ("_SYSTEMD_UNIT", b"nginx.service"),
                ("SYSLOG_IDENTIFIER", b"nginx"),
                ("_PID", b"4242"),
                ("MESSAGE", b"two\nlines\n"),
            ],
            &[
                ("__CURSOR", b"s=2"),
                ("_COMM", b"kworker"),
                ("MESSAGE", b"bad \xff byte"),
            ],
        ]);
        let records: Vec<_> = Entries::new(&data[..]).collect();
        assert_eq!(records.len(), 2);
        let a = to_entry(&records[0]).unwrap();
        assert_eq!(a.ts_unix_ns, 1_700_000_000_123_456_000);
        assert_eq!(a.priority, 3);
        assert_eq!(a.unit.as_deref(), Some("nginx.service"));
        assert_eq!((a.ident.as_str(), a.pid), ("nginx", Some(4242)));
        assert_eq!(a.message, "two\nlines");
        assert!(!a.truncated);
        let b = to_entry(&records[1]).unwrap();
        assert_eq!((b.ident.as_str(), b.priority, b.unit), ("kworker", 6, None));
        assert_eq!(b.message, "bad \u{fffd} byte");
    }

    #[test]
    fn long_fields_are_cut() {
        let long = "é".repeat(MAX_LOG_MESSAGE);
        let name = "u".repeat(200);
        let data = export(&[&[
            ("MESSAGE", long.as_bytes()),
            ("_SYSTEMD_UNIT", name.as_bytes()),
        ]]);
        let e = to_entry(&Entries::new(&data[..]).next().unwrap()).unwrap();
        assert!(e.truncated);
        assert!(e.message.len() <= MAX_LOG_MESSAGE && e.message.len() > MAX_LOG_MESSAGE - 2);
        assert_eq!(e.unit.as_ref().unwrap().len(), MAX_LOG_NAME);
        // Such an entry fits a datagram.
        let batch = LogBatch {
            run: 1,
            first_seq: 0,
            dropped: 0,
            entries: vec![e],
        };
        assert_eq!(sysmon_proto::encode_logs(1, 2, 3, &batch).unwrap().len(), 1);
    }

    #[test]
    fn rate_limit_drops_the_excess_and_refills() {
        let t0 = Instant::now();
        let mut l = RateLimit::new(t0);
        let passed = (0..MAX_LINES_PER_S + 50)
            .filter(|_| l.allow(t0, 10))
            .count();
        assert_eq!(passed, MAX_LINES_PER_S as usize);
        assert!(l.allow(t0 + Duration::from_millis(100), 10));
        // Bytes too: one huge burst empties that budget.
        let mut l = RateLimit::new(t0);
        assert!(l.allow(t0, MAX_BYTES_PER_S));
        assert!(!l.allow(t0, 1));
    }

    #[test]
    fn priorities_by_name_or_number() {
        assert_eq!(parse_priority("warning"), Ok(4));
        assert_eq!(parse_priority("WARN"), Ok(4));
        assert_eq!(parse_priority("err"), Ok(3));
        assert_eq!(parse_priority("7"), Ok(7));
        assert!(parse_priority("8").is_err());
        assert!(parse_priority("loud").is_err());
    }

    /// A stand-in journalctl: records its arguments, prints two records
    /// (the second with the cursor `s=2`), then stays running like `-f`.
    fn fake_journalctl(dir: &Path) -> PathBuf {
        let data = export(&[
            &[
                ("__CURSOR", b"s=1"),
                ("PRIORITY", b"4"),
                ("MESSAGE", b"first"),
            ],
            &[
                ("__CURSOR", b"s=2"),
                ("PRIORITY", b"3"),
                ("MESSAGE", b"second"),
            ],
        ]);
        std::fs::write(dir.join("records"), data).unwrap();
        let script = dir.join("journalctl");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {args}\necho --- >> {args}\ncat {records}\nexec sleep 5\n",
                args = dir.join("args").display(),
                records = dir.join("records").display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    fn take_until(j: &mut Journal, n: usize) -> Vec<LogBatch> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut batches = Vec::new();
        while batches
            .iter()
            .map(|b: &LogBatch| b.entries.len())
            .sum::<usize>()
            < n
        {
            assert!(Instant::now() < deadline, "no lines from journalctl");
            batches.push(j.take());
            std::thread::sleep(Duration::from_millis(10));
        }
        batches
    }

    #[test]
    fn follows_journalctl_and_resumes_where_it_stopped() {
        let dir = std::env::temp_dir().join(format!("sysmon-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = || Config {
            program: fake_journalctl(&dir),
            priority: 4,
            units: vec!["a.service".into()],
            cursor_file: Some(dir.join("cursor")),
        };

        let mut j = Journal::spawn(config()).unwrap();
        let batches = take_until(&mut j, 2);
        let lines: Vec<(u64, &str)> = batches
            .iter()
            .flat_map(|b| {
                b.entries
                    .iter()
                    .enumerate()
                    .map(move |(i, e)| (b.first_seq + i as u64, e.message.as_str()))
            })
            .collect();
        assert_eq!(lines, [(0, "first"), (1, "second")]);
        assert!(batches.iter().all(|b| b.run == batches[0].run));
        j.save_position();
        assert_eq!(
            std::fs::read_to_string(dir.join("cursor")).unwrap(),
            "s=2\n"
        );
        let args = std::fs::read_to_string(dir.join("args")).unwrap();
        assert!(args.contains("--priority=4\n--output-fields="), "{args}");
        assert!(args.contains("--unit=a.service\n--lines=0\n"), "{args}");

        // A new run (the agent restarted) carries on after the saved line,
        // numbering from 0 again under a new run ID.
        let mut k = Journal::spawn(config()).unwrap();
        let again = take_until(&mut k, 2);
        assert_ne!(again[0].run, batches[0].run);
        assert_eq!(
            again
                .iter()
                .find(|b| !b.entries.is_empty())
                .unwrap()
                .first_seq,
            0
        );
        let args = std::fs::read_to_string(dir.join("args")).unwrap();
        assert!(
            args.rsplit("---")
                .nth(1)
                .unwrap()
                .contains("--after-cursor=s=2\n"),
            "{args}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
