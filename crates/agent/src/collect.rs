//! Readers for the Linux `/proc` files the agent samples.
//!
//! Everything here returns raw cumulative counters; rates are the monitor's job.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use sysmon_proto::{
    CpuCounters, DiskStat, HostInfo, MemInfo, NetIf, ProcKey, ProcMeta, ProcSample, SystemSample,
};

/// Longest command line sent in a `ProcMeta`; keeps metadata well inside a datagram.
const MAX_CMDLINE: usize = 512;

thread_local! {
    /// One buffer reused for every `/proc` read, so steady-state sampling
    /// doesn't allocate per file.
    static BUF: RefCell<String> = RefCell::new(String::with_capacity(64 * 1024));
}

/// Read a file into the shared buffer and run `f` on its contents.
fn with_file<T>(path: &str, f: impl FnOnce(&str) -> T) -> Option<T> {
    BUF.with_borrow_mut(|buf| {
        buf.clear();
        fs::File::open(path).ok()?.read_to_string(buf).ok()?;
        Some(f(buf))
    })
}

/// uid → user name from `/etc/passwd`.
pub fn read_passwd() -> HashMap<u32, String> {
    let s = fs::read_to_string("/etc/passwd").unwrap_or_default();
    s.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

pub fn host_id() -> u64 {
    let id = fs::read_to_string("/etc/machine-id")
        .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_else(|_| hostname());
    fnv1a(id.trim().as_bytes())
}

pub fn boot_id() -> u128 {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .and_then(|s| u128::from_str_radix(&s.trim().replace('-', ""), 16).ok())
        .unwrap_or(0)
}

pub fn host_info(interval_ms: u32) -> HostInfo {
    // SAFETY: sysconf has no preconditions.
    let (clk_tck, page_size) = unsafe {
        (
            libc::sysconf(libc::_SC_CLK_TCK),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    let mem_total_kib = read_meminfo().total;
    HostInfo {
        hostname: hostname(),
        kernel: read_trimmed("/proc/sys/kernel/osrelease"),
        cpu_count: std::thread::available_parallelism().map_or(1, |n| n.get() as u16),
        mem_total_kib,
        clk_tck: clk_tck.max(1) as u32,
        page_size: page_size.max(1) as u32,
        interval_ms,
    }
}

pub fn system(ts_unix_ns: u64) -> SystemSample {
    SystemSample {
        ts_unix_ns,
        cpus: read_cpus(),
        mem: read_meminfo(),
        load: read_loadavg(),
        net: read_net(),
        disks: read_disks(),
    }
}

/// Every process in `/proc`. Processes that exit mid-scan are skipped.
pub fn procs(out: &mut Vec<ProcSample>) {
    out.clear();
    let Ok(dir) = fs::read_dir("/proc") else {
        return;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if let Some(p) =
            with_file(&format!("/proc/{pid}/stat"), |s| parse_proc_stat(pid, s)).flatten()
        {
            out.push(p);
        }
    }
}

pub fn proc_meta(key: ProcKey) -> Option<ProcMeta> {
    let dir = format!("/proc/{}", key.pid);
    let uid = fs::metadata(&dir).ok()?.uid();
    let raw = fs::read(format!("{dir}/cmdline")).unwrap_or_default();
    let mut cmdline: String = String::from_utf8_lossy(&raw)
        .trim_end_matches('\0')
        .replace('\0', " ");
    if cmdline.len() > MAX_CMDLINE {
        let mut end = MAX_CMDLINE;
        while !cmdline.is_char_boundary(end) {
            end -= 1;
        }
        cmdline.truncate(end);
    }
    Some(ProcMeta { key, uid, cmdline })
}

fn parse_proc_stat(pid: u32, s: &str) -> Option<ProcSample> {
    // `comm` is in parentheses and may itself contain spaces or ')'.
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s[open + 1..close].to_string();
    // Fields after comm, numbered from 3 as in proc(5).
    let f: Vec<&str> = s[close + 2..].split_ascii_whitespace().collect();
    let field = |n: usize| f.get(n - 3).copied();
    let num = |n: usize| field(n).and_then(|v| v.parse::<u64>().ok());
    Some(ProcSample {
        pid,
        ppid: num(4)? as u32,
        starttime: num(22)?,
        state: field(3)?.bytes().next()?,
        utime: num(14)?,
        stime: num(15)?,
        rss_pages: num(24)?,
        threads: num(20)? as u32,
        comm,
    })
}

fn read_cpus() -> Vec<CpuCounters> {
    with_file("/proc/stat", |s| {
        s.lines()
            .take_while(|l| l.starts_with("cpu"))
            .map(|l| {
                let v: Vec<u64> = l
                    .split_ascii_whitespace()
                    .skip(1)
                    .map(|x| x.parse().unwrap_or(0))
                    .collect();
                let g = |i: usize| v.get(i).copied().unwrap_or(0);
                CpuCounters {
                    user: g(0),
                    nice: g(1),
                    system: g(2),
                    idle: g(3),
                    iowait: g(4),
                    irq: g(5),
                    softirq: g(6),
                    steal: g(7),
                }
            })
            .collect()
    })
    .unwrap_or_default()
}

fn read_meminfo() -> MemInfo {
    with_file("/proc/meminfo", |s| {
        let mut m = MemInfo::default();
        for line in s.lines() {
            let mut it = line.split_ascii_whitespace();
            let (Some(key), Some(val)) = (it.next(), it.next().and_then(|v| v.parse().ok())) else {
                continue;
            };
            match key {
                "MemTotal:" => m.total = val,
                "MemFree:" => m.free = val,
                "MemAvailable:" => m.available = val,
                "Buffers:" => m.buffers = val,
                "Cached:" => m.cached = val,
                "SwapTotal:" => m.swap_total = val,
                "SwapFree:" => m.swap_free = val,
                _ => {}
            }
        }
        m
    })
    .unwrap_or_default()
}

fn read_loadavg() -> [f32; 3] {
    with_file("/proc/loadavg", |s| {
        let mut it = s.split_ascii_whitespace().map(|v| v.parse().unwrap_or(0.0));
        [
            it.next().unwrap_or(0.0),
            it.next().unwrap_or(0.0),
            it.next().unwrap_or(0.0),
        ]
    })
    .unwrap_or_default()
}

fn read_net() -> Vec<NetIf> {
    with_file("/proc/net/dev", |s| {
        s.lines()
            .skip(2)
            .filter_map(|l| {
                let (name, rest) = l.split_once(':')?;
                let v: Vec<u64> = rest
                    .split_ascii_whitespace()
                    .map(|x| x.parse().unwrap_or(0))
                    .collect();
                Some(NetIf {
                    name: name.trim().to_string(),
                    rx_bytes: *v.first()?,
                    rx_packets: *v.get(1)?,
                    tx_bytes: *v.get(8)?,
                    tx_packets: *v.get(9)?,
                })
            })
            .filter(|n| n.name != "lo")
            .collect()
    })
    .unwrap_or_default()
}

fn read_disks() -> Vec<DiskStat> {
    with_file("/proc/diskstats", |s| {
        s.lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_ascii_whitespace().collect();
                let name = *f.get(2)?;
                if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") {
                    return None;
                }
                let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok());
                Some(DiskStat {
                    name: name.to_string(),
                    sectors_read: n(5)?,
                    sectors_written: n(9)?,
                    io_ms: n(12)?,
                })
            })
            .collect()
    })
    .unwrap_or_default()
}

fn hostname() -> String {
    read_trimmed("/proc/sys/kernel/hostname")
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_awkward_comm() {
        let line = "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 \
                    250 75 0 0 20 0 3 0 98765 123456789 2048 18446744073709551615";
        let p = parse_proc_stat(1234, line).unwrap();
        assert_eq!(p.comm, "my (weird) proc");
        assert_eq!((p.state, p.ppid), (b'S', 1));
        assert_eq!((p.utime, p.stime), (250, 75));
        assert_eq!((p.threads, p.starttime, p.rss_pages), (3, 98765, 2048));
    }

    #[test]
    fn reads_this_machine() {
        let s = system(0);
        assert!(s.cpus.len() >= 2, "aggregate line plus at least one core");
        assert!(s.mem.total > 0);
        let mut ps = Vec::new();
        procs(&mut ps);
        assert!(ps.iter().any(|p| p.pid == std::process::id()));
    }
}
