//! Readers for the Linux `/proc` files the agent samples.
//!
//! Everything here returns raw cumulative counters; rates are the monitor's job.

use std::cell::RefCell;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use sysmon_proto::{
    CpuCounters, DiskStat, HostInfo, MemInfo, NetIf, ProcKey, ProcMeta, ProcSample, SystemSample,
    ThreadSample,
};

/// `PF_KTHREAD` in the `flags` field of `/proc/[pid]/stat`: a kernel thread.
const PF_KTHREAD: u64 = 0x0020_0000;

/// Longest command line sent in a `ProcMeta`; keeps metadata well inside a datagram.
const MAX_CMDLINE: usize = 512;

thread_local! {
    /// One buffer reused for every `/proc` read, so steady-state sampling
    /// doesn't allocate per file.
    static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(64 * 1024));
}

/// Read a file into the shared buffer and run `f` on its contents.
///
/// The contents are decoded leniently: names in `/proc` (a process's or
/// thread's `comm`, network interfaces, disks) are arbitrary bytes, and an
/// unprivileged process can give itself a name that isn't UTF-8. Reading
/// strictly would skip the whole file, hiding that process (or every
/// interface) from the monitor. Invalid bytes become U+FFFD instead.
fn with_file<T>(path: &str, f: impl FnOnce(&str) -> T) -> Option<T> {
    BUF.with_borrow_mut(|buf| {
        buf.clear();
        fs::File::open(path).ok()?.read_to_end(buf).ok()?;
        Some(f(&String::from_utf8_lossy(buf)))
    })
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

pub fn host_info(interval_ms: u32, sends_threads: bool) -> HostInfo {
    // SAFETY: sysconf has no preconditions.
    let (clk_tck, page_size) = unsafe {
        (
            libc::sysconf(libc::_SC_CLK_TCK),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    let mem_total_kib = read_meminfo().total;
    HostInfo {
        hostname: cap(&hostname(), 255),
        kernel: cap(&read_trimmed("/proc/sys/kernel/osrelease"), 255),
        // The CPUs in /proc/stat, as the per-core bars show them. Not
        // available_parallelism(), which counts only the CPUs this process
        // may run on (taskset, cgroup cpusets, a unit's CPUAffinity=).
        cpu_count: read_cpus().len().saturating_sub(1).max(1) as u16,
        mem_total_kib,
        clk_tck: clk_tck.max(1) as u32,
        page_size: page_size.max(1) as u32,
        interval_ms,
        sends_threads,
    }
}

pub fn system(ts_unix_ns: u64) -> SystemSample {
    SystemSample {
        ts_unix_ns,
        boottime_ns: boottime_ns(),
        cpus: read_cpus(),
        mem: read_meminfo(),
        load: read_loadavg(),
        net: read_net(),
        disks: read_disks(),
    }
}

/// Every process in `/proc`, and with `threads`, every thread of every user
/// process other than its main thread. Processes and threads that exit
/// mid-scan are skipped.
pub fn procs(out: &mut Vec<ProcSample>, mut threads: Option<&mut Vec<ThreadSample>>) {
    out.clear();
    if let Some(t) = threads.as_deref_mut() {
        t.clear();
    }
    let Ok(dir) = fs::read_dir("/proc") else {
        return;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if let Some(mut p) =
            with_file(&format!("/proc/{pid}/stat"), |s| parse_proc_stat(pid, s)).flatten()
        {
            // SHR is only in statm. If the process exits in between, it's
            // simply unknown for this sample.
            p.shared_pages = with_file(&format!("/proc/{pid}/statm"), parse_statm_shared).flatten();
            // Kernel threads are single-threaded; a process with one thread
            // has only its main thread, which is the process row itself.
            if let Some(t) = threads.as_deref_mut()
                && p.kernel_thread != Some(true)
                && p.threads > 1
            {
                read_threads(pid, t);
            }
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

fn read_threads(tgid: u32, out: &mut Vec<ThreadSample>) {
    let Ok(dir) = fs::read_dir(format!("/proc/{tgid}/task")) else {
        return;
    };
    for entry in dir.flatten() {
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if tid == tgid {
            continue;
        }
        if let Some(t) = with_file(&format!("/proc/{tgid}/task/{tid}/stat"), |s| {
            parse_thread_stat(tgid, tid, s)
        })
        .flatten()
        {
            out.push(t);
        }
    }
}

/// A thread's `stat` has the same layout as a process's.
fn parse_thread_stat(tgid: u32, tid: u32, s: &str) -> Option<ThreadSample> {
    let p = parse_proc_stat(tid, s)?;
    Some(ThreadSample {
        tgid,
        tid,
        starttime: p.starttime,
        state: p.state,
        utime: p.utime,
        stime: p.stime,
        comm: p.comm,
    })
}

/// The third field of `/proc/[pid]/statm`: resident shared pages (file-backed
/// and shared memory), which htop shows as SHR.
fn parse_statm_shared(s: &str) -> Option<u64> {
    s.split_ascii_whitespace().nth(2)?.parse().ok()
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
        vsize_bytes: num(23),
        // From statm; filled in by the caller.
        shared_pages: None,
        kernel_thread: Some(num(9)? & PF_KTHREAD != 0),
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
    with_file("/proc/diskstats", |s| parse_diskstats(s, is_physical_disk)).unwrap_or_default()
}

/// Whether a block device is a disk in its own right. `/proc/diskstats` also
/// lists partitions, device-mapper devices (LUKS, LVM), software RAID, loop
/// and RAM disks, whose I/O is already counted on the disks underneath;
/// summing them all counted the same I/O two or three times. Only disks
/// backed by a device (`/sys/block/<name>/device`) are kept.
fn is_physical_disk(name: &str) -> bool {
    std::path::Path::new("/sys/block")
        .join(name)
        .join("device")
        .exists()
}

fn parse_diskstats(s: &str, keep: impl Fn(&str) -> bool) -> Vec<DiskStat> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_ascii_whitespace().collect();
            let name = *f.get(2)?;
            if !keep(name) {
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
}

/// `CLOCK_BOOTTIME`: time since boot, including suspend, never stepped.
pub fn boottime_ns() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for clock_gettime to fill in.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    (rc == 0).then(|| ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// `s` cut to at most `max` bytes, at a character boundary.
pub fn cap(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn hostname() -> String {
    read_trimmed("/proc/sys/kernel/hostname")
}

fn read_trimmed(path: &str) -> String {
    with_file(path, |s| s.trim().to_string()).unwrap_or_default()
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
    fn processes_with_non_utf8_names_are_listed() {
        // Name a child process with a byte that isn't valid UTF-8, as any
        // unprivileged process can (prctl PR_SET_NAME).
        let mut child = std::process::Command::new("python3")
            .args([
                "-c",
                "import ctypes, time; ctypes.CDLL(None).prctl(15, b'\\xffhidden', 0, 0, 0); time.sleep(5)",
            ])
            .spawn()
            .expect("python3 for the test");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let found = loop {
            let mut ps = Vec::new();
            procs(&mut ps, None);
            if let Some(p) = ps
                .iter()
                .find(|p| p.pid == child.id() && p.comm.ends_with("hidden"))
            {
                break Some(p.comm.clone());
            }
            if std::time::Instant::now() > deadline {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        child.kill().ok();
        child.wait().ok();
        assert_eq!(found.as_deref(), Some("\u{FFFD}hidden"));
    }

    #[test]
    fn cpu_count_is_the_hosts_not_the_agents_affinity() {
        let cores = read_cpus().len() - 1; // minus the aggregate line
        // Pin this thread to CPU 0, as taskset or a cpuset would.
        // SAFETY: plain libc calls on a zeroed cpu_set_t for this thread.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let mut old: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::cpu_set_t>();
        unsafe {
            libc::sched_getaffinity(0, size, &mut old);
            libc::CPU_SET(0, &mut set);
            assert_eq!(libc::sched_setaffinity(0, size, &set), 0);
        }
        assert_eq!(std::thread::available_parallelism().unwrap().get(), 1);
        let info = host_info(1000, false);
        unsafe {
            libc::sched_setaffinity(0, size, &old);
        }
        assert_eq!(info.cpu_count as usize, cores);
    }

    #[test]
    fn samples_carry_a_boot_time_clock() {
        let a = system(0).boottime_ns.expect("CLOCK_BOOTTIME");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let b = system(0).boottime_ns.unwrap();
        assert!(b - a >= 20_000_000, "{a} -> {b}");
        // Since boot: well below the wall clock's time since 1970.
        assert!(b < crate::unix_now_ns());
    }

    #[test]
    fn only_physical_disks_are_reported() {
        let diskstats = "\
 259       0 nvme0n1 100 0 3000 0 50 0 800 0 0 400 0 0 0 0 0 0 0
 259       1 nvme0n1p1 10 0 300 0 5 0 80 0 0 40 0 0 0 0 0 0 0
 259       2 nvme0n1p2 90 0 2700 0 45 0 720 0 0 360 0 0 0 0 0 0 0
 254       0 dm-0 90 0 2700 0 45 0 720 0 0 360 0 0 0 0 0 0 0
   7       0 loop0 1 0 2 0 0 0 0 0 0 1 0 0 0 0 0 0 0
";
        let disks = parse_diskstats(diskstats, |n| n == "nvme0n1");
        assert_eq!(disks.len(), 1);
        assert_eq!(
            (disks[0].sectors_read, disks[0].sectors_written),
            (3000, 800)
        );

        // On this machine: every disk reported is a real one, and none of
        // the partitions or mapped devices are.
        for d in read_disks() {
            assert!(is_physical_disk(&d.name), "{}", d.name);
            assert!(!d.name.starts_with("dm-") && !d.name.starts_with("loop"));
        }
    }

    #[test]
    fn parses_stat_with_awkward_comm() {
        let line = "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 \
                    250 75 0 0 20 0 3 0 98765 123456789 2048 18446744073709551615";
        let p = parse_proc_stat(1234, line).unwrap();
        assert_eq!(p.comm, "my (weird) proc");
        assert_eq!((p.state, p.ppid), (b'S', 1));
        assert_eq!((p.utime, p.stime), (250, 75));
        assert_eq!((p.threads, p.starttime, p.rss_pages), (3, 98765, 2048));
        assert_eq!(p.vsize_bytes, Some(123456789));
        assert_eq!(
            p.kernel_thread,
            Some(false),
            "flags 4194560 has no PF_KTHREAD"
        );
        // kthreadd: flags 0x208040 includes PF_KTHREAD (0x200000).
        let kthreadd = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0 \
                        18446744073709551615";
        assert_eq!(
            parse_proc_stat(2, kthreadd).unwrap().kernel_thread,
            Some(true)
        );
        let t = parse_thread_stat(1234, 1240, line).unwrap();
        assert_eq!(
            (t.tgid, t.tid, t.utime, &t.comm[..]),
            (1234, 1240, 250, "my (weird) proc")
        );
        assert_eq!(parse_statm_shared("5000 2048 512 100 0 900 0\n"), Some(512));
        assert_eq!(parse_statm_shared("5000 2048"), None);
    }

    #[test]
    fn reads_this_machine() {
        let s = system(0);
        assert!(s.cpus.len() >= 2, "aggregate line plus at least one core");
        assert!(s.mem.total > 0);
        // Give this process a second thread to find.
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::Builder::new()
            .name("probe-thread".into())
            .spawn(move || {
                let _ = stop_rx.recv();
            })
            .unwrap();
        let mut ps = Vec::new();
        let mut ts = Vec::new();
        procs(&mut ps, Some(&mut ts));
        let me = std::process::id();
        assert!(
            ts.iter().any(|t| t.tgid == me && t.comm == "probe-thread"),
            "our own extra thread is reported"
        );
        assert!(
            ts.iter().all(|t| t.tid != t.tgid),
            "main threads are left out"
        );
        if let Some(k) = ps.iter().find(|p| p.pid == 2) {
            assert_eq!(k.kernel_thread, Some(true), "kthreadd is a kernel thread");
        }
        stop_tx.send(()).unwrap();
        worker.join().unwrap();
        let me = ps.iter().find(|p| p.pid == std::process::id()).unwrap();
        assert!(me.vsize_bytes.unwrap() > me.rss_pages * 4096 / 2);
        assert!(me.shared_pages.is_some());
    }
}
