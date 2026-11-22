# sysmon architecture

sysmon is a `top`-like system monitor split in two:

- **`sysmon-agent`** runs on the machine being monitored. It samples the
  kernel's counters and pushes them over UDP.
- **`sysmon-ui`** runs on the monitoring machine. It receives the datagrams,
  shows them live in a [gpui-kit](https://gpui-kit.com) desktop application,
  and records them to disk so they can be replayed offline.

Everything is Rust, organised as one Cargo workspace.

```
 REMOTE HOST                                MONITORING HOST
┌──────────────────────┐   UDP datagrams   ┌──────────────────────────────────────────┐
│ sysmon-agent         │ ───────────────►  │ sysmon-ui (gpui-kit)                     │
│  collector (/proc)   │   (postcard,      │  ┌────────────┐   ┌──────────────────┐   │
│  encoder + chunker   │    framed)        │  │ net thread │──►│ assembler        │   │
│  UdpSocket sender    │                   │  └────────────┘   └───┬──────────┬───┘   │
└──────────────────────┘                   │                      ▼          ▼       │
                                           │              store writer   HostModel    │
                                           │              (disk thread)  (history)    │
                                           │                      │          │        │
                                           │              segment files   gpui views  │
                                           │                      └─► ReplaySource ──┘│
                                           └──────────────────────────────────────────┘
```

## Design principles

1. **Raw cumulative counters on the wire, rates on the monitor.** The agent
   sends CPU jiffies, process `utime`/`stime`, byte counters and so on as the
   kernel reports them. The monitor computes rates from any two samples it
   has. A lost packet only makes one interval longer; it never corrupts data.
   It also keeps the agent close to free.
2. **Every datagram decodes on its own.** Large samples are split into chunks
   that each hold whole records, so losing one chunk loses only that chunk's
   processes for one tick.
3. **The disk format is the wire format.** The recorder stores received
   datagrams, opened (decrypted) and decompressed, plus a receive
   timestamp. Replay feeds them through the same decoder and assembler as
   live data. Decompressing first matters: blocks of plain datagrams
   compress together to about half the size of datagrams the agent
   compressed one by one (measured with a real agent: 11 vs 20 MB per
   host-hour).
4. **Live and replay end in the same models.** Both produce the same ingest
   `Event`s, applied to `HostModel`s the same way. Live events arrive on the
   ingest channel; replay ones on the replay engine's `Feed` channel, which
   adds a `Reset` on seek (section 5).
5. **Only `sysmon-ui` depends on gpui.** Protocol, ingest, storage and
   modelling are plain libraries that can be tested headless. A headless
   recorder would be just `ingest` + `store`; none is built yet (the
   recorder runs inside `sysmon-ui`).

## Workspace layout

| Crate | Kind | Responsibility |
|---|---|---|
| `crates/proto` (`sysmon-proto`) | lib | Wire types, framing, chunking, encode/decode, `Frame` |
| `crates/agent` (`sysmon-agent`) | bin | Collect from `/proc`, encode, send over UDP |
| `crates/ingest` (`sysmon-ingest`) | lib | UDP receive thread, chunk reassembly, fan-out |
| `crates/store` (`sysmon-store`) | lib | Segment files: append-only writer, reader, index, retention |
| `crates/model` (`sysmon-model`) | lib | Rates, history, process trees, graph series, `ReplaySource` and the replay engine |
| `crates/ui` (`sysmon-ui`) | bin | gpui-kit application: host list, header graphs, process table, timeline |
| `crates/notices` (`sysmon-notices`) | lib | Embedded license notices: data types, `embed!`, the full notices document |
| `crates/notices-build` (`sysmon-notices-build`) | lib | Build-script side: collects a binary's notices with `cargo metadata` |

Dependencies between the workspace crates (normal dependencies; each
binary's `build.rs` also uses `notices-build`, which depends on `notices`):

| Crate | Depends on |
|---|---|
| `proto`, `store`, `notices` | (none) |
| `ingest` | `proto` |
| `model` | `proto`, `ingest`, `store` (its `ReplaySource` reads recordings) |
| `agent` | `proto`, `notices` |
| `ui` | `proto`, `ingest`, `store`, `model`, `notices` |
| `notices-build` | `notices` |

## 1. `sysmon-proto`: wire protocol

### Datagram layout

```
 0      2        3        4
 ┌──────┬────────┬────────┬───────────────────────────────────┐
 │ "SM" │ version│ flags  │ postcard( Header, Msg )           │
 └──────┴────────┴────────┴───────────────────────────────────┘
```

- `magic` and `version` sit at fixed offsets, so a reader can reject foreign
  traffic and old recordings before it tries to deserialize anything.
- `flags` marks a zstd-compressed payload (`COMPRESSED`) and an encrypted,
  authenticated one (`ENCRYPTED`); see [Security](#security). Unknown bits
  are rejected.
- Each datagram is at most `MAX_DATAGRAM` (1200 bytes) so it fits in one
  packet on any reasonable path MTU.

### Header

```rust
pub struct Header {
    pub host_id: u64,    // stable per machine (hash of /etc/machine-id)
    pub boot_id: u128,   // /proc/sys/kernel/random/boot_id: counters reset when this changes
    pub seq: u32,        // sample sequence number, shared by every chunk of one sample
    pub chunk: u16,      // index of this datagram within the sample
    pub chunks: u16,     // total datagrams in the sample
}
```

### Messages

```rust
pub enum Msg {
    HostInfo(HostInfo),         // hostname, kernel, cpu_count, mem_total, clk_tck, page_size
    System(SystemSample),       // chunk 0 of a sample: timestamp, per-CPU, memory, load, net, disk
    Procs(Vec<ProcSample>),     // chunks 1..n of a sample: whole process records
    ProcMeta(Vec<ProcMeta>),    // cmdline/uid for (pid, starttime)
    Users(Vec<UserName>),       // uid → name for the uids of running processes
    Threads(Vec<ThreadSample>), // chunks after a sample's Procs, with `--threads`
    Logs(LogBatch),             // journal lines, with `--logs` (v5)
}

pub struct LogBatch {
    pub run: u64,          // random per agent start; numbering restarts with it
    pub first_seq: u64,    // number of entries[0]; +1 per line, so a jump means loss
    pub dropped: u32,      // lines the agent dropped (rate limit) before these
    pub entries: Vec<LogEntry>, // time, priority, unit, identifier, PID, message
}
```

- A **sample** is one tick. It is sent as one `System` datagram (chunk 0)
  followed by as many `Procs` datagrams as needed, all with the same `seq`.
- `HostInfo` and `Users` are sent with every sample (about 150 bytes,
  `--host-info-every`), so a monitor that starts or restarts while agents
  keep running knows each host's name, settings and users from its first
  sample. `ProcMeta` for processes that already exist only comes with the
  next full refresh (every 30 samples, about 14 KB), so until then a newly
  started monitor shows those processes as `[comm]` without user or command
  line.
- `ProcMeta` carries the strings that rarely change (full command line, uid).
  The agent sends it for processes it hasn't seen before, and sends a full
  refresh every ~30 s. `ProcSample` carries only `comm` (≤ 16 bytes).
- `Users` lists only uids that running processes use. It's sent with
  `HostInfo`, and also as soon as a newly resolved name is available.
- `Logs` batches are standalone (`chunk 0 of 1`), sent each tick that has
  lines, and empty at least every 10 s as a heartbeat, so the monitor knows
  a host sends logs even when it's quiet. `encode_logs` splits a batch over
  datagrams, adjusting `first_seq`. Messages are cut to 800 bytes and unit
  and identifier to 64 (`truncated` says so), so any entry fits.
- New `Msg` variants are only ever appended, so old recordings keep decoding.
- **Versions:** changing a type's fields changes the encoding (postcard isn't
  self-describing), so it bumps `VERSION`. The old types are frozen in a
  module (`proto::v1`), and `decode` reads every version from `MIN_VERSION`
  up, converting to the current types. Version 2 added
  `ProcSample::vsize_bytes` (VIRT) and `shared_pages` (SHR), both `Option`:
  `None` from v1 data, and SHR also `None` if a process exits between the
  agent's two reads. Version 3 added `ProcSample::kernel_thread` (the kernel's
  `PF_KTHREAD` flag), `HostInfo::sends_threads`, and `Msg::Threads`
  (`ThreadSample { tgid, tid, starttime, state, utime, stime, comm }`, keyed
  by `(tid, starttime)`, which never collides with a process key). Version 4
  added `SystemSample::boottime_ns`, the agent's `CLOCK_BOOTTIME` (time since
  boot, counting suspend, never stepped like the wall clock), which monitors
  use to order samples and compute rates (section 5). v1–v3 are frozen in
  `proto::v1`, `proto::v2` and `proto::v3`. Version 5 added `Msg::Logs`, and
  only log datagrams are sent as v5 (`version_of`): v4 and v5 payloads
  decode the same way, so everything else stays v4 and a v4 monitor keeps
  reading an agent that sends logs, rejecting just the log datagrams. That
  also lets a recording be scanned for logs by the version byte alone.
  Otherwise monitors must be upgraded before agents, since an older monitor
  rejects newer versions.
- **Process identity** is `(pid, starttime)`, so a reused PID never merges two
  processes' histories.

### `Frame`

`Frame` is the reassembled unit that everything after ingest works with:

```rust
pub struct Frame {
    pub host_id: u64,
    pub boot_id: u128,
    pub seq: u32,
    pub system: Option<SystemSample>,   // None if chunk 0 was lost
    pub procs: Vec<ProcSample>,
    pub threads: Vec<ThreadSample>,     // empty unless the agent sends threads
    pub complete: bool,                 // false if any chunk was missing
    pub received_ns: u64,               // monitor clock: newest chunk received
}
```

## 2. `sysmon-agent`: collector

- No async runtime. The main thread runs the sampling loop,
  `loop { collect(); encode(); send(); sleep_until(next_tick) }`, with
  blocking `std::net::UdpSocket`s: one per address family the targets use,
  since a socket bound to `0.0.0.0` can't reach IPv6 addresses
  (`send::Sender`; each is created when first needed). Two more threads do
  lookups: user names (below), and monitor addresses (`targets::Targets`),
  which are resolved again every 60 s so a monitor that moves is followed. A
  name that doesn't resolve yet (DNS not up at boot) doesn't stop the agent;
  it's sent to once it resolves, and the last good address is kept while
  lookups fail. Malformed targets (no port) are rejected at start-up.
- Nothing that can't be encoded stops the agent: each part of a sample is
  encoded and sealed separately, and a part that fails is skipped and
  logged once. User names over 256 bytes, and hostname and kernel strings
  over 255, are cut so they always fit.
- The sample counter wraps after 2^32 samples; the monitor takes the new 0
  as an agent restart.
- `--interval-ms` is at least 10 ms, and `HostInfo` reports the interval
  actually used. `HostInfo.cpu_count` is the number of CPUs in `/proc/stat`,
  not the CPUs the agent may run on.
- Logging defaults to `info` (`RUST_LOG` overrides it), so the start-up
  line and send failures reach the terminal or the journal.
- It reads `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/[pid]/stat`,
  `/proc/[pid]/statm`, `/proc/net/dev` and `/proc/diskstats` into one reused
  buffer. Files are read as bytes and decoded leniently (invalid UTF-8
  becomes U+FFFD): names in `/proc` are arbitrary bytes, and any process can
  rename itself to bytes that aren't UTF-8, which a strict read would skip,
  hiding that process. Only physical disks are sent (`/sys/block/<name>/device`
  exists): partitions, device-mapper, RAID, loop and RAM devices would count
  the same I/O again. `statm` is read only for SHR (its third field).
- **Kept-open files** (`collect::Collector`): opening a `/proc/[pid]` file
  costs far more than reading it, so each process's `stat` and `statm`
  (and with `--threads`, each thread's `stat`) stay open between samples
  and are re-read from offset 0, which produces them afresh. A file whose
  process has exited fails to read rather than showing another process, so
  a reused pid is just opened again; files of what's gone are closed each
  sample. At start-up the agent raises its soft open-file limit to the hard
  one (systemd's default soft limit is 1024) and keeps at most that minus
  256 files open, opening the rest per read. Files are read with plain
  `read`/`pread` calls, not `read_to_end`, which first asks for the size and
  position (two wasted system calls, as `/proc` files report size 0).
  Measured with ~490 processes at 1 Hz: 7 → 3 ms per sample (0.3 % of a
  core), with about 975 files open.
- User names come from `getpwuid_r`, so they follow `/etc/nsswitch.conf`:
  local files plus systemd's dynamic and homed users, LDAP, SSSD and so on
  (`users::UserNames`). A directory lookup can be slow, or hang while a
  server is unreachable, so lookups run on their own thread and the
  sampling loop only reads the cache. Each uid is looked up again every
  60 samples. musl has no NSS modules, so a static musl build sees only
  `/etc/passwd` (or nscd).
- It tracks the set of known `(pid, starttime)` pairs to decide when to emit
  `ProcMeta`.
- CLI (`clap`): `--target host:port` (repeatable), `--interval-ms`,
  `--compress`, `--key-file`, `--generate-key <path>`, `--threads`, `--logs`
  (with `--log-priority`, `--log-unit`, `--log-cursor-file` and
  `--logs-unencrypted`), and `--licenses` (third-party license notices; see
  section 6).
- `--logs` (`journal.rs`, off by default) follows `journalctl --follow
  --output=export`, filtered there by priority (default warning and above)
  and unit, on its own thread. Running journalctl rather than linking
  libsystemd keeps the agent's dependencies (and a static build), and
  leaves access to systemd: system logs need the `systemd-journal` group.
  - The export format is parsed directly: `KEY=value` lines, or for binary
    values (and ones with newlines) the key, a little-endian length and the
    bytes. Fields used: time, priority, `_SYSTEMD_UNIT`,
    `SYSLOG_IDENTIFIER` (else `_COMM`), `_PID`, `MESSAGE`, `__CURSOR`.
  - Each tick the sampling loop takes what was read as one batch, numbered
    on from the last under the run's random ID.
  - Over 200 lines/s or 256 KiB/s of text, or 10,000 lines queued, lines are
    dropped and counted in the next batch.
  - After each send the journal cursor of the last line read is saved
    (write and rename) to `--log-cursor-file`, by default
    `$STATE_DIRECTORY/journal-cursor`. A restart passes it to
    `--after-cursor`, so lines logged while the agent was down are sent and
    none are repeated. Without one, it starts with new lines (`--lines=0`).
    If journalctl fails at once with a saved cursor (the journal was
    vacuumed), the cursor is dropped.
  - journalctl is started again 10 s after it exits, and stops when the
    agent does, however it ends (`PR_SET_PDEATHSIG` on the reader thread
    that starts it, which lives as long as the agent); before, one left by
    an agent stopped outside systemd ran until its next matching line.
  - `--logs` refuses to start without `--key-file` unless
    `--logs-unencrypted` is given (see [Security](#security)).
  - Tested against the real journal with `logger`: warning and err arrive,
    info is filtered, and a line logged while the agent was stopped arrives
    after the restart without repeats.
- `kernel_thread` comes from the `flags` field of `stat`, which is already
  read, so it costs nothing.
- `--threads` (off by default) also reads `/proc/[pid]/task/*/stat` for every
  user process with more than one thread, and sends all threads but the main
  one, which is the process row. Measured with ~490 processes and ~1750
  threads: 3 → 9 ms per sample (about 2,200 files kept open), and 10.1 →
  26.5 KB per sample compressed.
- Deployment: the sandboxed systemd unit in
  `crates/agent/dist/sysmon-agent.service` (which allows `AF_UNIX` besides IP,
  because user lookups reach systemd's user database, SSSD and nscd over Unix
  sockets, and has `SupplementaryGroups=systemd-journal` and
  `StateDirectory=sysmon-agent` for `--logs`), and a static musl build
  (`rustup target add x86_64-unknown-linux-musl`, then
  `cargo build --release -p sysmon-agent --target x86_64-unknown-linux-musl`).
  CI builds the musl agent and checks that it's static and runs.

## 3. `sysmon-ingest`: receiver

- A dedicated thread does a blocking `recv_from`, then **opens** each
  datagram with the configured key (dropping anything that fails to
  authenticate), and hands the opened datagram to:
  - the **store** channel, as bytes plus the receive timestamp, and
  - the **assembler**, which decodes the datagram.
- The `Assembler` keys partial samples by `(host_id, seq)`. It emits a `Frame`
  as soon as all `chunks` have arrived, or with `complete = false` once a
  newer `seq` arrives or the sample times out (a fixed 1.5 s, not tied to
  the host's interval). A `boot_id` change resets that host's state.
- **Agent restarts:** a restarted agent has the same host and boot but numbers
  its samples from 0 again. The assembler treats a sample 0 seen after later
  ones, or a sample more than 64 behind the newest, as a restart and resets
  that host's sequence state. Anything less far behind is a late or
  duplicated packet and is dropped. The restarted agent resends `HostInfo`,
  `Users` and every `ProcMeta` in its first sample, so changed settings (e.g.
  `--threads`) take effect at once. As a guard against a late duplicate
  being taken for a restart, `HostModel` ignores samples that aren't newer
  than the last one from that boot (by the boot-time clock; section 5). The
  first rates after a restart average over the downtime, as after lost
  samples.
- Standalone messages (`HostInfo`, `ProcMeta`, `Users`, `Logs`) pass straight
  through; `Event::Logs` also carries the boot and the monitor-side receive
  time, which playback seeks by.
- Channels are bounded (`flume`). When a consumer falls behind, frames are
  dropped and counted. The socket thread never blocks.

## 4. `sysmon-store`: offline storage

### Files

```
<data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.seg   # one segment per host per hour (UTC)
<data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.idx   # sparse time index
<data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.marks # blocks with error log lines
```

`data_dir` defaults to the platform data directory, e.g.
`~/.local/share/sysmon` on Linux.

### Segment format

```
file   := file_header block*
file_header := "SMSEG" version:u8
block  := len:u32le  crc32:u32le  zstd( record* )
record := recv_ts_ns:u64le  len:u16le  datagram[len]
```

- The writer buffers records and flushes a block every ~10 s or 64 KiB,
  whichever comes first. It calls fsync per block, not per record.
- **Crash recovery:** files are append-only. When the writer opens an existing
  segment, it validates the blocks and truncates a torn tail.
- **Index:** `<name>.idx` holds one 28-byte `(first_ts, last_ts, offset, len)`
  entry per block, appended by the writer after each block. Seeking is a
  binary search plus decompressing one block. The index is derived data:
  readers trust only the prefix of entries that chains through the segment
  and scan any blocks after it, and the writer rewrites a stale index when it
  reopens a segment. Only the writer writes `.idx` files.
- **Marks:** `<name>.marks` lists the offsets (u64le) of blocks holding a
  record the caller marked (`append_marked`); sysmon's recorder marks log
  batches with errors (`logs::has_errors`). It's created with its segment
  and appended to after each marked block, unsynced: marks are hints that
  readers check, and one lost in a crash only goes unmarked. A segment
  without one (recorded before marks existed) must be read in full; the
  writer doesn't start one for such a segment, as it would be incomplete.
  Retention removes it with its segment.
- **Catalog:** `list_segments` finds every segment under a directory and
  parses host, boot and hour from its path.
- **Retention:** `prune` deletes whole hour files beyond a maximum age or total
  size (`--keep-hours`, `--max-gib`), oldest first, and never the current
  hour. The recorder runs it every 10 minutes.
- The writer runs on its own thread so a disk stall never reaches the socket
  or the UI.
- **Stopping the monitor:** blocks are buffered for up to 10 s or 64 KB, so
  stopping would lose that much. SIGINT, SIGTERM and SIGHUP, and quitting
  the app (gpui's `on_app_quit`), call `RecorderHandle::stop()`, which writes
  out everything received before the process exits (waiting at most 2 s).
  After an unclean stop (SIGKILL, power loss) the next monitor truncates the
  torn tail, rebuilds the index if needed, and appends to the same hour's
  segment; the downtime shows as a gap in replay.

## 5. `sysmon-model`: state and data sources

Events (`sysmon_ingest::Event`: `Frame`, `HostInfo`, `ProcMeta`, `Users`)
come from one of two places:

- **Live:** the ingest thread's `Receiver<Event>`, drained by the UI.
- **Replay:** `ReplaySource` opens every segment under a path, groups them
  into one stream per (host, boot), and merges the streams by **receive
  time**, which is the monitor's single clock. It feeds records through an
  `Assembler` exactly as live traffic is fed, and seeks each stream through
  the index (`seek_to`). Its `next_event()` reads as fast as possible, for
  headless tools and tests; the UI plays recordings through the engine
  below.

### Replay engine

`replay::spawn(source, speed)` runs a thread that emits events when a
`PlaybackClock` (which maps wall time onto recording time, with speed, pause
and seek) reaches them. It returns a `ReplayHandle`:

- `feed: Receiver<Feed>`, where `Feed` is `Event(Event)` or `Reset`. `Reset`
  is sent on every seek, so the UI discards models built before the jump;
- `send(Control)`: `SetPaused`, `TogglePause`, `SetSpeed`, `Seek(ts)`;
- `status()`: start, end, position, speed, paused, finished.

`ReplayHandle::manual` makes a handle with no engine behind it: the caller
feeds events and reads the controls sent. UI tests use it, since an engine
thread waking the UI is outside gpui's deterministic test scheduler.

A seek starts reading the full history window (10 min) before the target and
delivers it at once, so the models have rates and the process graphs are
full as soon as the target is shown. Gaps in the recording longer than 5 s (an
agent or the monitor was offline) are skipped rather than waited out.

### `HostModel`

`HostModel` is fed events and keeps:

- the previous and current samples, used for CPU %, memory, and per-interface
  and per-disk rates (bytes/s and disk busy %);
- **time:** samples are ordered and rates computed by the agent's boot-time
  clock (`boottime_ns`), so a step of the agent's wall clock (NTP, a date
  change, a VM resume) neither freezes the host nor distorts rates. A
  sample that isn't newer than the last on that clock is a duplicate and is
  ignored. Agents older than v4 fall back to the wall clock; a sample is
  only compared with one from the same boot on the same kind of clock, so
  an agent upgraded mid-boot just starts rates afresh. When the wall clock
  jumps by more than 2 s relative to boot time, `history` and `proc_history`
  are cleared, since the graphs' time axis is wall time;
- per-process `%CPU = Δ(utime + stime) / clk_tck / Δt`, where each process
  remembers when its ticks were read;
- after an incomplete frame, the rows that didn't arrive, carried over and
  marked `stale` (a complete frame drops processes that really exited);
- a ring buffer of derived system metrics (10 minutes at 1 Hz) for sparklines;
- the process table, joined with `ProcMeta` (cmdline, uid) and `Users`;
- `proc_history`: every process of the last 600 samples, frame-major
  (`series::ProcFrame`: timestamp, memory total, and each process's key,
  ppid, %CPU, VIRT, RES, SHR and threads). Rows carried over lost chunks are left out,
  so graphs show a gap instead of a repeated value. `series(target, metric,
  since)` gives one graph line, where `target` is a `Process(key)` or a
  `Subtree(key)` and `metric` is %CPU, VIRT, RES, SHR, %MEM (against that
  sample's memory total) or threads. Unknown VIRT/SHR values are gaps; a
  subtree sums the values that are known. A subtree total is taken from each sample's own
  parent links, so children count only while they exist. Memory: a point
  is 56 bytes (unknown sizes use a sentinel rather than `Option`), so
  56 × processes × 600 per host, about 17 MB for 500 processes;
- `logs` (`logs::Logs`): up to 20,000 journal rows per host in the agent's
  order, with `Lost(n)` rows for numbering gaps and `Dropped(n)` for lines
  the agent dropped. A batch ahead of a missing one waits up to 2 s for it
  (UDP reorders; a repeat keeps its first arrival time), then the gap is
  called lost; frames advance that clock too. Duplicates and too-late
  batches are dropped. A new run or boot restarts the numbering, and a
  monitor starting mid-run doesn't call what came before lost. Any batch,
  heartbeats included, marks logs as enabled. Each row keeps its receive
  time, which playback seeks to;
- liveness: when the monitor last received a sample (`last_received_ns`,
  from `Frame::received_ns`, the monitor-side receive time of the frame's
  newest chunk; the recorded receive time when replaying), so a skewed
  agent clock doesn't make a host look silent, or hide that it is; and the
  incomplete-frame rate.

Arithmetic on values from the network (CPU tick sums, `utime + stime`,
pages × page size, memory used, collapsed-subtree totals) saturates, so a
buggy or hostile agent can't overflow it (a panic in debug builds).

## 6. `sysmon-ui`: gpui-kit application

- **Entry point:** `gpui_kit::application().run(..)`, then `gpui_kit::init(cx)`,
  then `gpui_kit::open_window(..)`.
- **State:** one `AppState` entity holds two sets of `HostModel`s: live ones,
  and those of the open recording (a `ReplaySession`). The toolbar switches
  between the **Live** and **Recording** views. Live data keeps being received
  and recorded while a recording is open.
- **Bridges:** foreground tasks (`cx.spawn`) drain the live `Event` channel and
  the replay `Feed` channel. Each wakes on one item, drains the rest of the
  queue, and calls `cx.notify()` once per batch. A 200 ms ticker moves the
  timeline slider and position while replaying, redrawing only when the
  status shown (position to the second, speed, paused) changed, so a paused
  replay costs nothing.
- **Redraws** (a full redraw is about 2.4 ms with 490 processes):
  - Live: only the selected host's samples, or the host list changing,
    redraw at once. Other hosts' samples mark the sidebar out of date, and
    the ticker redraws it once a second; it also redraws once a second
    while any host is silent, so its dot turns red even when nothing at all
    arrives.
  - Replay: a seek delivers the 10 minutes before the target at once
    (about 120 ms of work per host). The feed is queued and applied in
    slices of at most 8 ms with frames drawn between, and anything queued
    before the last reset is skipped. Measured with 10 hosts: 986 ms of
    work in 92 slices, the longest 12 ms.
  - Graph lines are kept between redraws (`graph::LineCache`, per view,
    host, target and metric) and extended by the samples added since, as
    the chart redraws on every mouse move; a subtree's line walks every
    process of every sample. With 8 subtree lines a redraw went from 39 to
    2.8 ms. A line is computed afresh when the history no longer matches
    (cleared after a clock step), and all are dropped on a replay reset.
- **Live hosts are forgotten** after an hour of silence (their history and
  graph selection with them), and at most 256 are kept, the longest silent
  going first: each can hold tens of MB of history, and without a key anyone
  can send under made-up host IDs.
- **Window:** titled "sysmon", with app ID / WM_CLASS `sysmon` to match
  `crates/ui/dist/sysmon.desktop`.
- **Views** (built from `gpui_kit::component`):
  - a menu bar (File, View, Processes, Graph, Playback, Help). On Linux and
    Windows it's gpui-kit's in-window `AppMenuBar`; on macOS it's the native
    menu bar (`cx.set_menus`). Menu items show their shortcuts;
  - a toolbar with Live / Recording and Open recording… (the system file
    picker, via `cx.prompt_for_paths`; the recording is opened on the
    background executor, since that reads every segment's index), and any
    error, dismissed with its × or Esc;
  - a sidebar listing hosts by name, with a liveness dot ("silent for N")
    and the incomplete-frame rate;
  - a header with CPU, memory, network and disk figures, each with a
    sparkline (canvas paths), plus per-core bars and host details. Network
    draws receive and transmit, Disk read and write, as two lines on one
    scale: blue for incoming, orange for outgoing (from the graph palette;
    the theme's chart colours are all one hue), with the total (both directions
    added) on the title line and the two figures side by side below the
    sparkline, each in its line's colour and named in its accessible
    description. A sparkline is at least 160 px, and as wide as
    its tile when the text is wider;
  - a process table: a virtualized `uniform_list`, clickable column headers
    to sort (PID, user, %CPU, VIRT, RES, SHR, threads, command; RES is the
    resident set size (RSS), and "–" marks sizes a v1 agent didn't send), a filter input (command,
    user or exact PID), and stale rows dimmed. The USER column fits the
    longest name shown (measured with the monospace font), 4–16 characters;
    longer names keep both ends around `…` (`format::fit`), since names often
    share a prefix like `systemd-`. Hostnames, commands and legend labels end
    in `…` instead (their start is what tells them apart). Each shortened
    text has the full text as a tooltip and accessible description;
  - a **Tree** toggle that groups processes under their parent
    (`sysmon_model::tree::build`). Siblings follow the current sort, guide
    lines show the structure, and ▾/▸ collapse a subtree. A collapsed row
    shows how many descendants it hides and their summed CPU and memory.
    When filtering, matches are shown with their ancestors (dimmed) so they
    keep their place. Expand all / Collapse all act on the selected host;
  - **kernel threads** (`ProcRow::kernel_thread`: the agent's flag, or for
    data older than v3, kthreadd and its children) are left out by default
    (Ctrl+K); in the tree that's kthreadd's whole subtree, which never has
    user processes under it;
  - **threads** (Ctrl+H, off by default) come from `Snapshot::threads`. Each
    has its own %CPU from its own ticks and is carried over lost chunks like
    a process. They sort by %CPU, command or (for PID) TID in the chosen
    direction, otherwise by TID. In the flat view they follow their process; in the tree
    they're its *first* children, so the guides already drawn for its real
    children stay right. Memory columns show `–` (they're the process's), and
    collapsed totals don't include threads. A thread matching the filter
    keeps its process as dimmed context. Threads can be graphed
    (`SeriesTarget::Thread`, %CPU only; history is a 24-byte `ThreadPoint`
    per thread per sample);
  - **process graphs:** pick up to 8 rows with the checkbox column,
    Ctrl+click (toggle), Shift+click (range), or the row cursor (↑/↓, `j`/`k`)
    and `g`. Picking a collapsed tree row graphs its subtree's total. Picks
    are kept per view and host by `ProcKey`, so they survive sorting,
    filtering and tree changes, and each keeps its colour while picked;
  - a **graph panel** below the process list while anything is picked: one
    line per pick for the chosen metric (%CPU, VIRT, RES, SHR, %MEM, threads) over
    1, 5 or 10 minutes, drawn on a canvas (`graph.rs`). Lines break where a
    process was absent. Hovering shows a crosshair, and the legend switches
    to the values at that moment. The legend names each line (with a
    subtree's member count, or "exited") and removes it with ×. Drag the
    divider above the panel to resize it;
  - a **Logs** tab in the same panel (`L`), for hosts whose agents run with
    `--logs`: a virtualized list of `HostModel::logs` with time, priority
    (err and worse red, warning orange), unit (or identifier), PID and the
    message's first line (full text on hover). Lost and dropped lines have
    rows of their own. It keeps the newest line in view until you scroll
    up; **Jump to latest** resumes. Filters: text (message, unit,
    identifier), All / Warnings / Errors, and a unit picked by clicking it
    (a chip removes it); lost and dropped rows only show unfiltered.
    Clicking a PID moves the process table's cursor to that process (or
    says it isn't running or is hidden). Clicking a line selects it, kept by
    its receive and log times since a seek rebuilds the rows, and the graph
    draws a line at its time. In a recording the click also seeks to when
    the line was received, and the line is brought back into view once the
    seek's reset has rebuilt the list. The Graph tab is disabled until
    something is picked;
  - in the Recording view, a replay bar: play/pause, 1× to 256× speed, a
    timeline `Slider` that seeks on release, and start, position and end
    times. Red ticks under it mark where the selected host logged errors
    (err or worse), at most one per 1/500 of the timeline. They come from
    `logs::error_marks`, run in the background, which reads only the blocks
    each segment's `.marks` lists (6 hours: 70 → 0.9 ms). Segments without
    marks are read in full, skipping every datagram older than v5 by its
    version byte (0.3 s per host-day).
- **About and license notices:** Help → About opens a dialog with the
  version, sysmon's licenses, and every third-party crate in the binary with
  its license files (filterable, and savable as one document).
  `sysmon-ui --licenses` and `sysmon-agent --licenses` print the same kind
  of document for their own binary. Each binary's `build.rs` calls
  `sysmon_notices_build::generate`, and the binary embeds the result with
  `sysmon_notices::embed!`. The build side is a separate crate so that its
  `serde_json` never shows up as a dependency of the binaries (`cargo
  metadata` merges features across the workspace, so a feature flag
  wouldn't keep it out of the list). It builds the list with
  `cargo metadata`:
  - It follows only normal dependencies from the binary's own package,
    skipping proc-macro crates and everything under them, since none of
    that is linked in. Workspace crates are covered by sysmon's own license
    and left out.
  - It collects files named LICENSE*, LICENCE*, COPYING*, NOTICE*,
    COPYRIGHT* or UNLICENSE* anywhere in each package (which picks up
    bundled code, such as zstd's C sources or the Lucide icons).
  - For the few crates that publish no license file, it uses the standard
    text of their declared license, labelled as such.
  - Texts are deduplicated and zstd-compressed into the binary: about 1 MB
    of text becomes about 40 KB. They're decompressed the first time
    they're needed.
- **Times** are shown in the system's local time zone (`TZ`, or
  `/etc/localtime`), with the UTC offset beside the sample time and the
  replay position. The offset is worked out per timestamp, so a recording
  that spans a DST change reads correctly. Segment file names stay in UTC.
- **Keyboard:** every command is a gpui action (`crates/ui/src/actions.rs`).
  `SHORTCUTS` is the single table that both binds the keys and fills the
  F1 / `?` overlay. The root element sets the `SysmonApp` key context and
  holds focus; when the filter loses focus to nothing, focus returns to the
  root. Shortcuts without a modifier use the predicate
  `SysmonApp && !Input`, so they're off while typing in the filter.

  | Keys | Action |
  |---|---|
  | Ctrl+O, Ctrl+Q | Open recording, quit |
  | Ctrl+1, Ctrl+2 | Live view, Recording view |
  | Ctrl+↓, Ctrl+↑ | Next / previous host |
  | `l` | Logs tab, or back to the graph |
  | Ctrl+F or `/` | Filter processes (Enter returns, Esc clears) |
  | ↑/↓ or `j`/`k`, PgUp/PgDn | Move the row cursor |
  | `t`, `e`, `c` | Tree view, expand all, collapse all |
  | Ctrl+K, Ctrl+H | Hide/show kernel threads, show/hide threads |
  | `g`, Ctrl+G | Graph the cursor row (collapsed: its subtree), clear the graph |
  | `1`–`6`, `w`, `v` | Graph %CPU / VIRT / RES / SHR / %MEM / threads, cycle window, show/hide |
  | Shift+P / V / M / S | Sort by CPU / VIRT / RES / SHR (again flips) |
  | Shift+N / U / C | Sort by PID / user / command (again flips) |
  | Space, `]`, `[` | Play/pause, faster, slower |
  | ←/→, Shift+←/→, Home/End | Seek 10 s, 1 min, to start/end |
  | F1 or `?` | Shortcuts overlay |
- **Tests:** headless UI tests (`gpui-kit` `test-support`, dev-only) press
  keys and click in a real window and check the resulting state and layout:
  shortcuts (and that single-key ones don't fire while typing in the
  filter), the menu bar's position, picking rows, and the graph panel's
  placement, divider drag, legend and subtree values; and the Logs tab's
  list, following, filters, PID links, graph mark, and seeking from a line
  in a recording (driven by `ReplayHandle::manual`).
- **Opening recordings:** Open recording…, or
  `sysmon-ui --replay <data_dir>/<host>/…` (which doesn't listen).

## Threading (monitoring host)

| Thread | Work |
|---|---|
| gpui main | Rendering and `HostModel` updates (cheap: the difference between two frames) |
| `sysmon-ingest` | `recv_from`, open (decrypt), decode, assemble |
| `sysmon-recorder` | Compress, append and rotate segments; apply retention; write out on stop |
| `sysmon-replay` (per open recording) | Read and decompress blocks; pace events by the playback clock |
| `sysmon-signals` | On SIGINT/SIGTERM/SIGHUP, stop the recorder and exit |

## Security

UDP is unauthenticated, and on an untrusted network anyone can inject samples
or read them. There are two options, which can be combined:

1. Run the traffic over WireGuard or Tailscale.
2. Use sysmon's pre-shared key (`proto::seal`). `sysmon-agent --generate-key
   <path>` writes a 256-bit key (mode 0600). Give the same file to
   `--key-file` on the agent and on the monitor.
   - Each datagram is sealed with **XChaCha20-Poly1305**. The 4-byte preamble
     is the associated data, so flags can't be altered. The nonce is a random
     192 bits, carried in the datagram, so nonce reuse is not a practical
     concern even across agent restarts.
   - Layout: `preamble | nonce:24 | ciphertext | tag:16`. Chunk budgets
     always reserve these 40 bytes.
   - With a key, the monitor accepts **only** datagrams that authenticate
     with it. Without a key, it rejects encrypted datagrams.
   - Datagrams are decrypted before recording, so recordings don't need the
     key. Keep the data directory as private as the network, all the more
     with `--logs`, since journal lines often hold sensitive details. For
     that reason `--logs` needs a key unless `--logs-unencrypted` is given.
   - Replayed datagrams that are still authentic are mostly harmless. The
     assembler drops sequence numbers slightly behind the newest. A replayed
     sample 0, or one far behind, looks like an agent restart and resets
     that host's sequence tracking, but `HostModel` then ignores it, since
     it isn't newer than the last sample. At worst one sample shows as
     incomplete. Replayed datagrams are still written to the recording;
     replay drops them the same way.

Compression (`--compress`) runs before encryption and is applied only when it
shrinks the payload. On a host with about 490 processes, one tick was
14.5 KB uncompressed and 8.6 KB compressed and encrypted.

## Running

```sh
# Once: make a shared key and copy it to both machines
cargo run --release -p sysmon-agent -- --generate-key sysmon.key

# Monitoring machine: listen, record to ~/.local/share/sysmon (keep a week), show live
cargo run --release -p sysmon-ui -- --listen 0.0.0.0:9876 --key-file sysmon.key --keep-hours 168

# Remote machine
cargo run --release -p sysmon-agent -- --target monitor-host:9876 --compress --key-file sysmon.key

# Offline: replay a recording (a data dir, host dir, boot dir or one .seg file)
cargo run --release -p sysmon-ui -- --replay ~/.local/share/sysmon --speed 4

# Headless tools
cargo run -p sysmon-ingest --example dump -- 0.0.0.0:9876 [key] # print received frames
cargo run -p sysmon-model --example replay -- <path> [--tree]  # print a recording
```

## Status

Implemented, and covered by tests where noted:

- `proto`: protocol v5 (logs only; everything else v4) with v1–v3 still
  decodable; types, framing, chunking of samples, threads, `ProcMeta`,
  `Users` and log batches; zstd compression;
  XChaCha20-Poly1305 sealing, including tamper, wrong-key and plaintext
  rejection (tested).
- `agent`: collection from `/proc` with kept-open files and lenient
  decoding, including VIRT, SHR, kernel threads, physical disks only and
  (with `--threads`) threads; a boot-time clock in every sample; IPv4 and
  IPv6 targets; user names through NSS on a background thread; HostInfo,
  ProcMeta and Users scheduling; compression, encryption, key generation;
  `--licenses`; journal lines with `--logs` (export parsing, rate limit,
  saved position and resume tested, and run against the real journal);
  systemd unit (parsers, lookups, non-UTF-8 names, disks, IPv6 and the clock
  tested).
- `ingest`: authenticated receive thread and assembler: completion, loss,
  timeout, reboot and agent-restart handling (tested); `dump` example.
- `store`: segment writer and reader, torn-tail recovery, sparse index with
  seek and rebuild, catalog, retention (tested).
- `model`: CPU, per-process, net and disk rates, rows carried over lost
  chunks, process tree building, per-process history and graph series
  including subtree totals (tested); journal lines with reordering, loss
  and restarts, and error marks from a recording (tested); playback clock
  (tested); multi-host merged replay with seek, and the paced replay engine
  (tested); `replay` example (with `--logs`).
- `ui`: everything in section 6, plus writing out the recording on stop
  (tested). Keyboard, selection, the menu bar, the graph panel, kernel
  threads and threads, the USER column and shortened text, the Logs tab and
  the About dialog have headless UI tests; drawing itself is checked by
  running it.
- `notices`, `notices-build`: license notices for both binaries (tested).
- CI (GitHub Actions): formatting, clippy with warnings as errors, all
  tests, the minimum Rust versions (agent 1.93, workspace 1.98) and the
  static musl agent.
- Not done yet: a headless recorder binary.

Possible next steps:

1. More UI tests: the replay bar, and accessibility snapshots of the process
   table.
2. A details pane for a process or interface (per-interface and per-disk
   rates are already in the model), and graphs of those rates.
3. Thumbnails on the timeline (CPU across the whole recording, from the
   index or a summary file), and multiple selected hosts side by side.
4. Agent: per-process I/O (`/proc/[pid]/io`, needs privileges), cgroup and
   container grouping, and GPU stats.
5. Key rotation (several accepted keys, identified by a key-id byte).

## Version control

The repository uses **jj** (colocated with git, so cargo and other git-aware
tools keep working).

- Start each piece of work with `jj new -m "<crate>: <what>"`. Use
  `jj describe` to amend the message, and `jj squash` to fold fixes into the
  parent change.
- `target/` and `data/` are ignored so build output and recordings never end
  up in a snapshot.
- The repository has no remote yet. To publish, add one
  (`jj git remote add origin <url>`), then run `jj bookmark set main -r @-`
  and `jj git push`.
