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
   datagrams verbatim, plus a receive timestamp. Replay feeds them through the
   same decoder and assembler as live data.
4. **The UI doesn't know where its data comes from.** Live and replay both
   implement one `DataSource` trait that yields `Frame`s.
5. **Only `sysmon-ui` depends on gpui.** Protocol, ingest, storage and
   modelling are plain libraries that can be tested headless. A headless
   recorder is just `ingest` + `store`.

## Workspace layout

| Crate | Kind | Responsibility |
|---|---|---|
| `crates/proto` (`sysmon-proto`) | lib | Wire types, framing, chunking, encode/decode, `Frame` |
| `crates/agent` (`sysmon-agent`) | bin | Collect from `/proc`, encode, send over UDP |
| `crates/ingest` (`sysmon-ingest`) | lib | UDP receive thread, chunk reassembly, fan-out |
| `crates/store` (`sysmon-store`) | lib | Segment files: append-only writer, reader, index, retention |
| `crates/model` (`sysmon-model`) | lib | Rate computation, history ring buffers, `DataSource` (live and replay) |
| `crates/ui` (`sysmon-ui`) | bin | gpui-kit application: host list, header graphs, process table, timeline |
| `crates/notices` (`sysmon-notices`) | lib | Embedded license notices: data types, `embed!`, the full notices document |
| `crates/notices-build` (`sysmon-notices-build`) | lib | Build-script side: collects a binary's notices with `cargo metadata` |

Dependency graph (arrows point at dependencies):

```
agent ──► proto ◄── ingest ◄──┐
            ▲  ▲              ├── ui
          store └── model ◄───┘
            ▲         │
            └─────────┘   (model's ReplaySource reads the store)
```

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
}
```

- A **sample** is one tick. It is sent as one `System` datagram (chunk 0)
  followed by as many `Procs` datagrams as needed, all with the same `seq`.
- `HostInfo` is sent at start-up and then every ~10 s, so a monitor that
  starts late learns about the host quickly.
- `ProcMeta` carries the strings that rarely change (full command line, uid).
  The agent sends it for processes it hasn't seen before, and sends a full
  refresh every ~30 s. `ProcSample` carries only `comm` (≤ 16 bytes).
- `Users` lists only uids that running processes use. It's sent with
  `HostInfo`, and also as soon as a newly resolved name is available.
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
  by `(tid, starttime)`, which never collides with a process key). v1 and v2
  are frozen in `proto::v1` and `proto::v2`. Monitors must be upgraded before
  agents, since an older monitor rejects newer versions.
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
}
```

## 2. `sysmon-agent`: collector

- One thread and no async runtime:
  `loop { collect(); encode(); send(); sleep_until(next_tick) }` with a
  blocking `std::net::UdpSocket`.
- It reads `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/[pid]/stat`,
  `/proc/[pid]/statm`, `/proc/net/dev` and `/proc/diskstats` into one reused
  buffer. `statm` is read only for SHR (its third field). That second read
  per process costs about 57 % more agent CPU: 4.1 → 6.5 ms per sample of
  about 495 processes, or 0.4 % → 0.65 % of a core at 1 Hz.
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
  `--compress`, `--key-file`, `--generate-key <path>`, `--threads`, and
  `--licenses` (third-party license notices; see section 6).
- `kernel_thread` comes from the `flags` field of `stat`, which is already
  read, so it costs nothing.
- `--threads` (off by default) also reads `/proc/[pid]/task/*/stat` for every
  user process with more than one thread, and sends all threads but the main
  one, which is the process row. Measured with ~470 processes and ~1700
  threads: 6.8 → 17 ms per sample, and 10.1 → 26.5 KB per sample
  compressed.
- Deployment: a static musl build
  (`rustup target add x86_64-unknown-linux-musl`, then
  `cargo build --release -p sysmon-agent --target x86_64-unknown-linux-musl`)
  plus the sandboxed systemd unit in `crates/agent/dist/sysmon-agent.service`.

## 3. `sysmon-ingest`: receiver

- A dedicated thread does a blocking `recv_from`, then **opens** each
  datagram with the configured key (dropping anything that fails to
  authenticate), and hands the opened datagram to:
  - the **store** channel, as bytes plus the receive timestamp, and
  - the **assembler**, which decodes the datagram.
- The `Assembler` keys partial samples by `(host_id, seq)`. It emits a `Frame`
  as soon as all `chunks` have arrived, or with `complete = false` once a
  newer `seq` arrives or the sample times out (~1.5× the interval). A
  `boot_id` change resets that host's state.
- **Agent restarts:** a restarted agent has the same host and boot but numbers
  its samples from 0 again. The assembler treats a sample 0 seen after later
  ones, or a sample more than 64 behind the newest, as a restart and resets
  that host's sequence state. Anything less far behind is a late or
  duplicated packet and is dropped. The restarted agent resends `HostInfo`,
  `Users` and every `ProcMeta` in its first sample, so changed settings (e.g.
  `--threads`) take effect at once. As a guard against a late duplicate
  being taken for a restart, `HostModel` ignores samples that aren't newer
  than the last one from that boot. The first rates after a restart average
  over the downtime, as after lost samples.
- Channels are bounded (`flume`). When a consumer falls behind, frames are
  dropped and counted. The socket thread never blocks.

## 4. `sysmon-store`: offline storage

### Files

```
<data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.seg   # one segment per host per hour (UTC)
<data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.idx   # sparse time index
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
- **Catalog:** `list_segments` finds every segment under a directory and
  parses host, boot and hour from its path.
- **Retention:** `prune` deletes whole hour files beyond a maximum age or total
  size (`--keep-hours`, `--max-gib`), oldest first, and never the current
  hour. The recorder runs it every 10 minutes.
- The writer runs on its own thread so a disk stall never reaches the socket
  or the UI.

## 5. `sysmon-model`: state and data sources

```rust
pub trait DataSource: Send {
    fn next_event(&mut self) -> Option<Event>;   // Frame | HostInfo | ProcMeta
    fn seek(&mut self, _ts_unix_ns: u64) {}
    fn kind(&self) -> SourceKind;                // Live | Replay
}
```

- `LiveSource` wraps the ingest `Receiver<Event>`.
- `ReplaySource` opens every segment under a path, groups them into one
  stream per (host, boot), and merges the streams by **receive time**, which
  is the monitor's single clock. It feeds records through an `Assembler`
  exactly as live traffic is fed, and seeks each stream through the index.

### Replay engine

`replay::spawn(source, speed)` runs a thread that emits events when a
`PlaybackClock` (which maps wall time onto recording time, with speed, pause
and seek) reaches them. It returns a `ReplayHandle`:

- `feed: Receiver<Feed>`, where `Feed` is `Event(Event)` or `Reset`. `Reset`
  is sent on every seek, so the UI discards models built before the jump;
- `send(Control)`: `SetPaused`, `TogglePause`, `SetSpeed`, `Seek(ts)`;
- `status()`: start, end, position, speed, paused, finished.

A seek starts reading the full history window (10 min) before the target and
delivers it at once, so the models have rates and the process graphs are
full as soon as the target is shown. Gaps in the recording longer than 5 s (an
agent or the monitor was offline) are skipped rather than waited out.

### `HostModel`

`HostModel` is fed events and keeps:

- the previous and current samples, used for CPU %, memory, and per-interface
  and per-disk rates (bytes/s and disk busy %);
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
- liveness: when the last sample was taken, and the incomplete-frame rate.

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
  timeline slider and position while replaying.
- **Views** (built from `gpui_kit::component`):
  - a menu bar (File, View, Processes, Playback, Help). On Linux and
    Windows it's gpui-kit's in-window `AppMenuBar`; on macOS it's the native
    menu bar (`cx.set_menus`). Menu items show their shortcuts;
  - a toolbar with Live / Recording and Open recording… (the system file
    picker, via `cx.prompt_for_paths`);
  - a sidebar listing hosts with a liveness dot ("silent for N") and the
    incomplete-frame rate;
  - a header with CPU, memory, network and disk figures, each with a
    sparkline (canvas paths), plus per-core bars and host details;
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
    a process. In the flat view they follow their process; in the tree
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
  - in the Recording view, a replay bar: play/pause, 1× to 256× speed, a
    timeline `Slider` that seeks on release, and start, position and end
    times.
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
  - It follows only normal dependencies from `sysmon-ui`, skipping
    proc-macro crates and everything under them, since none of that is
    linked in.
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
  placement, divider drag, legend and subtree values.
- **Opening recordings:** Open recording…, or
  `sysmon-ui --replay <data_dir>/<host>/…` (which doesn't listen).

## Threading (monitoring host)

| Thread | Work |
|---|---|
| gpui main | Rendering and `HostModel` updates (cheap: the difference between two frames) |
| net | `recv_from`, decode, assemble |
| store | Compress, append and rotate segments; apply retention |
| replay (per open recording) | Read and decompress blocks; pace events by the playback clock |

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
     key. Keep the data directory as private as the network.
   - Replayed datagrams that are still authentic are mostly harmless: the
     assembler drops sequence numbers it has already emitted for that boot.

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

- `proto`: types, framing, chunking of samples, `ProcMeta` and `Users`; zstd
  compression; XChaCha20-Poly1305 sealing, including tamper, wrong-key and
  plaintext rejection (tested).
- `agent`: collection from `/proc` with a reused buffer; HostInfo, ProcMeta
  and Users scheduling; compression, encryption, key generation; systemd
  unit (parser tested).
- `ingest`: authenticated receive thread and assembler: completion, loss,
  timeout and reboot handling (tested); `dump` example.
- `store`: segment writer and reader, torn-tail recovery, sparse index with
  seek and rebuild, catalog, retention (tested).
- `model`: CPU, per-process, net and disk rates, rows carried over lost
  chunks, process tree building, per-process history and graph series
  including subtree totals (tested); playback clock (tested); multi-host merged replay with
  seek, and the paced replay engine (tested); `replay` example.
- `ui`: everything in section 6. Keyboard, selection, the menu bar and the
  graph panel have headless UI tests; drawing itself is checked by running
  it.

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
- To publish, run `jj bookmark set main -r @-` and then `jj git push`.
