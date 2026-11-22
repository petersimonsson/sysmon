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
- `flags` is reserved for payload compression (zstd/lz4) and authenticated
  encryption (see [Security](#security)).
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
}
```

- A **sample** is one tick. It is sent as one `System` datagram (chunk 0)
  followed by as many `Procs` datagrams as needed, all with the same `seq`.
- `HostInfo` is sent at start-up and then every ~10 s, so a monitor that
  starts late learns about the host quickly.
- `ProcMeta` carries the strings that rarely change (full command line, uid).
  The agent sends it for processes it hasn't seen before, and sends a full
  refresh every ~30 s. `ProcSample` carries only `comm` (≤ 16 bytes).
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
    pub complete: bool,                 // false if any chunk was missing
}
```

## 2. `sysmon-agent`: collector

- One thread and no async runtime:
  `loop { collect(); encode(); send(); sleep_until(next_tick) }` with a
  blocking `std::net::UdpSocket`.
- It reads `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/[pid]/stat`,
  `/proc/net/dev` and `/proc/diskstats`. Buffers are reused between ticks.
- It tracks the set of known `(pid, starttime)` pairs to decide when to emit
  `ProcMeta`.
- CLI (`clap`): `--target host:port` (repeatable), `--interval 1s`,
  and later `--key-file`.
- Deployment: a static musl build plus a systemd unit.

## 3. `sysmon-ingest`: receiver

- A dedicated thread does a blocking `recv_from` and hands each datagram to:
  - the **store** channel, as raw bytes plus the receive timestamp, and
  - the **assembler**, which decodes the datagram.
- The `Assembler` keys partial samples by `(host_id, seq)`. It emits a `Frame`
  as soon as all `chunks` have arrived, or with `complete = false` once a
  newer `seq` arrives or the sample times out (~1.5× the interval). A
  `boot_id` change resets that host's state.
- Channels are bounded (`flume`). When a consumer falls behind, frames are
  dropped and counted. The socket thread never blocks.

## 4. `sysmon-store`: offline storage

### Files

```
<data_dir>/<host_id>/<boot_id>/<YYYY-MM-DDTHH>.seg   # one segment per host per hour
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
- **Index:** one `(first_ts, last_ts, offset)` entry per block. Seeking is a
  binary search plus decompressing one block. The index can be rebuilt from
  the segment if it is missing.
- **Retention:** delete whole hour files beyond a configured age or total size.
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
- `ReplaySource` wraps a `SegmentReader` and an `Assembler`, paced by a
  `PlaybackClock` (speed, pause, seek).

`HostModel` is fed `Frame`s and keeps:

- the previous and current samples, used for CPU %, memory, and net/disk rates;
- per-process `%CPU = Δ(utime + stime) / clk_tck / Δwall`;
- a ring buffer of derived system metrics (default 10 minutes) for sparklines;
- a process table `HashMap<(pid, starttime), ProcRow>`, joined with `ProcMeta`;
- liveness: when the last packet arrived, and the chunk loss rate.

## 6. `sysmon-ui`: gpui-kit application

- **Entry point:** `gpui_kit::application().run(..)`, then `gpui_kit::init(cx)`,
  then `gpui_kit::open_window(..)`.
- **Entities:** `AppState` (hosts, selection, live/replay mode) owns one
  `Entity<HostModel>` per host.
- **Bridge:** a foreground task spawned with `cx.spawn` drains the frame
  channel, applies frames with `model.update(cx, ..)`, and calls `cx.notify()`.
  Repaints are coalesced to at most the display rate.
- **Views** (built from `gpui_kit::component`):
  - a sidebar listing hosts with liveness and loss indicators;
  - a header with per-core CPU bars, memory and swap bars, the load average,
    and sparklines;
  - a process table: a virtualized list, sortable columns (CPU, MEM, PID,
    user, command), a filter, and an optional tree view by `ppid`;
  - in replay mode, a timeline scrubber and play/pause/speed controls.
- **Opening recordings:** File → Open recording, or
  `sysmon-ui --replay <data_dir>/<host>/…`.

## Threading (monitoring host)

| Thread | Work |
|---|---|
| gpui main | Rendering and `HostModel` updates (cheap: the difference between two frames) |
| net | `recv_from`, decode, assemble |
| store | Compress, append and rotate segments; apply retention |
| replay (on demand) | Read and decompress blocks; pace frames by the playback clock |

## Security

UDP is unauthenticated, and on an untrusted network anyone can inject samples.
There are two options:

1. Run the traffic over WireGuard or Tailscale. This is the recommended
   default, and nothing in sysmon changes.
2. Use a pre-shared key with `chacha20poly1305` AEAD per datagram. This is
   signalled by a bit in `flags`, and the nonce is derived from
   `(boot_id, seq, chunk)`.

## Running

```sh
# Monitoring machine: listen, record to ~/.local/share/sysmon, show live
cargo run --release -p sysmon-ui -- --listen 0.0.0.0:9876

# Remote machine
cargo run --release -p sysmon-agent -- --target monitor-host:9876

# Offline: replay a recording (a data dir, host dir, boot dir or one .seg file)
cargo run --release -p sysmon-ui -- --replay ~/.local/share/sysmon --speed 4

# Headless tools
cargo run -p sysmon-ingest --example dump -- 0.0.0.0:9876     # print received frames
cargo run -p sysmon-model --example replay -- <path>           # print a recording
```

## Status

Implemented in the scaffold, and covered by tests where noted:

- `proto`: all types, framing, chunking of samples and of `ProcMeta` (tested).
- `agent`: CPU, memory, load, net, disk and process collection from `/proc`;
  HostInfo and ProcMeta scheduling; drift-free tick loop (parser tested).
- `ingest`: receive thread and assembler: completion, loss, timeout and
  reboot handling (tested); `dump` example.
- `store`: segment writer and reader, torn-tail recovery, per-host, per-boot,
  per-hour rotation (tested).
- `model`: CPU % and per-process %CPU from counter deltas (tested), history
  ring buffer, `LiveSource`, `ReplaySource`; `replay` example.
- `ui`: gpui-kit window with a host sidebar, CPU and memory bars, load
  average, and a process table sorted by CPU. It records in live mode and
  plays back paced recordings in replay mode.

Next steps:

1. Store: `.idx` sparse index, seek, retention.
2. Model: `PlaybackClock` (pause, speed, seek), with pacing moved out of the
   UI; carrying forward process rows that were in lost chunks; net and disk
   rates.
3. UI: a virtualized `uniform_list` process table with sortable columns and a
   filter; sparklines from `history`; a timeline scrubber in replay mode;
   File → Open recording; uid → user name (needs `HostInfo` to carry
   `/etc/passwd` names, or a `UserMeta` message).
4. Agent: a systemd unit, a musl release build, and reusing `/proc` read
   buffers.
5. Protocol: zstd payload compression and AEAD (the `flags` bits are reserved).

## Version control

The repository uses **jj** (colocated with git, so cargo and other git-aware
tools keep working).

- Start each piece of work with `jj new -m "<crate>: <what>"`. Use
  `jj describe` to amend the message, and `jj squash` to fold fixes into the
  parent change.
- `target/` and `data/` are ignored so build output and recordings never end
  up in a snapshot.
- To publish, run `jj bookmark set main -r @-` and then `jj git push`.
