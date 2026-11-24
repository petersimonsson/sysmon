# sysmon

A `top`-like system monitor split in two:

- **`sysmon-agent`** runs on each machine you want to watch. It samples
  `/proc` once a second and sends the raw counters over UDP. It's a single
  small binary that depends only on libc.
- **`sysmon-ui`** runs on your desktop. It receives data from any number of
  agents, shows it live, and records it to disk so you can replay it later.

The UI shows per-host CPU, memory, network and disk with short history
graphs, and a process table you can sort, filter and view as a tree. You can
pick processes (or whole subtrees) and graph their %CPU, memory or thread
count over the last 10 minutes. Recordings replay at up to 256× speed with
seeking.

See [docs/architecture.md](docs/architecture.md) for how it works inside.

## Requirements

- **Rust 1.98 or newer** for the UI (gpui needs it), or **1.93 or newer**
  for just the agent (`cargo build -p sysmon-agent`). Install it with
  [rustup](https://rustup.rs).
- **Agent:** Linux (it reads `/proc`). Nothing else.
- **UI:** developed and tested on Linux. It's built with
  [gpui-kit](https://gpui-kit.com), which also supports macOS and Windows,
  but those haven't been tried. On Linux it needs:
  - a C compiler and `pkg-config` (to build the bundled zstd library);
  - the development files for **xkbcommon** (with its X11 part), **xcb** and
    **freetype**, which the UI links against;
  - a **Vulkan** driver at run time, which gpui renders with.

  Package names vary between distributions; these should cover it:

  ```sh
  # Debian / Ubuntu
  sudo apt install build-essential pkg-config libxkbcommon-dev libxkbcommon-x11-dev \
      libxcb1-dev libfreetype-dev libvulkan1 mesa-vulkan-drivers

  # Fedora
  sudo dnf install gcc pkgconf-pkg-config libxkbcommon-devel libxkbcommon-x11-devel \
      libxcb-devel freetype-devel vulkan-loader mesa-vulkan-drivers

  # Arch
  sudo pacman -S base-devel libxkbcommon libxkbcommon-x11 libxcb freetype2 \
      vulkan-icd-loader   # plus vulkan-radeon, vulkan-intel or nvidia-utils
  ```

## Building

```sh
cargo build --release                     # everything
cargo build --release -p sysmon-agent     # just the agent (fast, no GUI deps)
cargo build --release -p sysmon-ui        # just the UI
```

The binaries end up in `target/release/`. The first UI build takes a while,
because it compiles gpui.

To get an agent you can copy to any x86-64 Linux machine, build it statically
with musl:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release -p sysmon-agent --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/sysmon-agent
```

## Quick start

To try it on one machine, run both halves locally:

```sh
cargo run --release -p sysmon-ui -- --listen 127.0.0.1:9876 &
cargo run --release -p sysmon-agent -- --target 127.0.0.1:9876
```

The host shows up in the sidebar within a second.

## Monitoring other machines

1. **Make a shared key** and copy it to the monitoring machine and to every
   agent. It's optional, but without it anyone who can reach the UDP port can
   read your data and inject fake samples.

   ```sh
   sysmon-agent --generate-key sysmon.key     # 64 hex digits, mode 0600
   ```

2. **Start the UI** on the monitoring machine. Open UDP port 9876 in its
   firewall.

   ```sh
   sysmon-ui --key-file sysmon.key
   ```

3. **Start an agent** on each machine to watch:

   ```sh
   sysmon-agent --target monitor.example:9876 --compress --key-file sysmon.key
   ```

   `--compress` roughly halves the bandwidth (about 9 KB per second for a host
   with 500 processes). `--target` can be given several times to send to more
   than one monitor, by name or by IPv4 or IPv6 address (e.g.
   `[2001:db8::7]:9876`). Add `--threads` to send every thread as well, so the UI
   can list them. That costs about 3× the agent's CPU and 2.5× its bandwidth
   (measured with ~1750 threads: 9 ms and 26 KB per sample), so it's off by
   default.

   Add `--logs` to send the machine's journal lines too (warning and above;
   change with `--log-priority`, e.g. `err` or `info`, and limit to units
   with `--log-unit`, which can be repeated). The agent runs `journalctl`, so
   it must be in the `systemd-journal` group to see system logs. Logs often
   hold sensitive details, so `--logs` needs `--key-file` unless you add
   `--logs-unencrypted`. Over 200 lines or 256 KiB per second, lines are
   dropped and the UI says how many. Use `--log-cursor-file` to keep the
   journal position across restarts (the systemd unit does this for you), so
   a restarted agent sends what was logged while it was down.

   **Upgrading:** update the monitor before the agents. A newer monitor reads
   data from older agents (and old recordings), but an older monitor rejects
   a newer agent's data. The exception is logs: a monitor from before them
   still reads everything else from an agent sending `--logs`, and only
   rejects the log datagrams.

### Running the agent as a service

`crates/agent/dist/sysmon-agent.service` is a sandboxed systemd unit. The
comment at the top of the file has the install steps. In short: copy the
binary to `/usr/local/bin`, the key to `/etc/sysmon/key`, put
`SYSMON_TARGET=monitor.example:9876` in `/etc/default/sysmon-agent`, then
`systemctl enable --now sysmon-agent`. To send journal lines, switch to the
commented-out `--logs` line in the unit; it already has the journal group
and a state directory for the journal position.

### Desktop entry

`crates/ui/dist/sysmon.desktop` puts `sysmon-ui` in the desktop's
application menu: copy it to `~/.local/share/applications/` (with
`sysmon-ui` on your `PATH`).

## Using the UI

### Command-line options

| Option | Default | |
|---|---|---|
| `-l, --listen ADDR` | `0.0.0.0:9876` | UDP address to receive agents on |
| `-k, --key-file PATH` | none | Accept only data encrypted with this key |
| `-d, --data-dir DIR` | `~/.local/share/sysmon` | Where recordings are written |
| `--no-record` | | Don't record |
| `--keep-hours N` | keep all | Delete recordings older than N hours |
| `--max-gib N` | no limit | Delete the oldest recordings above N GiB |
| `--replay PATH` | | Open a recording instead of listening |
| `--speed N` | `1` | Replay speed |
| `--licenses` | | Print all license notices and exit |

### The window

- **Sidebar:** one entry per host, by name. The dot turns red when the
  monitor hasn't heard from a host for three intervals; a host silent for
  an hour is dropped. Click a host to show it.
- **Header:** CPU, memory, network and disk for the selected host, each with
  a short history graph, plus a bar for every core. The network graph shows
  receive (blue) and transmit (orange), the disk graph read (blue) and
  write (orange); the figure at the top is the two added together.
- **Process table:** like htop, memory is shown as **VIRT** (virtual size),
  **RES** (resident set size, RSS) and **SHR** (resident memory shared
  with other processes, e.g. libraries), plus %MEM (RES as a share of RAM).
  "–" means the agent didn't report it (agents older than protocol v2).
  - The USER column is as wide as the longest name shown, up to 16
    characters. Longer names are shortened in the middle, keeping both ends
    (`systemd-journal-remote` → `systemd-…-remote`), because many names share
    a prefix. Hover for the full name and uid. Long hostnames, commands and
    graph legend labels end in `…` instead, with the full text on hover.
  - User names come from the monitored machine's user lookup (as `getent
    passwd` would find them), so LDAP, SSSD and systemd dynamic users are
    named too. A user shows as a number until its name arrives. The static
    musl build of the agent can only see users in `/etc/passwd`.
  - Click a column header to sort, and click it again to reverse.
  - Type in the filter box to match command, user or an exact PID.
  - **Tree** groups processes under their parent. Click ▾/▸ to collapse a
    subtree; a collapsed row shows the subtree's total CPU, RES and VIRT.
    (Like htop's, these totals count memory shared between the processes
    more than once.)
  - **Hide kernel threads** (on by default, Ctrl+K) leaves out the kernel's
    own threads (`kthreadd` and its children), which are often most of the
    list. The header and status line say how many there are.
  - **Show threads** (off by default, Ctrl+H) lists each process's threads
    under it, marked `↳`, with their own state and %CPU. Their memory is the
    process's, so those columns show `–`. In the tree they're the first
    children of their process. This needs agents started with `--threads`;
    otherwise the status line says so.
  - Thread names match the filter too. A process with a matching thread is
    shown (dimmed) along with it.
- **Graphs:** pick up to 8 processes with the checkbox at the left of a row,
  Ctrl+click, or Shift+click for a range. A panel opens below the table with
  one line per process (or thread). Picking a collapsed tree row graphs the whole
  subtree's total.
  - Choose the metric (%CPU, VIRT, RES, SHR, %MEM, threads) and the time window (1, 5 or
    10 minutes) at the top of the panel.
  - Hover over the chart to read the values at that moment.
  - Drag the divider above the panel to resize it.
- **Logs:** press `L`, or choose the **Logs** tab in the bottom panel, to see
  the host's journal lines (from agents started with `--logs`): time,
  priority (errors red, warnings orange), unit, PID and message, with the
  full message on hover.
  - The list keeps the newest line in view; scroll up to stop that, and
    **Jump to latest** to start again.
  - Filter by text, show **All**, **Warnings** or **Errors**, or click a
    unit to see only its lines (click its chip in the toolbar to undo).
  - Click a PID to find the process in the table. Click a line to select it:
    its time is marked on the graph.
  - Lines lost on the network, or dropped by the agent, are shown as such.
- **Process details:** press `D` or Enter, or choose the **Details** tab in
  the bottom panel, to see everything about the process under the row
  cursor. The tab follows the cursor as it moves.
  - It shows the PID, parent, user, state, when the process started and how
    long it has run, the full command line, and a small graph of each
    metric.
  - It also lists the process's children, its threads (from agents started
    with `--threads`) and its log lines (`--logs`).
  - Click the parent or a child to move to it, click a log line to open it
    in the Logs tab, and use **Graph** to add the process to the graph.
  - A process that exits stays on show, marked *exited*, until you move the
    cursor.
- **Times** are shown in your local time zone.
- **Help → About sysmon** shows the version, sysmon's licenses, and the
  license of every third-party crate built into the UI, with the full texts.
  **Save all notices…** writes them all to one file.

### Recordings

While listening, the UI records everything it receives, under
`<data dir>/<host>/<boot>/<YYYY-MM-DDTHH>.seg`, with one file per host per
hour (named in UTC). It goes on recording while you look at an old recording.
Stopping the UI (Ctrl+C, `SIGTERM`, Ctrl+Q or closing the window) writes out
what it has received first. A restarted UI carries on in the same files,
and the time it was down shows as a gap. For up to 30 s after it starts, the
command lines and users of processes that were already running may be
missing, until the agents' next full metadata refresh.

To replay a recording, use **File → Open Recording…** (Ctrl+O). It lists
the recordings in the data directory, one row per boot of each machine,
grouped by machine with the newest first. Each row shows the time covered,
how long that is, a bar with the gaps (times when nothing was recorded) and
their total length, the size on disk, and a **recording** badge if it is still
being recorded. Type to filter by machine name, use ↑/↓ to pick a row and
Enter (or a double-click) to open it. Opening a machine's row opens all its
boots, and **Open all** opens the whole data directory. **Browse…** opens a
recording from somewhere else. You can also start with
`sysmon-ui --replay ~/.local/share/sysmon`, and give it the whole data
directory, one host or boot directory, or a single `.seg` file. Use the
replay bar at the bottom to play, pause, change speed and seek. Recordings
from several hosts play back together, in the order they were received.

Logs are recorded too. Red ticks under the replay bar show where the
selected host logged errors. In the Logs tab, clicking a line jumps there,
so the graphs and process table show that moment; after a jump, the list
shows the 10 minutes leading up to it.

### Keyboard

Press **F1** or **?** in the app for the full list. The most useful ones:

| Keys | |
|---|---|
| Ctrl+O, Ctrl+Q | Open recording, quit |
| Ctrl+1, Ctrl+2 | Live view, Recording view |
| Ctrl+↑ / Ctrl+↓ | Previous / next host |
| `l` | Logs, or back to the graph |
| `d` or Enter | Details of the cursor row's process, or back to the graph |
| Ctrl+F or `/` | Filter (Enter goes back to the list, Esc clears) |
| ↑/↓ or `j`/`k` | Move the row cursor |
| `g`, Ctrl+G | Graph the cursor row, clear the graph |
| `1`–`6`, `w`, `v` | Graph %CPU / VIRT / RES / SHR / %MEM / threads, change window, show/hide graph |
| `t`, `e`, `c` | Tree view, expand all, collapse all |
| Ctrl+K, Ctrl+H | Hide/show kernel threads, show/hide threads |
| Shift+P / V / M / S | Sort by CPU / VIRT / RES / SHR |
| Shift+N / U / C | Sort by PID / user / command |
| Space, `[`, `]` | Play/pause, slower, faster |
| ←/→, Shift+←/→, Home/End | Seek 10 s, 1 min, to start/end |

Single-letter shortcuts are turned off while you type in the filter.

## Command-line tools

Two small programs let you look at the data without the UI:

```sh
# Print what arrives on a port (add a key file as the second argument if used)
cargo run -p sysmon-ingest --example dump -- 0.0.0.0:9876 sysmon.key

# Print a recording sample by sample, or its last sample as a process tree
cargo run -p sysmon-model --example replay -- ~/.local/share/sysmon
cargo run -p sysmon-model --example replay -- ~/.local/share/sysmon --tree
# ... or the journal lines it holds, and where errors are
cargo run -p sysmon-model --example replay -- ~/.local/share/sysmon --logs
```

## Development

The workspace has one crate per part:

| Crate | |
|---|---|
| `crates/proto` | Wire format, chunking, compression and encryption |
| `crates/agent` | The collector |
| `crates/ingest` | UDP receiver and reassembly |
| `crates/store` | Recording files, index and retention |
| `crates/model` | Rates, history, process trees, graph series, replay engine |
| `crates/ui` | The gpui-kit application |
| `crates/notices`, `crates/notices-build` | License notices embedded in both binaries |

```sh
cargo test --workspace                    # all tests, including headless UI tests
cargo clippy --workspace --all-targets
cargo fmt --all
```

The UI tests open real windows headlessly through gpui-kit's `test-support`
feature, press keys, click and check the results. They need no display.

CI (`.github/workflows/ci.yml`, GitHub Actions) runs on pushes to `main` and
on pull requests:

- formatting (`cargo fmt --check`);
- clippy with warnings as errors, and all tests, on stable;
- the minimum Rust versions: the agent's tests on 1.93, and the whole
  workspace built on 1.98;
- a static musl build of the agent, kept as a downloadable artifact for 14
  days.

`.github/install-deps.sh` installs the UI's Ubuntu build packages.

The repository uses [jj](https://jj-vcs.github.io/jj/), colocated with git:
start a piece of work with `jj new -m "<crate>: <what>"`, and see
[docs/architecture.md](docs/architecture.md#version-control) for the rest.

## Distributing binaries

The licenses of the crates sysmon is built from (MIT, Apache-2.0, BSD and
others) require their notices to be shipped with the binaries. Both binaries
have them built in, and can write them out to ship alongside:

```sh
sysmon-ui --licenses    > THIRD_PARTY_LICENSES-ui.txt      # also in Help → About
sysmon-agent --licenses > THIRD_PARTY_LICENSES-agent.txt
```

Each binary's `build.rs` collects them at build time from exactly the crates
linked into that binary (552 for the UI, 64 for the agent), so the lists are
always current.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
