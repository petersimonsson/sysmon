//! sysmon-ui: receives agent datagrams, records them, and shows them live, or
//! replays a recording.

mod about;
mod actions;
mod app;
mod format;
mod graph;
mod notices;
mod pipeline;
mod selection;
mod widgets;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use gpui_kit::*;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// UDP address to listen on for agents.
    #[arg(short, long, default_value = "0.0.0.0:9876")]
    listen: SocketAddr,
    /// Directory recordings are written to. Defaults to `$XDG_DATA_HOME/sysmon`.
    #[arg(short, long)]
    data_dir: Option<PathBuf>,
    /// Accept only datagrams encrypted with this pre-shared key file
    /// (generate one with `sysmon-agent --generate-key`).
    #[arg(short, long)]
    key_file: Option<PathBuf>,
    /// Don't record received data to disk.
    #[arg(long)]
    no_record: bool,
    /// Delete recordings older than this many hours.
    #[arg(long, value_name = "HOURS")]
    keep_hours: Option<u64>,
    /// Delete the oldest recordings once they take more than this many GiB.
    #[arg(long, value_name = "GIB")]
    max_gib: Option<f64>,
    /// Open a recording (a data dir, host dir, boot dir, or a single .seg
    /// file) instead of listening for agents.
    #[arg(long)]
    replay: Option<PathBuf>,
    /// Replay speed multiplier.
    #[arg(long, default_value_t = 1.0)]
    speed: f64,
    /// Print sysmon's license and the license notices of all third-party
    /// software in this binary, then exit.
    #[arg(long)]
    licenses: bool,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    if args.licenses {
        return Ok(notices::NOTICES.print()?);
    }
    let data_dir = args.data_dir.clone().unwrap_or_else(default_data_dir);

    // Stops the recorder cleanly when the app quits or is signalled.
    let mut stopper: Option<pipeline::RecorderHandle> = None;
    let start = match &args.replay {
        Some(path) => app::Start {
            live: None,
            replay: Some(pipeline::open_replay(path, args.speed)?),
            replay_label: path.display().to_string(),
            data_dir,
        },
        None => {
            let recording = (!args.no_record).then(|| pipeline::Recording {
                dir: data_dir.clone(),
                retention: sysmon_store::Retention {
                    max_age: args.keep_hours.map(|h| Duration::from_secs(h * 3600)),
                    max_bytes: args.max_gib.map(|g| (g * (1u64 << 30) as f64) as u64),
                },
            });
            let (live, recorder) = pipeline::start_live(args.listen, opener(&args)?, recording)?;
            if let Some(r) = &recorder {
                stop_recording_on_signals(r.clone())?;
            }
            stopper = recorder;
            app::Start {
                live: Some(live),
                replay: None,
                replay_label: String::new(),
                data_dir,
            }
        }
    };

    gpui_kit::application().run(move |cx| {
        gpui_kit::init(cx);
        actions::init(cx);
        // Ctrl+Q, File → Quit and closing the window all end up here.
        if let Some(r) = stopper.clone() {
            cx.on_app_quit(move |_| {
                r.stop(STOP_TIMEOUT);
                async {}
            })
            .detach();
        }
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(px(1200.), px(800.)),
                cx,
            ))),
            ..Default::default()
        };
        gpui_kit::open_window(options, cx, |window, cx| {
            cx.new(|cx| app::AppState::new(start, window, cx))
        })
        .expect("failed to open window");
        cx.activate(true);
    });
    Ok(())
}

/// Longest to wait for the recording to be written out when stopping.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// On SIGINT (Ctrl+C), SIGTERM (e.g. systemd) or SIGHUP, write out the
/// recording before exiting, instead of losing what was still buffered.
fn stop_recording_on_signals(recorder: pipeline::RecorderHandle) -> anyhow::Result<()> {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP])?;
    std::thread::Builder::new()
        .name("sysmon-signals".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                tracing::info!(signal = sig, "stopping");
                recorder.stop(STOP_TIMEOUT);
                // The conventional status for "terminated by this signal".
                std::process::exit(128 + sig);
            }
        })?;
    Ok(())
}

fn opener(args: &Args) -> anyhow::Result<sysmon_proto::Opener> {
    let key = args
        .key_file
        .as_deref()
        .map(sysmon_proto::Key::from_file)
        .transpose()?;
    Ok(sysmon_proto::Opener::new(key.as_ref()))
}

fn default_data_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sysmon")
}
