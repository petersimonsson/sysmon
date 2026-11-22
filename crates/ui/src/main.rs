//! sysmon-ui: receives agent datagrams, records them, and shows them live, or
//! replays a recording.

mod app;
mod pipeline;

use std::net::SocketAddr;
use std::path::PathBuf;

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
    /// Replay a recording (a data dir, host dir, boot dir, or a single .seg file)
    /// instead of listening.
    #[arg(long)]
    replay: Option<PathBuf>,
    /// Replay speed multiplier.
    #[arg(long, default_value_t = 1.0)]
    speed: f64,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let (events, mode) = match &args.replay {
        Some(path) => (pipeline::start_replay(path, args.speed)?, app::Mode::Replay),
        None => {
            let data_dir =
                (!args.no_record).then(|| args.data_dir.clone().unwrap_or_else(default_data_dir));
            (
                pipeline::start_live(args.listen, opener(&args)?, data_dir)?,
                app::Mode::Live,
            )
        }
    };

    gpui_kit::application().run(move |cx| {
        gpui_kit::init(cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(px(1100.), px(750.)),
                cx,
            ))),
            ..Default::default()
        };
        gpui_kit::open_window(options, cx, |_, cx| {
            cx.new(|cx| app::AppState::new(events, mode, cx))
        })
        .expect("failed to open window");
        cx.activate(true);
    });
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
