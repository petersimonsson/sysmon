//! sysmon-ui: receives agent datagrams, records them, and shows them live, or
//! replays a recording.

mod about;
mod actions;
mod app;
mod config;
mod format;
mod graph;
mod icons;
mod keymap;
mod notices;
mod pipeline;
mod recordings;
mod selection;
mod shortcuts;
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
    #[arg(long, value_name = "GIB", value_parser = parse_gib)]
    max_gib: Option<f64>,
    /// Open a recording (a data dir, host dir, boot dir, or a single .seg
    /// file) instead of listening for agents.
    #[arg(long)]
    replay: Option<PathBuf>,
    /// Replay speed multiplier.
    #[arg(long, default_value_t = 1.0, value_parser = parse_speed)]
    speed: f64,
    /// Settings file. Defaults to `$XDG_CONFIG_HOME/sysmon/config.toml`.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Print sysmon's license and the license notices of all third-party
    /// software in this binary, then exit.
    #[arg(long)]
    licenses: bool,
    /// Print the keyboard shortcuts in effect as a `[keys]` table for the
    /// settings file, then exit.
    #[arg(long)]
    print_keys: bool,
}

/// Wayland app ID / X11 WM_CLASS; matches `dist/sysmon.desktop`, so
/// desktops can group the window with its entry and icon.
const APP_ID: &str = "sysmon";

/// gpui leaves the title and app ID empty, which shows as an untitled
/// window in task switchers.
fn window_options(bounds: Bounds<Pixels>) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        titlebar: Some(TitlebarOptions {
            title: Some("sysmon".into()),
            ..Default::default()
        }),
        app_id: Some(APP_ID.into()),
        ..Default::default()
    }
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
    let config_path = args.config.clone().unwrap_or_else(config::default_path);
    let (mut config, writable) = config::load(&config_path);
    // The keys in effect: the defaults with the file's [keys] over them.
    let (keymap, key_problems) = keymap::Keymap::resolve(&config.keys);
    for p in &key_problems {
        tracing::warn!(path = %config_path.display(), "{p}");
    }
    if args.print_keys {
        print!("{}", keymap.to_toml());
        return Ok(());
    }
    config.problems.extend(key_problems);
    let mut start = match &args.replay {
        Some(path) => app::Start {
            live: None,
            replay: Some((pipeline::open_replay(path, args.speed)?, path.clone())),
            recording_to: None,
            data_dir: data_dir.clone(),
            config: Default::default(),
            config_path: None,
        },
        None => {
            let recording = (!args.no_record).then(|| pipeline::Recording {
                dir: data_dir.clone(),
                retention: sysmon_store::Retention {
                    max_age: args
                        .keep_hours
                        .map(|h| Duration::from_secs(h.saturating_mul(3600))),
                    max_bytes: args.max_gib.map(|g| (g * (1u64 << 30) as f64) as u64),
                },
            });
            let (live, recorder) = pipeline::start_live(args.listen, opener(&args)?, recording)?;
            if let Some(r) = &recorder {
                stop_recording_on_signals(r.clone())?;
            }
            let recording_to = recorder.is_some().then(|| data_dir.clone());
            stopper = recorder;
            app::Start {
                live: Some(live),
                replay: None,
                recording_to,
                data_dir,
                config: Default::default(),
                config_path: None,
            }
        }
    };
    start.config = config;
    // A file that couldn't be read is left alone; changes last the session.
    start.config_path = writable.then_some(config_path);

    gpui_kit::application()
        .with_assets(icons::AppAssets)
        .run(move |cx| {
            gpui_kit::init(cx);
            actions::init(cx, keymap);
            // Ctrl+Q, File → Quit and closing the window all end up here.
            if let Some(r) = stopper.clone() {
                cx.on_app_quit(move |_| {
                    r.stop(STOP_TIMEOUT);
                    async {}
                })
                .detach();
            }
            let options = window_options(Bounds::centered(None, size(px(1200.), px(800.)), cx));
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

/// A size limit in GiB: a positive number. Anything else (a negative or
/// NaN typo, or one too small for a byte) would become a limit of 0 bytes,
/// and pruning would delete every recording.
fn parse_gib(s: &str) -> Result<f64, String> {
    let gib: f64 = s.parse().map_err(|e| format!("{e}"))?;
    if !gib.is_finite() || gib * ((1u64 << 30) as f64) < 1.0 {
        return Err(format!("{s} isn't a positive size in GiB"));
    }
    Ok(gib)
}

/// A replay speed: a positive number (the player would quietly use 1×
/// for anything else).
fn parse_speed(s: &str) -> Result<f64, String> {
    let speed: f64 = s.parse().map_err(|e| format!("{e}"))?;
    if !speed.is_finite() || speed <= 0.0 {
        return Err(format!("{s} isn't a positive speed"));
    }
    Ok(speed)
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

#[cfg(test)]
mod window_tests {
    use super::*;

    #[core::prelude::v1::test]
    fn the_window_has_a_title_and_app_id() {
        let o = window_options(Bounds::default());
        assert_eq!(
            o.titlebar
                .and_then(|t| t.title)
                .as_ref()
                .map(|t| t.as_ref()),
            Some("sysmon")
        );
        assert_eq!(o.app_id.as_deref(), Some(APP_ID));
    }

    #[core::prelude::v1::test]
    fn speed_must_be_positive() {
        let parse = |v: &str| Args::try_parse_from(["sysmon-ui", "--speed", v]);
        for bad in ["0", "-2", "nan", "inf", "fast"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(parse("0.5").unwrap().speed, 0.5);
        assert_eq!(Args::try_parse_from(["sysmon-ui"]).unwrap().speed, 1.0);
    }

    #[core::prelude::v1::test]
    fn max_gib_must_be_a_positive_size() {
        let parse = |v: &str| Args::try_parse_from(["sysmon-ui", "--max-gib", v]);
        for bad in ["-5", "0", "nan", "inf", "1e-12", "lots"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(parse("0.5").unwrap().max_gib, Some(0.5));
        assert_eq!(parse("20").unwrap().max_gib, Some(20.0));
    }
}
