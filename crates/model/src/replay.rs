//! A background thread that plays a [`ReplaySource`] in real time (scaled
//! by speed), controlled through a [`ReplayHandle`].

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sysmon_ingest::Event;

use crate::{PlaybackClock, ReplaySource};

/// After a seek, start reading this far before the target, delivering that
/// stretch at once. The models then have the samples they need for rates,
/// and the process graphs show their full window straight away instead of
/// filling up from empty.
pub const SEEK_LEAD_NS: u64 = crate::host::HISTORY_WINDOW_S * 1_000_000_000;
/// Longest the engine sleeps, so controls are handled promptly.
const MAX_SLEEP: Duration = Duration::from_millis(100);
/// Gaps in the recording longer than this are skipped instead of waited out.
const MAX_GAP_NS: u64 = 5_000_000_000;

/// What the UI receives from a replay.
#[derive(Debug, Clone)]
// Events are moved through a channel once each; boxing them buys nothing.
#[allow(clippy::large_enum_variant)]
pub enum Feed {
    Event(Event),
    /// The replay jumped: discard all state built so far.
    Reset,
}

#[derive(Debug, Clone, Copy)]
pub enum Control {
    SetPaused(bool),
    TogglePause,
    SetSpeed(f64),
    Seek(u64),
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ReplayStatus {
    pub start_ns: u64,
    pub end_ns: u64,
    pub position_ns: u64,
    pub speed: f64,
    pub paused: bool,
    pub finished: bool,
}

/// Owner's side of a running replay. Dropping it stops the thread.
pub struct ReplayHandle {
    pub feed: flume::Receiver<Feed>,
    control: flume::Sender<Control>,
    status: Arc<Mutex<ReplayStatus>>,
}

impl ReplayHandle {
    pub fn send(&self, c: Control) {
        let _ = self.control.send(c);
    }

    pub fn status(&self) -> ReplayStatus {
        *self.status.lock().unwrap()
    }
}

/// Start playing `source` from its beginning at `speed`.
pub fn spawn(source: ReplaySource, speed: f64) -> std::io::Result<ReplayHandle> {
    let (feed_tx, feed) = flume::bounded(4096);
    let (control, control_rx) = flume::unbounded();
    let (start, end) = source.time_range().unwrap_or((0, 0));
    let status = Arc::new(Mutex::new(ReplayStatus {
        start_ns: start,
        end_ns: end,
        position_ns: start,
        speed,
        paused: false,
        finished: false,
    }));

    let engine = Engine {
        source,
        clock: {
            let mut c = PlaybackClock::new(start, Instant::now());
            c.set_speed(speed, Instant::now());
            c
        },
        range: (start, end),
        feed: feed_tx,
        controls: control_rx,
        status: status.clone(),
        finished: false,
    };
    std::thread::Builder::new()
        .name("sysmon-replay".into())
        .spawn(move || engine.run())?;

    Ok(ReplayHandle {
        feed,
        control,
        status,
    })
}

struct Engine {
    source: ReplaySource,
    clock: PlaybackClock,
    range: (u64, u64),
    feed: flume::Sender<Feed>,
    controls: flume::Receiver<Control>,
    status: Arc<Mutex<ReplayStatus>>,
    finished: bool,
}

impl Engine {
    fn run(mut self) {
        loop {
            // Emit everything that is due.
            let now = Instant::now();
            let pos = self.clock.position(now);
            while let Some(ts) = self.source.peek_ts() {
                if ts > pos {
                    break;
                }
                self.source.step();
                if !self.forward() {
                    return;
                }
            }

            let next = self.source.peek_ts();
            if next.is_none() && !self.finished {
                self.source.finish();
                if !self.forward() {
                    return;
                }
                self.finished = true;
                // Stop the clock at the end so the position doesn't run away.
                self.clock.seek(self.range.1, now);
                self.clock.set_paused(true, now);
            }
            if let Some(ts) = next
                && ts.saturating_sub(pos) > MAX_GAP_NS
                && !self.clock.is_paused()
            {
                // Skip over a gap (agent or monitor offline) instead of waiting it out.
                self.clock.seek(ts, now);
            }
            self.publish(now);

            let wait = next
                .and_then(|ts| self.clock.wall_until(ts, now))
                .map_or(MAX_SLEEP, |d| d.min(MAX_SLEEP));
            match self.controls.recv_timeout(wait) {
                Ok(c) => self.apply(c),
                Err(flume::RecvTimeoutError::Timeout) => {}
                Err(flume::RecvTimeoutError::Disconnected) => return,
            }
            while let Ok(c) = self.controls.try_recv() {
                self.apply(c);
            }
        }
    }

    fn forward(&mut self) -> bool {
        let events: Vec<_> = self.source.take_events().collect();
        events
            .into_iter()
            .all(|e| self.feed.send(Feed::Event(e)).is_ok())
    }

    fn apply(&mut self, c: Control) {
        let now = Instant::now();
        match c {
            Control::SetPaused(p) => self.clock.set_paused(p, now),
            Control::TogglePause => {
                if self.finished && self.clock.is_paused() {
                    // Play again from the start.
                    self.seek(self.range.0, now);
                }
                let paused = self.clock.is_paused();
                self.clock.set_paused(!paused, now);
            }
            Control::SetSpeed(s) => self.clock.set_speed(s, now),
            Control::Seek(ts) => self.seek(ts, now),
        }
        self.publish(now);
    }

    fn seek(&mut self, ts: u64, now: Instant) {
        let ts = ts.clamp(self.range.0, self.range.1);
        self.source.seek_to(ts.saturating_sub(SEEK_LEAD_NS));
        self.clock.seek(ts, now);
        if self.finished {
            self.finished = false;
        }
        let _ = self.feed.send(Feed::Reset);
    }

    fn publish(&self, now: Instant) {
        let mut s = self.status.lock().unwrap();
        s.position_ns = self.clock.position(now).min(self.range.1);
        s.speed = self.clock.speed();
        s.paused = self.clock.is_paused();
        s.finished = self.finished;
    }
}
