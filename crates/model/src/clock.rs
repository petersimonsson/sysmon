use std::time::{Duration, Instant};

/// Maps wall-clock time onto recording time, with speed, pause and seek.
///
/// Recording time is the monitor's receive timestamp in nanoseconds since the
/// Unix epoch, which is consistent across hosts.
#[derive(Debug, Clone)]
pub struct PlaybackClock {
    base_rec_ns: u64,
    base_wall: Instant,
    speed: f64,
    paused: bool,
}

impl PlaybackClock {
    pub fn new(start_ns: u64, now: Instant) -> Self {
        Self {
            base_rec_ns: start_ns,
            base_wall: now,
            speed: 1.0,
            paused: false,
        }
    }

    /// Current recording time.
    pub fn position(&self, now: Instant) -> u64 {
        if self.paused {
            return self.base_rec_ns;
        }
        let elapsed = now.saturating_duration_since(self.base_wall).as_secs_f64();
        self.base_rec_ns
            .saturating_add((elapsed * self.speed * 1e9) as u64)
    }

    /// Wall-clock time until the recording reaches `ts`, or `None` if paused.
    pub fn wall_until(&self, ts: u64, now: Instant) -> Option<Duration> {
        if self.paused {
            return None;
        }
        let ahead = ts.saturating_sub(self.position(now)) as f64 / self.speed;
        Some(Duration::from_nanos(ahead as u64))
    }

    pub fn speed(&self) -> f64 {
        self.speed
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn set_speed(&mut self, speed: f64, now: Instant) {
        self.rebase(now);
        self.speed = if speed.is_finite() && speed > 0.0 {
            speed
        } else {
            1.0
        };
    }

    pub fn set_paused(&mut self, paused: bool, now: Instant) {
        self.rebase(now);
        self.paused = paused;
    }

    pub fn seek(&mut self, ts: u64, now: Instant) {
        self.base_rec_ns = ts;
        self.base_wall = now;
    }

    fn rebase(&mut self, now: Instant) {
        self.base_rec_ns = self.position(now);
        self.base_wall = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn speed_pause_and_seek() {
        let t0 = Instant::now();
        let at = |s: f64| t0 + Duration::from_secs_f64(s);
        let mut c = PlaybackClock::new(100 * SEC, t0);
        assert_eq!(c.position(at(2.0)), 102 * SEC);

        c.set_speed(4.0, at(2.0));
        assert_eq!(c.position(at(3.0)), 106 * SEC);
        assert_eq!(
            c.wall_until(110 * SEC, at(3.0)),
            Some(Duration::from_secs(1))
        );

        c.set_paused(true, at(3.0));
        assert_eq!(c.position(at(60.0)), 106 * SEC);
        assert_eq!(c.wall_until(110 * SEC, at(60.0)), None);

        c.set_paused(false, at(60.0));
        c.seek(500 * SEC, at(60.0));
        assert_eq!(c.position(at(61.0)), 504 * SEC);
    }
}
