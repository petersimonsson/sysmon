//! Text formatting for the UI.

use jiff::tz::TimeZone;
use jiff::{Timestamp, ZonedDateTime};

pub fn bytes_per_s(v: f64) -> String {
    format!("{}/s", bytes(v))
}

pub fn bytes(v: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = v.max(0.0);
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{v:.0} {}", UNITS[unit])
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

/// A receive or sample timestamp in the system time zone (`TZ`, or
/// `/etc/localtime`). The offset is worked out for that moment, so DST
/// changes within a recording are right.
fn local(ts_ns: u64) -> ZonedDateTime {
    in_zone(ts_ns, TimeZone::system())
}

fn in_zone(ts_ns: u64, tz: TimeZone) -> ZonedDateTime {
    Timestamp::from_nanosecond(ts_ns as i128)
        .unwrap_or(Timestamp::UNIX_EPOCH)
        .to_zoned_datetime(tz)
}

/// `HH:MM:SS` in local time.
pub fn time(ts_ns: u64) -> String {
    local(ts_ns).strftime("%H:%M:%S").to_string()
}

/// `YYYY-MM-DD` in local time.
pub fn day(ts_ns: u64) -> String {
    local(ts_ns).strftime("%Y-%m-%d").to_string()
}

/// `MM-DD HH:MM:SS` in local time.
pub fn day_time(ts_ns: u64) -> String {
    local(ts_ns).strftime("%m-%d %H:%M:%S").to_string()
}

/// `YYYY-MM-DD HH:MM:SS` in local time.
pub fn datetime(ts_ns: u64) -> String {
    local(ts_ns).strftime("%Y-%m-%d %H:%M:%S").to_string()
}

/// A stretch of time in local time, to the minute, leaving out the end's
/// date when it's the same day: `2026-11-23 14:02 → 18:40`, or
/// `2026-11-23 14:02 → 11-24 09:15`.
pub fn span(start_ns: u64, end_ns: u64) -> String {
    span_in(start_ns, end_ns, TimeZone::system())
}

fn span_in(start_ns: u64, end_ns: u64, tz: TimeZone) -> String {
    let (a, b) = (in_zone(start_ns, tz.clone()), in_zone(end_ns, tz));
    let end = if a.date() == b.date() {
        b.strftime("%H:%M")
    } else if a.year() == b.year() {
        b.strftime("%m-%d %H:%M")
    } else {
        b.strftime("%Y-%m-%d %H:%M")
    };
    format!("{} → {end}", a.strftime("%Y-%m-%d %H:%M"))
}

/// The local zone's offset at that moment, e.g. `UTC+01:00`.
pub fn utc_offset(ts_ns: u64) -> String {
    offset_label(&local(ts_ns))
}

fn offset_label(t: &ZonedDateTime) -> String {
    format!("UTC{}", t.strftime("%:z"))
}

/// Shorten `s` to at most `max` characters by replacing its middle with
/// `…`, keeping both ends. Used for user names, where many share a prefix
/// (`systemd-resolve`, `systemd-timesync`) and the end tells them apart.
pub fn fit(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    if max <= 1 {
        return "…".into();
    }
    let keep = max - 1;
    let head = keep.div_ceil(2);
    let tail = keep / 2;
    let start: String = s.chars().take(head).collect();
    let end: String = s.chars().skip(n - tail).collect();
    format!("{start}…{end}")
}

pub fn duration(ns: u64) -> String {
    let s = ns / 1_000_000_000;
    if s >= 86_400 {
        // "75h36m" made you divide by 24.
        format!("{}d{:02}h", s / 86_400, s / 3600 % 24)
    } else if s >= 3600 {
        format!("{}h{:02}m", s / 3600, s / 60 % 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(bytes(512.0), "512 B");
        assert_eq!(bytes(1536.0), "1.5 KiB");
        assert_eq!(bytes_per_s(3.0 * 1024.0 * 1024.0), "3.0 MiB/s");
        assert_eq!(duration(3_725 * 1_000_000_000), "1h02m");
        assert_eq!(duration(65 * 1_000_000_000), "1m05s");
        assert_eq!(
            duration((3 * 86_400 + 3 * 3600 + 36 * 60) * 1_000_000_000),
            "3d03h"
        );
    }

    fn fmt(ts_ns: u64, tz: TimeZone) -> (String, String) {
        let t = in_zone(ts_ns, tz);
        (
            t.strftime("%Y-%m-%d %H:%M:%S").to_string(),
            offset_label(&t),
        )
    }

    fn fixed(offset_s: i32) -> TimeZone {
        TimeZone::fixed(jiff::tz::Offset::from_seconds(offset_s).unwrap())
    }

    #[test]
    fn spans_leave_out_what_the_start_says() {
        let utc = || fixed(0);
        let t = 1_795_332_065u64 * 1_000_000_000; // 2026-11-22T07:21:05Z
        let h = 3600 * 1_000_000_000;
        assert_eq!(span_in(t, t + 2 * h, utc()), "2026-11-22 07:21 → 09:21");
        assert_eq!(
            span_in(t, t + 20 * h, utc()),
            "2026-11-22 07:21 → 11-23 03:21"
        );
        assert_eq!(
            span_in(t, t + 60 * 24 * h, utc()),
            "2026-11-22 07:21 → 2027-01-21 07:21"
        );
    }

    #[test]
    fn fit_keeps_both_ends() {
        assert_eq!(fit("root", 16), "root");
        assert_eq!(fit("systemd-timesync", 16), "systemd-timesync");
        assert_eq!(fit("systemd-journal-remote", 16), "systemd-…-remote");
        assert_eq!(fit("systemd-resolve", 12), "system…solve");
        assert_eq!(fit("systemd-timesync", 12), "system…esync");
        assert_eq!(fit("anna.lindström@corp.example", 9), "anna…mple");
        assert_eq!(fit("abc", 1), "…");
        for n in 2..20 {
            assert!(fit("first.last@corp.example.com", n).chars().count() <= n);
        }
    }

    #[test]
    fn times_follow_the_zone() {
        // 2026-11-22T07:21:05Z
        let ts = 1_795_332_065u64 * 1_000_000_000;
        assert_eq!(
            fmt(ts, fixed(0)),
            ("2026-11-22 07:21:05".into(), "UTC+00:00".into())
        );
        assert_eq!(
            fmt(ts, fixed(3600)),
            ("2026-11-22 08:21:05".into(), "UTC+01:00".into())
        );
        // Across midnight, and a half-hour zone.
        assert_eq!(fmt(ts, fixed(-8 * 3600)).0, "2026-11-21 23:21:05");
        assert_eq!(fmt(ts, fixed(5 * 3600 + 1800)).0, "2026-11-22 12:51:05");
        // The public helpers use the system zone.
        assert_eq!(datetime(ts), fmt(ts, TimeZone::system()).0);
    }

    #[test]
    fn dst_is_applied_per_timestamp() {
        // Needs the system tz database; skip where there isn't one.
        let Ok(stockholm) = TimeZone::get("Europe/Stockholm") else {
            eprintln!("no tz database; skipping");
            return;
        };
        let winter = 1_795_332_065u64 * 1_000_000_000; // 2026-11-22T07:21:05Z
        let summer = 1_782_907_200u64 * 1_000_000_000; // 2026-07-01T12:00:00Z
        assert_eq!(
            fmt(winter, stockholm.clone()),
            ("2026-11-22 08:21:05".into(), "UTC+01:00".into())
        );
        assert_eq!(
            fmt(summer, stockholm),
            ("2026-07-01 14:00:00".into(), "UTC+02:00".into())
        );
    }
}
