//! Text formatting for the UI.

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

/// `HH:MM:SS` in UTC.
pub fn time_utc(ts_ns: u64) -> String {
    let s = ts_ns / 1_000_000_000 % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn datetime_utc(ts_ns: u64) -> String {
    let path = sysmon_store::segment_path(std::path::Path::new(""), 0, 0, ts_ns);
    let date = path
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.split('T').next())
        .unwrap_or_default()
        .to_string();
    format!("{date} {}", time_utc(ts_ns))
}

pub fn duration(ns: u64) -> String {
    let s = ns / 1_000_000_000;
    if s >= 3600 {
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
        let ts = 1_795_332_065u64 * 1_000_000_000;
        assert_eq!(datetime_utc(ts), "2026-11-22 07:21:05");
        assert_eq!(duration(3_725 * 1_000_000_000), "1h02m");
        assert_eq!(duration(65 * 1_000_000_000), "1m05s");
    }
}
