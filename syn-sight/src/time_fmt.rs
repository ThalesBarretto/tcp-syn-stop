// SPDX-License-Identifier: GPL-2.0-only
/// Format a Unix timestamp to "YYYY-MM-DD HH:MM:SS" without chrono dependency.
pub(crate) fn format_unix_ts(ts: i64) -> String {
    if ts <= 0 {
        return String::from("-");
    }
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    let days = ts / 86400;
    let (y, m, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, hours, mins, secs)
}

/// Read `CLOCK_BOOTTIME` in nanoseconds (matches `bpf_ktime_get_ns()` on kernel ≥5.7).
pub(crate) fn clock_boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid pointer, CLOCK_BOOTTIME is a valid clock id.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if ret != 0 {
        return 0;
    }
    #[allow(clippy::cast_sign_loss)]
    {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    }
}

/// Format a BPF ktime timestamp as a human-readable "ago" string.
///
/// Returns "3s ago", "2m ago", "1h ago", or "-" if the timestamp is 0 or in the future.
pub(crate) fn format_ktime_ago(ts_ns: u64, now_ns: u64) -> String {
    if ts_ns == 0 || ts_ns > now_ns {
        return String::from("-");
    }
    let delta_s = (now_ns - ts_ns) / 1_000_000_000;
    if delta_s < 60 {
        format!("{}s ago", delta_s)
    } else if delta_s < 3600 {
        format!("{}m ago", delta_s / 60)
    } else {
        format!("{}h ago", delta_s / 3600)
    }
}

/// Civil calendar from days since 1970-01-01.
/// Implements Howard Hinnant's `civil_from_days` algorithm:
/// https://howardhinnant.github.io/date_algorithms.html#civil_from_days
fn days_to_ymd(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_format_unix_ts_negative() {
        assert_eq!(format_unix_ts(-1), "-");
    }

    #[test]
    fn test_format_unix_ts_zero() {
        assert_eq!(format_unix_ts(0), "-");
    }

    #[test]
    fn test_format_unix_ts_epoch() {
        assert_eq!(format_unix_ts(1), "1970-01-01 00:00:01");
    }

    #[test]
    fn test_format_unix_ts_known_date() {
        assert_eq!(format_unix_ts(1700000000), "2023-11-14 22:13:20");
    }

    #[test]
    fn test_format_unix_ts_leap_year() {
        // 2000-02-29 00:00:00 UTC = 951782400
        assert_eq!(format_unix_ts(951782400), "2000-02-29 00:00:00");
    }

    #[test]
    fn test_format_ktime_ago_zero() {
        assert_eq!(format_ktime_ago(0, 1_000_000_000), "-");
    }

    #[test]
    fn test_format_ktime_ago_future() {
        assert_eq!(format_ktime_ago(5_000_000_000, 1_000_000_000), "-");
    }

    #[test]
    fn test_format_ktime_ago_seconds() {
        let now = 10_000_000_000u64;
        let ts = now - 3_000_000_000; // 3 seconds ago
        assert_eq!(format_ktime_ago(ts, now), "3s ago");
    }

    #[test]
    fn test_format_ktime_ago_minutes() {
        let now = 200_000_000_000u64;
        let ts = now - 120_000_000_000; // 2 minutes ago
        assert_eq!(format_ktime_ago(ts, now), "2m ago");
    }

    #[test]
    fn test_format_ktime_ago_hours() {
        let now = 10_000_000_000_000u64;
        let ts = now - 3_600_000_000_000; // 1 hour ago
        assert_eq!(format_ktime_ago(ts, now), "1h ago");
    }

    #[test]
    fn test_clock_boottime_ns_nonzero() {
        // On a running Linux system, CLOCK_BOOTTIME should return > 0
        let ns = clock_boottime_ns();
        assert!(ns > 0);
    }
}
