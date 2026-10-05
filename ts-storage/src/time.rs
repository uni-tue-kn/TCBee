//! Timestamps for `meta.created_at`, without a date-time dependency.

use std::time::{SystemTime, UNIX_EPOCH};

/// `secs` since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ` (UTC, proleptic Gregorian).
pub fn iso8601(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The current time as [`iso8601`] (the epoch if the clock is before 1970).
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    iso8601(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_709_251_199), "2024-02-29T23:59:59Z");
        assert_eq!(iso8601(1_709_251_200), "2024-03-01T00:00:00Z");
        assert_eq!(iso8601(1_790_000_000), "2026-09-21T14:13:20Z");
        assert_eq!(iso8601(1_791_158_400), "2026-10-05T00:00:00Z");
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn now_has_the_format() {
        let n = now_iso8601();
        assert_eq!(n.len(), 20);
        assert!(n.starts_with("20") && n.ends_with('Z') && n.as_bytes()[10] == b'T');
    }
}
