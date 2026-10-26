//! Numbers as the watcher shows them: decimal prefixes, three significant digits

use std::time::Duration;

const PREFIXES: [&str; 5] = ["", "K", "M", "G", "T"];

/// `val` scaled to a decimal prefix, with three significant digits
fn scaled(val: f64) -> (String, &'static str) {
    let mut val = val.max(0.0);
    let mut prefix = 0;
    // 999.7 would round to "1000", so it moves on to the next prefix as well
    while val >= 999.5 && prefix + 1 < PREFIXES.len() {
        val /= 1000.0;
        prefix += 1;
    }
    let number = if prefix == 0 && val.fract() == 0.0 {
        format!("{val:.0}")
    } else if val < 9.995 {
        format!("{val:.2}")
    } else if val < 99.95 {
        format!("{val:.1}")
    } else {
        format!("{val:.0}")
    };
    (number, PREFIXES[prefix])
}

/// A count or rate in a narrow column or an axis label: "0", "999", "1.20K", "812K"
pub fn si(val: f64) -> String {
    let (number, prefix) = scaled(val);
    format!("{number}{prefix}")
}
/// Bytes with a decimal prefix: "1.90 GB"
pub fn bytes(val: f64) -> String {
    let (number, prefix) = scaled(val);
    format!("{number} {prefix}B")
}

/// Elapsed time as hh:mm:ss
pub fn clock(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

/// A time axis label: "42s", "12:05", "1:02:03"
pub fn axis_time(secs: f64) -> String {
    let secs = secs.max(0.0).round() as u64;
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}:{:02}", secs / 60, secs % 60),
        _ => format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60),
    }
}

/// Bars of a text sparkline, from the lowest to the highest
const BARS: [char; 8] = [
    '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}',
];

/// The last `width` values as a text sparkline, scaled to their maximum
pub fn spark(values: &[f64], width: usize) -> String {
    let shown = &values[values.len().saturating_sub(width)..];
    let max = shown.iter().copied().fold(0.0, f64::max);
    shown
        .iter()
        .map(|value| {
            let level = if max > 0.0 { value / max * 7.0 } else { 0.0 };
            BARS[(level as usize).min(7)]
        })
        .collect()
}

/// The last `width` values as a text sparkline on a fixed scale up to `max`: the lowest bar
/// for nothing, any more at least the second, `max` and more the highest
pub fn spark_fixed(values: &[u64], max: u64, width: usize) -> String {
    let shown = values.iter().skip(values.len().saturating_sub(width));
    shown
        .map(|value| match value {
            0 => BARS[0],
            value => BARS[(1 + value * 6 / max.max(1)).min(7) as usize],
        })
        .collect()
}

/// A rate in the status line of -q: "1.50 KEvents/s". Unchanged from earlier releases for
/// scripts that read it, so a prefix starts above 1000, not at it.
pub fn quiet_rate(val: f64, suffix: &str) -> String {
    if val > 1_000_000_000.0 {
        format!("{:.2} G{}", val / 1_000_000_000.0, suffix)
    } else if val > 1_000_000.0 {
        format!("{:.2} M{}", val / 1_000_000.0, suffix)
    } else if val > 1_000.0 {
        format!("{:.2} K{}", val / 1_000.0, suffix)
    } else {
        format!("{:.2} {}", val, suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_switch_at_a_thousand() {
        assert_eq!(si(0.0), "0");
        assert_eq!(si(999.0), "999");
        assert_eq!(si(1000.0), "1.00K");
        assert_eq!(si(999.7), "1.00K");
        assert_eq!(si(0.5), "0.50");
        assert_eq!(si(12_345.0), "12.3K");
        assert_eq!(si(812_400.0), "812K");
        assert_eq!(si(151_000_000.0), "151M");
        assert_eq!(si(-3.0), "0");
        assert_eq!(bytes(1_900_000_000.0), "1.90 GB");
        assert_eq!(bytes(512.0), "512 B");
        assert_eq!(quiet_rate(1000.0, "pps"), "1000.00 pps");
        assert_eq!(quiet_rate(1500.0, "pps"), "1.50 Kpps");
        assert_eq!(quiet_rate(999.0, "pps"), "999.00 pps");
    }

    #[test]
    fn times_read_as_clocks() {
        assert_eq!(clock(Duration::from_millis(45_296_900)), "12:34:56");
        assert_eq!(clock(Duration::from_secs(59)), "00:00:59");
        assert_eq!(axis_time(42.4), "42s");
        assert_eq!(axis_time(725.0), "12:05");
        assert_eq!(axis_time(3723.0), "1:02:03");
    }

    #[test]
    fn sparklines_scale_to_their_maximum() {
        assert_eq!(
            spark(&[0.0, 1.0, 2.0, 4.0, 8.0], 4),
            "\u{2581}\u{2582}\u{2584}\u{2588}"
        );
        assert_eq!(spark(&[0.0, 0.0], 8), "\u{2581}\u{2581}");
        assert_eq!(spark(&[], 8), "");
        assert_eq!(
            spark_fixed(&[9, 0, 1, 50, 100, 300], 100, 5),
            "\u{2581}\u{2582}\u{2585}\u{2588}\u{2588}"
        );
    }
}
