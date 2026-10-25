//! Numbers as the watcher shows them

pub fn rate(val: f64, suffix: &str) -> String {
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

pub fn sum(val: u64, suffix: &str) -> String {
    let val = val as f64;
    if val > 1_000_000_000.0 {
        format!("{:.2} G{}", val / 1_000_000_000.0, suffix)
    } else if val > 1_000_000.0 {
        format!("{:.2} M{}", val / 1_000_000.0, suffix)
    } else if val > 1_000.0 {
        format!("{:.2} K{}", val / 1_000.0, suffix)
    } else {
        format!("{:.0} {}", val, suffix)
    }
}
