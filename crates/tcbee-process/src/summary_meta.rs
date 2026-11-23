//! The `summary.*` rows of the meta table: what a database holds at a glance.
//!
//! All values are decimal integers or UTC timestamps, units are in the key names. Times in
//! `_ns` keys are CLOCK_MONOTONIC nanoseconds, the clock of the records. The `_utc` keys need
//! the recorder's clock samples (`run.*`, `tcbee-record --metadata`) and are left out without
//! them. Every value only depends on the trace, so the rows are the same for every run.

use ts_storage::{time::iso8601, Catalog, SeriesKind};

use crate::pipeline::Summary;

/// Prefix of the summary keys
const PREFIX: &str = "summary";

/// The summary rows of a finished catalog. Call it once the catalog is complete (flows,
/// connections, owners, series and the `run.*` rows).
pub fn rows(catalog: &Catalog, summary: &Summary) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    let mut push = |key: &str, value: String| rows.push((format!("{PREFIX}.{key}"), value));

    push("events", summary.rows.to_string());
    for (table, n) in &summary.rows_by_table {
        push(&format!("events_by_table.{table}"), n.to_string());
    }
    push("records", summary.records.to_string());
    push("discarded", summary.discarded.to_string());
    push("flows", catalog.flows.len().to_string());
    push("connections", catalog.connections.len().to_string());
    push("owners", catalog.owners.len().to_string());
    push("series", catalog.series.len().to_string());

    let run = |key: &str| -> Option<i64> {
        let key = format!("{}.{key}", crate::metadata::PREFIX);
        catalog
            .meta
            .iter()
            .find(|(k, _)| *k == key)
            .and_then(|(_, v)| v.parse().ok())
    };
    let start_offset = run("start.clock.realtime_minus_monotonic_ns");

    if let Some((first, last)) = event_span(catalog) {
        push("span.first_ns", first.to_string());
        push("span.last_ns", last.to_string());
        push("span.duration_ns", (last - first).to_string());
        // One offset for both: it drifts by microseconds over a recording (NTP slew), less
        // than the uncertainty of the sample
        if let Some(offset) = start_offset {
            push_utc(&mut push, "span.first_utc", first, offset);
            push_utc(&mut push, "span.last_utc", last, offset);
        }
    }

    let start = run("start.clock.monotonic_ns").zip(start_offset);
    let stop = run("stop.clock.monotonic_ns").zip(run("stop.clock.realtime_minus_monotonic_ns"));
    if let Some((mono, offset)) = start {
        push_utc(&mut push, "recorder.start_utc", mono, offset);
    }
    if let Some((mono, offset)) = stop {
        push_utc(&mut push, "recorder.stop_utc", mono, offset);
    }
    if let (Some((start, _)), Some((stop, _))) = (start, stop) {
        // A broken metadata file can have any values; leave out what makes no sense
        if let Some(duration) = stop.checked_sub(start).filter(|d| *d >= 0) {
            push("recorder.duration_ns", duration.to_string());
        }
    }
    rows
}

/// The UTC row of a monotonic time, none if the sum overflows (broken metadata)
fn push_utc(push: &mut impl FnMut(&str, String), key: &str, monotonic: i64, offset: i64) {
    if let Some(ns) = monotonic.checked_add(offset) {
        push(key, utc(ns));
    }
}

/// First and last event time over the recorded series, None without events
fn event_span(catalog: &Catalog) -> Option<(i64, i64)> {
    let raw = catalog.series.iter().filter(|s| s.kind == SeriesKind::Raw);
    let first = raw.clone().filter_map(|s| s.t_min).min()?;
    let last = raw.filter_map(|s| s.t_max).max()?;
    Some((first, last))
}

/// Nanoseconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`
fn utc(ns: i64) -> String {
    let secs = iso8601(ns.div_euclid(1_000_000_000));
    let frac = ns.rem_euclid(1_000_000_000);
    format!("{}.{frac:09}Z", secs.trim_end_matches('Z'))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ts_storage::{ColType, Dir, SeriesInfo};

    use super::*;

    fn series(kind: SeriesKind, t: Option<(i64, i64)>) -> SeriesInfo {
        SeriesInfo {
            id: 0,
            flow_id: 1,
            kind,
            source: "tcp4".into(),
            dir: Dir::Send,
            name: "cwnd".into(),
            value_type: ColType::U32,
            tbl: None,
            col: None,
            n: i64::from(t.is_some()),
            t_min: t.map(|t| t.0),
            t_max: t.map(|t| t.1),
            v_min: None,
            v_max: None,
        }
    }

    fn map(catalog: &Catalog, summary: &Summary) -> BTreeMap<String, String> {
        rows(catalog, summary).into_iter().collect()
    }

    #[test]
    fn empty_catalog_has_counts_but_no_span() {
        let m = map(&Catalog::default(), &Summary::default());
        assert_eq!(m["summary.events"], "0");
        assert_eq!(m["summary.flows"], "0");
        assert!(!m
            .keys()
            .any(|k| k.contains(".span.") || k.contains("recorder")));
    }

    #[test]
    fn span_covers_raw_series_only() {
        let catalog = Catalog {
            series: vec![
                series(SeriesKind::Raw, Some((200, 500))),
                series(SeriesKind::Raw, Some((100, 300))),
                series(SeriesKind::Raw, None),
                series(SeriesKind::Derived, Some((1, 9_000))),
            ],
            ..Catalog::default()
        };
        let m = map(&catalog, &Summary::default());
        assert_eq!(m["summary.span.first_ns"], "100");
        assert_eq!(m["summary.span.last_ns"], "500");
        assert_eq!(m["summary.span.duration_ns"], "400");
        assert_eq!(m["summary.series"], "4");
        assert!(!m.contains_key("summary.span.first_utc"));
    }

    #[test]
    fn counts_per_table() {
        let summary = Summary {
            records: 7,
            rows: 6,
            discarded: 1,
            rows_by_table: [("sock", 4), ("tcp4", 2)].into_iter().collect(),
            ..Summary::default()
        };
        let m = map(&Catalog::default(), &summary);
        assert_eq!(m["summary.events"], "6");
        assert_eq!(m["summary.events_by_table.sock"], "4");
        assert_eq!(m["summary.events_by_table.tcp4"], "2");
        assert_eq!(m["summary.records"], "7");
        assert_eq!(m["summary.discarded"], "1");
    }

    #[test]
    fn wall_clock_from_the_recorder_clock_samples() {
        let offset = 1_790_000_000_000_000_000_i64;
        let meta = [
            ("run.start.clock.monotonic_ns", 50),
            ("run.start.clock.realtime_minus_monotonic_ns", offset),
            ("run.stop.clock.monotonic_ns", 2_000_000_050),
            ("run.stop.clock.realtime_minus_monotonic_ns", offset + 7),
        ];
        let catalog = Catalog {
            series: vec![series(SeriesKind::Raw, Some((100, 1_500_000_100)))],
            meta: meta
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Catalog::default()
        };
        let m = map(&catalog, &Summary::default());
        assert_eq!(
            m["summary.span.first_utc"],
            "2026-09-21T14:13:20.000000100Z"
        );
        assert_eq!(m["summary.span.last_utc"], "2026-09-21T14:13:21.500000100Z");
        assert_eq!(
            m["summary.recorder.start_utc"],
            "2026-09-21T14:13:20.000000050Z"
        );
        assert_eq!(
            m["summary.recorder.stop_utc"],
            "2026-09-21T14:13:22.000000057Z"
        );
        assert_eq!(m["summary.recorder.duration_ns"], "2000000000");
    }

    #[test]
    fn stop_missing_gives_start_only() {
        let catalog = Catalog {
            meta: vec![
                ("run.start.clock.monotonic_ns".into(), "0".into()),
                (
                    "run.start.clock.realtime_minus_monotonic_ns".into(),
                    "0".into(),
                ),
            ],
            ..Catalog::default()
        };
        let m = map(&catalog, &Summary::default());
        assert_eq!(
            m["summary.recorder.start_utc"],
            "1970-01-01T00:00:00.000000000Z"
        );
        assert!(!m.contains_key("summary.recorder.stop_utc"));
        assert!(!m.contains_key("summary.recorder.duration_ns"));
    }

    #[test]
    fn broken_clock_samples_give_no_wall_clock_rows() {
        let catalog = Catalog {
            series: vec![series(SeriesKind::Raw, Some((100, 200)))],
            meta: vec![
                ("run.start.clock.monotonic_ns".into(), "500".into()),
                (
                    "run.start.clock.realtime_minus_monotonic_ns".into(),
                    i64::MAX.to_string(),
                ),
                ("run.stop.clock.monotonic_ns".into(), "400".into()),
                (
                    "run.stop.clock.realtime_minus_monotonic_ns".into(),
                    "0".into(),
                ),
            ],
            ..Catalog::default()
        };
        let m = map(&catalog, &Summary::default());
        assert_eq!(m["summary.span.first_ns"], "100");
        assert!(!m.contains_key("summary.span.first_utc"));
        assert!(!m.contains_key("summary.recorder.start_utc"));
        // Stop before start
        assert!(m.contains_key("summary.recorder.stop_utc"));
        assert!(!m.contains_key("summary.recorder.duration_ns"));
    }

    #[test]
    fn utc_before_the_epoch() {
        assert_eq!(utc(-1), "1969-12-31T23:59:59.999999999Z");
    }
}
