//! Missing events of a raw series, found from `hook_seq` (the `seq` column).
//!
//! The recorder numbers the events of one hook counter 1, 2, 3, ... and a dropped event leaves a
//! hole. One counter feeds exactly one `(table, flow_id, dir)`, so the gaps of a series are the
//! jumps of `seq` within its rows, ordered by `seq` (not by `ts`, which can go back across CPUs).
//! A run recorded without hook_seq stores 0 everywhere; its gaps are unknown.
//! Losses after the last recorded event cannot be seen.

/// Events missing between two recorded events of a series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// Timestamps (ns) of the recorded events around the gap, `start_ns <= end_ns`. For events
    /// missing before the first recorded one, both are the timestamp of that event.
    pub start_ns: i64,
    pub end_ns: i64,
    /// `seq` of the first missing event
    pub first_seq: i64,
    /// Number of missing events
    pub missing: i64,
}

/// The gaps of a series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gaps {
    /// The series has no hook_seq: derived series, or recorded with `--no-hook-seq`.
    Unavailable,
    /// The gaps, ordered by `seq`; empty if no event is missing between recorded ones.
    Known(Vec<Gap>),
}

/// A row of [`crate::sql::seq_gaps_query`]: `(seq, ts, prev_seq, prev_ts)`.
pub(crate) type GapRow = (i64, i64, Option<i64>, Option<i64>);

/// Builds the gaps from the query rows and keeps those that overlap `range` (inclusive, ns).
pub(crate) fn from_rows(rows: impl IntoIterator<Item = GapRow>, range: Option<(f64, f64)>) -> Gaps {
    let mut gaps = Vec::new();
    for (seq, ts, prev_seq, prev_ts) in rows {
        let gap = match prev_seq.zip(prev_ts) {
            // The first row holds the lowest seq.
            None if seq == 0 => return Gaps::Unavailable,
            None if seq > 1 => Gap {
                start_ns: ts,
                end_ns: ts,
                first_seq: 1,
                missing: seq - 1,
            },
            None => continue,
            Some((prev_seq, prev_ts)) => Gap {
                start_ns: prev_ts.min(ts),
                end_ns: prev_ts.max(ts),
                first_seq: prev_seq + 1,
                missing: seq - prev_seq - 1,
            },
        };
        let inside = match range {
            Some((lo, hi)) => gap.end_ns as f64 >= lo && gap.start_ns as f64 <= hi,
            None => true,
        };
        if inside {
            gaps.push(gap);
        }
    }
    Gaps::Known(gaps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gap(start_ns: i64, end_ns: i64, first_seq: i64, missing: i64) -> Gap {
        Gap {
            start_ns,
            end_ns,
            first_seq,
            missing,
        }
    }

    #[test]
    fn leading_and_inner_gaps() {
        let rows = [(3, 100, None, None), (7, 90, Some(4), Some(120))];
        assert_eq!(
            from_rows(rows, None),
            Gaps::Known(vec![gap(100, 100, 1, 2), gap(90, 120, 5, 2)])
        );
    }

    #[test]
    fn zero_seq_is_unavailable() {
        assert_eq!(from_rows([(0, 5, None, None)], None), Gaps::Unavailable);
    }

    #[test]
    fn no_rows_and_no_gaps() {
        assert_eq!(from_rows([], None), Gaps::Known(vec![]));
        assert_eq!(from_rows([(1, 5, None, None)], None), Gaps::Known(vec![]));
    }

    #[test]
    fn range_keeps_overlapping_gaps() {
        let rows = [(1, 0, None, None), (5, 20, Some(2), Some(10))];
        assert_eq!(from_rows(rows, Some((21.0, 30.0))), Gaps::Known(vec![]));
        assert_eq!(
            from_rows(rows, Some((20.0, 30.0))),
            Gaps::Known(vec![gap(10, 20, 3, 2)])
        );
    }
}
