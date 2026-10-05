//! Catalog types and the statistics accumulator that fills the `series` table during ingest.

use std::collections::BTreeMap;

use std::collections::btree_map::Entry;
use std::ops::Range;

use super::batch::{ColumnData, EventBatch};
use super::error::StoreError;
use super::schema::{ColType, Dir, EventTable, SeriesKind};
use crate::Flow;

/// One row of the `series` table.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesInfo {
    pub id: i64,
    pub flow_id: i64,
    pub kind: SeriesKind,
    pub source: String,
    pub dir: Dir,
    pub name: String,
    pub value_type: ColType,
    pub tbl: Option<String>,
    pub col: Option<String>,
    pub n: i64,
    pub t_min: Option<i64>,
    pub t_max: Option<i64>,
    pub v_min: Option<f64>,
    pub v_max: Option<f64>,
}

/// Everything `IngestSession::finish` writes besides the event tables.
/// `meta` holds caller entries (writer, trace_dir); ts-storage adds schema_version and created_at.
#[derive(Debug)]
pub struct Catalog {
    pub flows: Vec<Flow>,
    pub series: Vec<SeriesInfo>,
    pub meta: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ColStats {
    v_min: Option<f64>,
    v_max: Option<f64>,
}

impl ColStats {
    fn observe(&mut self, v: f64) {
        if v.is_nan() {
            return;
        }
        self.v_min = Some(self.v_min.map_or(v, |m| m.min(v)));
        self.v_max = Some(self.v_max.map_or(v, |m| m.max(v)));
    }

    /// Folds another accumulator in. Observing its minimum and its maximum as two values
    /// gives the combined minimum and maximum.
    fn merge(&mut self, o: &ColStats) {
        if let Some(v) = o.v_min {
            self.observe(v);
        }
        if let Some(v) = o.v_max {
            self.observe(v);
        }
    }

    fn observe_column(&mut self, data: &ColumnData, rows: Range<usize>) {
        match data {
            ColumnData::Bool(v) => v[rows]
                .iter()
                .for_each(|&x| self.observe(f64::from(u8::from(x)))),
            ColumnData::U8(v) => v[rows].iter().for_each(|&x| self.observe(f64::from(x))),
            ColumnData::U16(v) => v[rows].iter().for_each(|&x| self.observe(f64::from(x))),
            ColumnData::U32(v) => v[rows].iter().for_each(|&x| self.observe(f64::from(x))),
            ColumnData::U64(v) => v[rows].iter().for_each(|&x| self.observe(sat(x))),
            ColumnData::I64(v) => v[rows].iter().for_each(|&x| self.observe(x as f64)),
            ColumnData::F64(v) => v[rows].iter().for_each(|&x| self.observe(x)),
            // No min/max for text.
            ColumnData::Text(_) => {}
        }
    }
}

#[derive(Debug, Clone)]
struct GroupStats {
    table: &'static EventTable,
    n: i64,
    t_min: i64,
    t_max: i64,
    cols: Vec<ColStats>,
}

/// Group key: flow, source and direction. The source orders alphabetically.
type GroupKey = (i64, &'static str, u8);

/// Per `(flow_id, source, dir)` and column statistics, computed while ingesting.
/// Values are what the read API returns: u64 is saturated to `i64::MAX`, booleans are 0/1,
/// text columns get no min/max.
#[derive(Debug, Clone, Default)]
pub struct StatsAccumulator {
    groups: BTreeMap<GroupKey, GroupStats>,
}

fn sat(v: u64) -> f64 {
    v.min(i64::MAX as u64) as f64
}

impl StatsAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of `(flow, source, dir)` groups seen.
    pub fn groups(&self) -> usize {
        self.groups.len()
    }

    /// Adds every row of the batch. Fails with `TypeMismatch` if the batch is not valid
    /// (`EventBatch::validate`).
    pub fn observe(&mut self, batch: &EventBatch) -> Result<(), StoreError> {
        batch.validate()?;
        let table = batch.table();
        let (flows, dirs, tss) = (batch.flow_ids(), batch.dirs(), batch.timestamps());
        let mut start = 0;
        while start < batch.len() {
            // Rows of one trace file arrive in runs of the same flow and direction, so look the
            // group up once per run instead of once per row.
            let (flow, dir) = (flows[start], dirs[start]);
            let mut end = start + 1;
            while end < batch.len() && flows[end] == flow && dirs[end] == dir {
                end += 1;
            }
            let g = self
                .groups
                .entry((flow, table.source, dir))
                .or_insert_with(|| GroupStats {
                    table,
                    n: 0,
                    t_min: i64::MAX,
                    t_max: i64::MIN,
                    cols: vec![ColStats::default(); table.columns.len()],
                });
            g.n += (end - start) as i64;
            for &ts in &tss[start..end] {
                g.t_min = g.t_min.min(ts);
                g.t_max = g.t_max.max(ts);
            }
            for (cs, data) in g.cols.iter_mut().zip(batch.columns()) {
                cs.observe_column(data, start..end);
            }
            start = end;
        }
        Ok(())
    }

    pub fn merge(&mut self, other: StatsAccumulator) {
        for (key, o) in other.groups {
            match self.groups.entry(key) {
                Entry::Vacant(e) => {
                    e.insert(o);
                }
                Entry::Occupied(mut e) => {
                    let g = e.get_mut();
                    debug_assert_eq!(g.cols.len(), o.cols.len());
                    g.n += o.n;
                    g.t_min = g.t_min.min(o.t_min);
                    g.t_max = g.t_max.max(o.t_max);
                    for (a, b) in g.cols.iter_mut().zip(&o.cols) {
                        a.merge(b);
                    }
                }
            }
        }
    }

    /// One raw `SeriesInfo` per column of every non-empty group, with IDs `next_id, next_id + 1, ...`
    /// in the order (flow id, source, dir, column order).
    pub fn into_series(self, next_id: i64) -> Vec<SeriesInfo> {
        let mut id = next_id;
        let mut out = Vec::new();
        for ((flow_id, source, dir), g) in self.groups {
            let dir = Dir::from_code(i64::from(dir)).unwrap_or(Dir::None);
            for (def, cs) in g.table.columns.iter().zip(g.cols) {
                out.push(SeriesInfo {
                    id,
                    flow_id,
                    kind: SeriesKind::Raw,
                    source: source.to_string(),
                    dir,
                    name: def.name.to_string(),
                    value_type: def.ty,
                    tbl: Some(g.table.table_name()),
                    col: Some(def.name.to_string()),
                    n: g.n,
                    t_min: Some(g.t_min),
                    t_max: Some(g.t_max),
                    v_min: cs.v_min,
                    v_max: cs.v_max,
                });
                id += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::testutil::{ALPHA, ZETA};

    type RowA = (i64, Dir, i64, u64, i64, f64);

    fn batch_a(rows: &[RowA]) -> EventBatch {
        let mut b = EventBatch::new(&ZETA, rows.len());
        for (k, (flow, dir, ts, u, i, f)) in rows.iter().enumerate() {
            b.push_header(*flow, *dir, *ts, k as i64);
            b.u64(0).push(*u);
            b.i64(1).push(*i);
            b.f64(2).push(*f);
            b.text(3).push("x".into());
        }
        b
    }

    fn batch_b(rows: &[(i64, i64, bool, u16)]) -> EventBatch {
        let mut b = EventBatch::new(&ALPHA, rows.len());
        for (k, (flow, ts, x, w)) in rows.iter().enumerate() {
            b.push_header(*flow, Dir::None, *ts, k as i64);
            b.bool(0).push(*x);
            b.u16(1).push(*w);
        }
        b
    }

    #[test]
    fn stats_extremes() {
        let mut acc = StatsAccumulator::new();
        acc.observe(&batch_a(&[
            (1, Dir::Send, 50, u64::MAX, -5, 1.5),
            (1, Dir::Send, 10, 3, i64::MIN, -2.5),
            (1, Dir::Send, 30, 0, i64::MAX, 0.0),
        ]))
        .unwrap();
        let s = acc.into_series(10);
        assert_eq!(s.len(), 4);
        assert_eq!(s[0].id, 10);
        assert_eq!((s[0].n, s[0].t_min, s[0].t_max), (3, Some(10), Some(50)));
        assert_eq!(s[0].v_min, Some(0.0));
        assert_eq!(s[0].v_max, Some(i64::MAX as f64)); // saturated
        assert_eq!(s[1].v_min, Some(i64::MIN as f64));
        assert_eq!(s[2].v_min, Some(-2.5));
        assert_eq!(s[2].v_max, Some(1.5));
        assert_eq!((s[3].v_min, s[3].v_max), (None, None));
        assert_eq!(s[3].value_type, ColType::Text);
        assert_eq!(s[0].tbl.as_deref(), Some("ev_zeta"));
        assert_eq!(s[0].col.as_deref(), Some("u"));
        assert_eq!(s[0].kind, SeriesKind::Raw);
    }

    #[test]
    fn empty_groups_produce_nothing() {
        let acc = StatsAccumulator::new();
        assert_eq!(acc.groups(), 0);
        assert!(acc.into_series(0).is_empty());
        let mut acc = StatsAccumulator::new();
        acc.observe(&EventBatch::new(&ZETA, 0)).unwrap();
        assert!(acc.into_series(0).is_empty());
    }

    #[test]
    fn bool_and_nan() {
        let mut acc = StatsAccumulator::new();
        acc.observe(&batch_b(&[(1, 5, true, 9), (1, 6, false, 2)]))
            .unwrap();
        acc.observe(&batch_a(&[(1, Dir::Recv, 1, 1, 1, f64::NAN)]))
            .unwrap();
        let s = acc.into_series(0);
        let b = s.iter().find(|x| x.name == "b").unwrap();
        assert_eq!((b.v_min, b.v_max), (Some(0.0), Some(1.0)));
        let f = s.iter().find(|x| x.name == "f").unwrap();
        assert_eq!((f.v_min, f.v_max), (None, None));
    }

    #[test]
    fn invalid_batch_is_an_error() {
        let mut b = batch_b(&[(1, 5, true, 9)]);
        b.push_header(1, Dir::None, 6, 1); // header longer than the columns
        let mut acc = StatsAccumulator::new();
        assert!(matches!(acc.observe(&b), Err(StoreError::TypeMismatch(_))));
        assert_eq!(acc.groups(), 0);
    }

    #[test]
    fn runs_within_one_batch() {
        // Alternating flows must still accumulate per group.
        let mut acc = StatsAccumulator::new();
        acc.observe(&batch_a(&[
            (1, Dir::Send, 1, 1, 1, 1.0),
            (2, Dir::Send, 2, 2, 2, 2.0),
            (1, Dir::Send, 3, 3, 3, 3.0),
            (1, Dir::Recv, 4, 4, 4, 4.0),
        ]))
        .unwrap();
        let s = acc.into_series(0);
        let n: Vec<_> = s
            .iter()
            .step_by(4)
            .map(|x| (x.flow_id, x.dir, x.n, x.t_max))
            .collect();
        assert_eq!(
            n,
            [
                (1, Dir::Send, 2, Some(3)),
                (1, Dir::Recv, 1, Some(4)),
                (2, Dir::Send, 1, Some(2))
            ]
        );
    }

    #[test]
    fn deterministic_ids_and_merge() {
        let rows_a = [
            (2, Dir::Recv, 5, 1, 1, 1.0),
            (1, Dir::Send, 6, 2, 2, 2.0),
            (1, Dir::Recv, 7, 3, 3, 3.0),
        ];
        let rows_b = [(2, 8, true, 1), (1, 9, false, 4)];

        let mut one = StatsAccumulator::new();
        one.observe(&batch_a(&rows_a)).unwrap();
        one.observe(&batch_b(&rows_b)).unwrap();

        // Same rows, split differently and merged.
        let mut x = StatsAccumulator::new();
        x.observe(&batch_b(&rows_b[..1])).unwrap();
        x.observe(&batch_a(&rows_a[..2])).unwrap();
        let mut y = StatsAccumulator::new();
        y.observe(&batch_a(&rows_a[2..])).unwrap();
        y.observe(&batch_b(&rows_b[1..])).unwrap();
        y.merge(x);

        let s1 = one.into_series(0);
        let s2 = y.into_series(0);
        assert_eq!(s1, s2);

        // Sorted by flow, source, dir, column order; IDs are consecutive.
        let key = |s: &SeriesInfo| {
            (
                s.id,
                s.flow_id,
                s.source.clone(),
                s.dir.code(),
                s.name.clone(),
            )
        };
        let expected: Vec<(i64, &str, u8, &str)> = vec![
            (1, "alpha", 0, "b"),
            (1, "alpha", 0, "w"),
            (1, "zeta", 1, "u"),
            (1, "zeta", 1, "i"),
            (1, "zeta", 1, "f"),
            (1, "zeta", 1, "t"),
            (1, "zeta", 2, "u"),
            (1, "zeta", 2, "i"),
            (1, "zeta", 2, "f"),
            (1, "zeta", 2, "t"),
            (2, "alpha", 0, "b"),
            (2, "alpha", 0, "w"),
            (2, "zeta", 2, "u"),
            (2, "zeta", 2, "i"),
            (2, "zeta", 2, "f"),
            (2, "zeta", 2, "t"),
        ];
        let got: Vec<_> = s1.iter().map(key).collect();
        for (i, (g, e)) in got.iter().zip(&expected).enumerate() {
            assert_eq!(
                (g.0, g.1, g.2.as_str(), g.3, g.4.as_str()),
                (i as i64, e.0, e.1, e.2, e.3)
            );
        }
        assert_eq!(got.len(), expected.len());
    }
}
