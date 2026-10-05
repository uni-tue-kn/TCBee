use super::*;
use crate::v2::catalog::StatsAccumulator;
use crate::v2::testutil::{alpha_batch, flow, pts, zeta_batch, TmpDb, ALPHA, DEMO, ZETA};
use crate::v2::{create as create_store, detect_engine, open as open_store};
use std::collections::HashMap;

/// `ev_alpha` as `create_table_sql` renders it, plus a CHECK that rejects `w = 13`.
const ALPHA_WITH_CHECK: &str = "CREATE TABLE ev_alpha (flow_id BIGINT NOT NULL, dir TINYINT NOT NULL, \
     ts BIGINT NOT NULL, seq BIGINT NOT NULL, b BOOLEAN NOT NULL, w USMALLINT NOT NULL CHECK (w <> 13))";

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| {
        r.get(0)
    })
    .unwrap()
}

fn live() -> Arc<AtomicUsize> {
    Arc::default()
}

fn alpha_rows(flow: i64, ts: &[i64]) -> EventBatch {
    let rows: Vec<_> = ts
        .iter()
        .enumerate()
        .map(|(k, &t)| (flow, t, k as i64, t % 2 == 0, t as u16))
        .collect();
    alpha_batch(&rows)
}

fn zeta_rows(flow: i64, dir: Dir, ts: &[i64], seq0: i64) -> EventBatch {
    let rows: Vec<_> = ts
        .iter()
        .enumerate()
        .map(|(k, &t)| {
            (
                flow,
                dir,
                t,
                seq0 + k as i64,
                t as u64,
                -t,
                t as f64 / 2.0,
                "x",
            )
        })
        .collect();
    zeta_batch(&rows)
}

// ---- appender-arrow lifecycle (regression tests for the assumptions the engine rests on) ------

#[test]
fn two_cloned_connections_append_to_two_tables_while_metadata_is_written() {
    let db = TmpDb::new();
    let conn = Connection::open(db.path()).unwrap();
    conn.execute_batch(&create_table_sql(D, &ZETA)).unwrap();
    conn.execute_batch(&create_table_sql(D, &ALPHA)).unwrap();
    conn.execute_batch("CREATE TABLE side (k BIGINT)").unwrap();
    let (c1, c2) = (conn.try_clone().unwrap(), conn.try_clone().unwrap());
    std::thread::scope(|sc| {
        sc.spawn(move || {
            let mut app = c1.appender("ev_zeta").unwrap();
            for i in 0..20 {
                let ts: Vec<i64> = (0..500).map(|k| i * 500 + k).collect();
                let b = zeta_rows(1, Dir::Send, &ts, i * 500);
                app.append_record_batch(to_record_batch(b).unwrap())
                    .unwrap();
            }
            app.flush().unwrap();
        });
        sc.spawn(move || {
            let mut app = c2.appender("ev_alpha").unwrap();
            for i in 0..20 {
                let ts: Vec<i64> = (0..500).map(|k| i * 500 + k).collect();
                let b = alpha_rows(2, &ts);
                app.append_record_batch(to_record_batch(b).unwrap())
                    .unwrap();
            }
            app.flush().unwrap();
        });
        // Metadata inserts on the main connection while the appenders are alive.
        for k in 0..200 {
            conn.execute("INSERT INTO side VALUES (?)", params![k])
                .unwrap();
        }
    });
    assert_eq!(count(&conn, "ev_zeta"), 10_000);
    assert_eq!(count(&conn, "ev_alpha"), 10_000);
    assert_eq!(count(&conn, "side"), 200);
}

#[test]
fn two_connections_append_to_the_same_table_concurrently() {
    let db = TmpDb::new();
    let conn = Connection::open(db.path()).unwrap();
    conn.execute_batch(&create_table_sql(D, &ZETA)).unwrap();
    let clones: Vec<_> = (0..2).map(|_| conn.try_clone().unwrap()).collect();
    std::thread::scope(|sc| {
        for (w, c) in clones.into_iter().enumerate() {
            sc.spawn(move || {
                let mut app = c.appender("ev_zeta").unwrap();
                for i in 0..20 {
                    let ts: Vec<i64> = (0..500).map(|k| i * 500 + k).collect();
                    let b = zeta_rows(w as i64, Dir::Recv, &ts, 0);
                    app.append_record_batch(to_record_batch(b).unwrap())
                        .unwrap();
                }
                app.flush().unwrap();
            });
        }
    });
    assert_eq!(count(&conn, "ev_zeta"), 20_000);
    let one: i64 = conn
        .query_row("SELECT count(*) FROM ev_zeta WHERE flow_id = 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(one, 10_000);
}

#[test]
fn check_violation_is_reported_by_append_or_flush_and_leaves_no_rows() {
    let db = TmpDb::new();
    let conn = Connection::open(db.path()).unwrap();
    conn.execute_batch(ALPHA_WITH_CHECK).unwrap();
    let c = conn.try_clone().unwrap();
    let mut app = c.appender("ev_alpha").unwrap();
    let rb = to_record_batch(alpha_rows(1, &[1, 2, 13, 14])).unwrap();
    let r_append = app.append_record_batch(rb);
    let r_flush = app.flush();
    assert!(
        r_append.is_err() || r_flush.is_err(),
        "violation was swallowed"
    );
    drop(app);
    assert_eq!(count(&conn, "ev_alpha"), 0);
    // The connection stays usable.
    let mut app = c.appender("ev_alpha").unwrap();
    app.append_record_batch(to_record_batch(alpha_rows(1, &[1, 2])).unwrap())
        .unwrap();
    app.flush().unwrap();
    assert_eq!(count(&conn, "ev_alpha"), 2);
}

#[test]
fn dropping_an_appender_does_not_make_failed_rows_visible() {
    // Dropping an appender discards its flush error, which is why writers flush in `close`.
    let db = TmpDb::new();
    let conn = Connection::open(db.path()).unwrap();
    conn.execute_batch(ALPHA_WITH_CHECK).unwrap();
    let mut app = conn.appender("ev_alpha").unwrap();
    let _ = app.append_record_batch(to_record_batch(alpha_rows(1, &[13])).unwrap());
    drop(app);
    assert_eq!(count(&conn, "ev_alpha"), 0);
}

// ---- writers ----------------------------------------------------------------------------------

#[test]
fn close_surfaces_flush_error() {
    let db = TmpDb::new();
    let conn = Connection::open(db.path()).unwrap();
    conn.execute_batch(ALPHA_WITH_CHECK).unwrap();
    let mut w = Box::new(DuckWriter::new(conn.try_clone().unwrap(), &live()));
    let written = w.write(alpha_rows(1, &[1, 2, 13]));
    let closed = w.close();
    assert!(
        written.is_err() || closed.is_err(),
        "violation was swallowed"
    );
    assert_eq!(count(&conn, "ev_alpha"), 0);
    // A fresh writer on the same database works.
    let mut w = Box::new(DuckWriter::new(conn.try_clone().unwrap(), &live()));
    w.write(alpha_rows(1, &[1, 2])).unwrap();
    w.close().unwrap();
    assert_eq!(count(&conn, "ev_alpha"), 2);
}

#[test]
fn writer_rejects_bad_batches_and_ignores_empty_ones() {
    let db = TmpDb::new();
    let s = create_store(Engine::DuckDb, db.path(), CreateOptions::default()).unwrap();
    s.create_tables(&[&DEMO]).unwrap();
    let mut w = s.writer().unwrap();
    // The table of this batch was never created.
    assert!(matches!(
        w.write(alpha_rows(1, &[1])),
        Err(StoreError::DuckDb(_))
    ));
    let mut short = EventBatch::new(&DEMO, 1);
    short.push_header(1, Dir::None, 1, 0);
    assert!(matches!(w.write(short), Err(StoreError::TypeMismatch(_))));
    let mut nan = EventBatch::new(&ZETA, 1);
    nan.push_header(1, Dir::None, 1, 0);
    nan.u64(0).push(1);
    nan.i64(1).push(1);
    nan.f64(2).push(f64::NAN);
    nan.text(3).push(String::new());
    assert!(matches!(w.write(nan), Err(StoreError::TypeMismatch(_))));
    w.write(EventBatch::new(&DEMO, 0)).unwrap();
    // After an error a writer is discarded (see `DuckWriter`).
    drop(w);
}

#[test]
fn finish_with_a_live_writer_fails_and_removes_the_partial_file() {
    let db = TmpDb::new();
    let s = create_store(Engine::DuckDb, db.path(), CreateOptions::default()).unwrap();
    s.create_tables(&[&ZETA]).unwrap();
    let w = s.writer().unwrap();
    assert!(s.finish(Catalog::default()).is_err());
    assert!(!db.path().exists() && !db.partial().exists());
    drop(w);

    // Closed or dropped writers do not count.
    let s = create_store(Engine::DuckDb, db.path(), CreateOptions::default()).unwrap();
    s.writer().unwrap().close().unwrap();
    drop(s.writer().unwrap());
    s.finish(Catalog::default()).unwrap();
    assert!(db.path().exists());
}

// ---- session lifecycle ------------------------------------------------------------------------

/// Flow 1 (send: four rows with a duplicate timestamp and extreme values; alpha rows) and
/// flow 2 (recv), written by two writer threads.
fn sample_db() -> (TmpDb, Box<dyn Store>) {
    let db = TmpDb::new();
    let s = create_store(Engine::DuckDb, db.path(), CreateOptions::default()).unwrap();
    s.create_tables(&[&ZETA, &ALPHA]).unwrap();
    let accs: Vec<StatsAccumulator> = std::thread::scope(|sc| {
        let hs = [
            vec![
                zeta_batch(&[
                    (1, Dir::Send, 30, 2, u64::MAX, -3, 0.5, "c"),
                    (1, Dir::Send, 10, 0, 7, i64::MIN, -1.5, "a"),
                ]),
                zeta_batch(&[
                    // Same timestamp as the next row: read back in seq order.
                    (1, Dir::Send, 20, 5, (1 << 63) + 1, 4, 2.0, "e"),
                    (1, Dir::Send, 20, 1, 1, 5, 3.0, "b"),
                ]),
                alpha_batch(&[(1, 1, 0, true, 5), (1, 2, 1, false, 6)]),
            ],
            vec![zeta_batch(&[(2, Dir::Recv, 5, 0, 9, 9, 9.0, "z")])],
        ]
        .into_iter()
        .map(|batches| {
            let s = &s;
            sc.spawn(move || {
                let mut w = s.writer().unwrap();
                let mut acc = StatsAccumulator::new();
                for b in batches {
                    acc.observe(&b).unwrap();
                    w.write(b).unwrap();
                }
                w.close().unwrap();
                acc
            })
        })
        .collect::<Vec<_>>();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut acc = StatsAccumulator::new();
    accs.into_iter().for_each(|a| acc.merge(a));
    s.finish(Catalog {
        flows: vec![flow(1, 1000), flow(2, 2000)],
        series: acc.into_series(1),
        meta: vec![("writer".into(), "test".into())],
    })
    .unwrap();
    let st = open_store(db.path()).unwrap();
    (db, st)
}

fn points(st: &dyn Store, s: &SeriesInfo, range: Option<(f64, f64)>) -> Vec<(f64, DataValue)> {
    let mut out = Vec::new();
    st.for_each_point(s, range, &mut |p| out.push((p.timestamp, p.value)))
        .unwrap();
    out
}

fn ints(st: &dyn Store, s: &SeriesInfo) -> Vec<i64> {
    points(st, s, None)
        .iter()
        .map(|p| p.1.as_int().unwrap())
        .collect()
}

fn find(st: &dyn Store, flow: i64, source: &str, dir: Dir, name: &str) -> SeriesInfo {
    st.series(flow)
        .unwrap()
        .into_iter()
        .find(|s| s.source == source && s.dir == dir && s.name == name)
        .unwrap_or_else(|| panic!("no series {source}/{name}"))
}

#[test]
fn finished_file_has_no_sidecars_and_is_detected() {
    let (db, st) = sample_db();
    assert_eq!(detect_engine(db.path()).unwrap(), Engine::DuckDb);
    assert_eq!(st.engine(), Engine::DuckDb);
    assert!(!db.partial().exists());
    assert!(!db.suffixed(".partial.wal").exists());
    assert!(!db.suffixed(".wal").exists());
}

#[test]
fn flows_series_and_stats() {
    let (_db, st) = sample_db();
    let flows = st.flows().unwrap();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0].tuple, flow(1, 1000).tuple);
    assert_eq!(st.flow(2).unwrap().unwrap().tuple.sport, 2000);
    assert!(st.flow(3).unwrap().is_none());

    // Four zeta columns plus two alpha columns for flow 1; empty groups have no series.
    assert_eq!(st.series(1).unwrap().len(), 6);
    assert_eq!(st.series(2).unwrap().len(), 4);
    assert!(st.series(3).unwrap().is_empty());
    let u = find(&*st, 1, "zeta", Dir::Send, "u");
    assert_eq!((u.n, u.t_min, u.t_max), (4, Some(10), Some(30)));
    assert_eq!(u.v_min, Some(1.0));
    assert_eq!(u.v_max, Some(i64::MAX as f64)); // saturated
    assert_eq!(u.tbl.as_deref(), Some("ev_zeta"));
    assert_eq!(st.series_by_id(u.id).unwrap().unwrap(), u);
    assert!(st.series_by_id(9999).unwrap().is_none());
    let t = find(&*st, 1, "zeta", Dir::Send, "t");
    assert!(t.v_min.is_none() && t.v_max.is_none());
    let b = find(&*st, 1, "alpha", Dir::None, "b");
    assert_eq!((b.v_min, b.v_max), (Some(0.0), Some(1.0)));
}

#[test]
fn points_are_ordered_by_ts_then_seq_and_typed() {
    let (_db, st) = sample_db();
    let u = find(&*st, 1, "zeta", Dir::Send, "u");
    let ts: Vec<f64> = points(&*st, &u, None).iter().map(|p| p.0).collect();
    assert_eq!(ts, [10.0, 20.0, 20.0, 30.0]);
    // u64 saturates to i64::MAX, small values are exact; the duplicate timestamp keeps seq order.
    assert_eq!(ints(&*st, &u), [7, 1, i64::MAX, i64::MAX]);
    assert_eq!(
        ints(&*st, &find(&*st, 1, "zeta", Dir::Send, "i"))[0],
        i64::MIN
    );
    let f = find(&*st, 1, "zeta", Dir::Send, "f");
    assert!(matches!(points(&*st, &f, None)[0].1, DataValue::Float(x) if x == -1.5));
    let t = find(&*st, 1, "zeta", Dir::Send, "t");
    let texts: Vec<String> = points(&*st, &t, None)
        .into_iter()
        .map(|p| p.1.as_string())
        .collect();
    assert_eq!(texts, ["a", "b", "e", "c"]);
    let b = find(&*st, 1, "alpha", Dir::None, "b");
    assert!(matches!(
        points(&*st, &b, None)[0].1,
        DataValue::Boolean(true)
    ));
    assert_eq!(ints(&*st, &find(&*st, 1, "alpha", Dir::None, "w")), [5, 6]);
    // The other flow and direction are separate.
    assert_eq!(ints(&*st, &find(&*st, 2, "zeta", Dir::Recv, "u")), [9]);
}

#[test]
fn range_bounds_round_inward() {
    let (_db, st) = sample_db();
    let u = find(&*st, 1, "zeta", Dir::Send, "u");
    let n = |lo, hi| points(&*st, &u, Some((lo, hi))).len();
    assert_eq!(n(10.5, 30.9), 3); // 20, 20, 30
    assert_eq!(n(20.0, 20.0), 2);
    assert_eq!(n(10.0, 30.0), 4);
    assert_eq!(n(30.5, 99.0), 0);
    assert_eq!(n(f64::NEG_INFINITY, f64::INFINITY), 4);
    assert_eq!(n(f64::NAN, 5.0), 0);
    assert_eq!(n(25.0, 15.0), 0);
}

#[test]
fn meta_has_caller_entries_and_ours() {
    let (db, st) = sample_db();
    drop(st); // release the file
    let conn = Connection::open(db.path()).unwrap();
    let mut st = conn.prepare(sql::SELECT_META).unwrap();
    let mut rows = st.query([]).unwrap();
    let mut meta = HashMap::new();
    while let Some(r) = rows.next().unwrap() {
        meta.insert(
            r.get::<_, String>(0).unwrap(),
            r.get::<_, String>(1).unwrap(),
        );
    }
    assert_eq!(meta.len(), 3);
    assert_eq!(meta["schema_version"], "2");
    assert_eq!(meta["writer"], "test");
    assert!(meta["created_at"].starts_with("20") && meta["created_at"].ends_with('Z'));
}

#[test]
fn open_rejects_other_schemas() {
    let db = TmpDb::new();
    // No meta table: what a schema v1 file looks like.
    Connection::open(db.path())
        .unwrap()
        .execute_batch("CREATE TABLE ts (x INT)")
        .unwrap();
    assert!(matches!(
        open_store(db.path()),
        Err(StoreError::UnsupportedSchema { found: None })
    ));
    drop(db);

    let db = TmpDb::new();
    Connection::open(db.path())
        .unwrap()
        .execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); \
             INSERT INTO meta VALUES ('schema_version', '9')",
        )
        .unwrap();
    match open_store(db.path()) {
        Err(StoreError::UnsupportedSchema { found }) => assert_eq!(found.as_deref(), Some("9")),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn existing_file_needs_force_and_an_abandoned_session_keeps_it() {
    let (db, st) = sample_db();
    drop(st);
    let before = std::fs::metadata(db.path()).unwrap().len();

    assert!(matches!(
        create_store(Engine::DuckDb, db.path(), CreateOptions::default()),
        Err(StoreError::Exists(_))
    ));
    assert!(!db.partial().exists());

    // With force the old file stays until finish; dropping the session deletes the partial
    // file and its WAL.
    let s = create_store(Engine::DuckDb, db.path(), CreateOptions { force: true }).unwrap();
    s.create_tables(&[&ZETA]).unwrap();
    let mut w = s.writer().unwrap();
    w.write(zeta_rows(1, Dir::Send, &[1, 2, 3], 0)).unwrap();
    w.close().unwrap();
    assert!(db.partial().exists());
    drop(s);
    assert!(!db.partial().exists() && !db.suffixed(".partial.wal").exists());
    assert_eq!(std::fs::metadata(db.path()).unwrap().len(), before);
    assert!(open_store(db.path()).is_ok());

    // Finishing a forced session replaces the file.
    let s = create_store(Engine::DuckDb, db.path(), CreateOptions { force: true }).unwrap();
    s.finish(Catalog::default()).unwrap();
    assert!(!db.partial().exists());
    assert!(open_store(db.path()).unwrap().flows().unwrap().is_empty());
}

#[test]
fn stale_wal_next_to_a_missing_file_is_removed() {
    let db = TmpDb::new();
    let wal = db.suffixed(".wal");
    std::fs::write(&wal, b"not a wal").unwrap();
    let s = create_store(Engine::DuckDb, db.path(), CreateOptions::default()).unwrap();
    assert!(!wal.exists(), "removed at create");
    // One that appears during the session is removed before the rename.
    std::fs::write(&wal, b"not a wal").unwrap();
    s.finish(Catalog::default()).unwrap();
    assert!(!wal.exists(), "removed at finish");
    assert!(open_store(db.path()).is_ok());
}

// ---- derived series ---------------------------------------------------------------------------

fn ints_pts(v: &[(f64, i64)]) -> Vec<DataPoint> {
    let v: Vec<_> = v.iter().map(|&(t, x)| (t, DataValue::Int(x))).collect();
    pts(&v)
}

#[test]
fn create_derived_computes_stats_and_ids() {
    let (_db, st) = sample_db();
    let s = st
        .create_derived(
            1,
            "d",
            ValueKind::Int,
            &ints_pts(&[(5.4, 3), (5.6, -2), (7.0, 9)]),
        )
        .unwrap();
    assert_eq!(
        (s.kind, s.source.as_str(), s.dir, s.n),
        (SeriesKind::Derived, "derived", Dir::None, 3)
    );
    assert_eq!(
        (s.t_min, s.t_max, s.v_min, s.v_max),
        (Some(5), Some(7), Some(-2.0), Some(9.0))
    );
    assert_eq!(s.id, 11); // after the ten catalog series
    assert_eq!(st.series_by_id(s.id).unwrap().unwrap(), s);
    let ts: Vec<f64> = points(&*st, &s, None).iter().map(|p| p.0).collect();
    assert_eq!(ts, [5.0, 6.0, 7.0]);
    assert_eq!(points(&*st, &s, Some((6.0, 7.0))).len(), 2);
    assert_eq!(st.series(1).unwrap().len(), 7);
}

#[test]
fn derived_value_kinds() {
    let (_db, st) = sample_db();
    let f = pts(&[
        (1.0, DataValue::Float(0.5)),
        (2.0, DataValue::Float(f64::NAN)),
    ]);
    let sf = st.create_derived(1, "f", ValueKind::Float, &f).unwrap();
    assert_eq!((sf.v_min, sf.v_max), (Some(0.5), Some(0.5)));
    let pf = points(&*st, &sf, None);
    assert!(matches!(pf[1].1, DataValue::Float(x) if x.is_nan()));
    let b = pts(&[(1.0, DataValue::Boolean(true))]);
    let sb = st.create_derived(1, "b", ValueKind::Bool, &b).unwrap();
    assert!(matches!(
        points(&*st, &sb, None)[0].1,
        DataValue::Boolean(true)
    ));
    let t = pts(&[(1.0, DataValue::String("hi".into()))]);
    let stx = st.create_derived(2, "t", ValueKind::String, &t).unwrap();
    assert!(stx.v_min.is_none());
    assert_eq!(points(&*st, &stx, None)[0].1.as_string(), "hi");
    let e = st.create_derived(2, "e", ValueKind::Int, &[]).unwrap();
    assert_eq!((e.n, e.t_min, e.v_min), (0, None, None));
    assert!(points(&*st, &e, None).is_empty());
}

#[test]
fn create_derived_rejects_bad_points_and_duplicate_names() {
    let (_db, st) = sample_db();
    let a = st
        .create_derived(1, "d", ValueKind::Int, &ints_pts(&[(1.0, 1)]))
        .unwrap();
    // Duplicate name in the same flow: Exists; nothing is left behind (the next id is unused).
    assert!(matches!(
        st.create_derived(1, "d", ValueKind::Int, &ints_pts(&[(1.0, 1)])),
        Err(StoreError::Exists(_))
    ));
    // The same name in another flow is fine, and gets the very next id.
    let other = st
        .create_derived(2, "d", ValueKind::Int, &ints_pts(&[(1.0, 1)]))
        .unwrap();
    assert_eq!(other.id, a.id + 1);
    // Value of the wrong kind, non-finite timestamp.
    let wrong = pts(&[(1.0, DataValue::Float(1.0))]);
    assert!(matches!(
        st.create_derived(1, "w", ValueKind::Int, &wrong),
        Err(StoreError::TypeMismatch(_))
    ));
    for bad in [f64::NAN, f64::INFINITY] {
        assert!(matches!(
            st.create_derived(1, "w", ValueKind::Int, &ints_pts(&[(bad, 1)])),
            Err(StoreError::TypeMismatch(_))
        ));
    }
    assert_eq!(st.series(1).unwrap().len(), 7);
}

#[test]
fn replace_keeps_the_id_and_the_name() {
    let (_db, st) = sample_db();
    let a = st
        .create_derived(1, "a", ValueKind::Int, &ints_pts(&[(1.0, 1), (2.0, 2)]))
        .unwrap();
    let b = st
        .create_derived(1, "b", ValueKind::Int, &ints_pts(&[(1.0, 5)]))
        .unwrap();
    let r = st.replace_derived(&a, &ints_pts(&[(100.0, 7)])).unwrap();
    assert_eq!((r.id, r.name.as_str(), r.flow_id, r.n), (a.id, "a", 1, 1));
    assert_eq!(
        (r.t_min, r.v_min, r.v_max),
        (Some(100), Some(7.0), Some(7.0))
    );
    assert_eq!(st.series_by_id(a.id).unwrap().unwrap(), r);
    assert_eq!(ints(&*st, &r), [7]);
    // The other series is untouched, and a new one still gets the next id.
    assert_eq!(ints(&*st, &b), [5]);
    let c = st.create_derived(1, "c", ValueKind::Int, &[]).unwrap();
    assert_eq!(c.id, b.id + 1);
}

#[test]
fn replace_of_the_series_with_the_highest_id() {
    let (_db, st) = sample_db();
    let a = st
        .create_derived(1, "a", ValueKind::Int, &ints_pts(&[(1.0, 1)]))
        .unwrap();
    let r = st
        .replace_derived(&a, &ints_pts(&[(2.0, 2), (3.0, 3)]))
        .unwrap();
    assert_eq!(r.id, a.id);
    assert_eq!(ints(&*st, &r), [2, 3]);
    let next = st.create_derived(1, "n", ValueKind::Int, &[]).unwrap();
    assert_eq!(next.id, a.id + 1);
}

#[test]
fn failed_replace_keeps_the_old_series() {
    let (_db, st) = sample_db();
    let a = st
        .create_derived(1, "a", ValueKind::Int, &ints_pts(&[(1.0, 1), (2.0, 2)]))
        .unwrap();
    let nan_ts = ints_pts(&[(f64::NAN, 1)]);
    assert!(matches!(
        st.replace_derived(&a, &nan_ts),
        Err(StoreError::TypeMismatch(_))
    ));
    let wrong = pts(&[(1.0, DataValue::Boolean(true))]);
    assert!(matches!(
        st.replace_derived(&a, &wrong),
        Err(StoreError::TypeMismatch(_))
    ));
    assert_eq!(st.series_by_id(a.id).unwrap().unwrap(), a);
    assert_eq!(ints(&*st, &a), [1, 2]);
}

#[test]
fn stale_or_raw_series_infos_are_rejected() {
    let (_db, st) = sample_db();
    let a = st
        .create_derived(1, "a", ValueKind::Int, &ints_pts(&[(1.0, 1)]))
        .unwrap();

    // Raw series cannot be edited.
    let raw = find(&*st, 1, "zeta", Dir::Send, "u");
    assert!(matches!(
        st.delete_derived(&raw),
        Err(StoreError::NotDerived)
    ));
    assert!(matches!(
        st.replace_derived(&raw, &[]),
        Err(StoreError::NotDerived)
    ));
    // A derived-looking info that points at a raw row.
    let fake = SeriesInfo {
        kind: SeriesKind::Derived,
        ..raw.clone()
    };
    assert!(matches!(
        st.delete_derived(&fake),
        Err(StoreError::NotDerived)
    ));

    // Name or flow differ from the stored row.
    let renamed = SeriesInfo {
        name: "other".into(),
        ..a.clone()
    };
    assert!(matches!(
        st.replace_derived(&renamed, &[]),
        Err(StoreError::NotFound(_))
    ));
    let moved = SeriesInfo {
        flow_id: 2,
        ..a.clone()
    };
    assert!(matches!(
        st.delete_derived(&moved),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(st.series_by_id(a.id).unwrap().unwrap(), a);

    // Deleted: every further edit through the stale info fails with NotFound.
    st.delete_derived(&a).unwrap();
    assert!(st.series_by_id(a.id).unwrap().is_none());
    assert!(matches!(
        st.delete_derived(&a),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        st.replace_derived(&a, &[]),
        Err(StoreError::NotFound(_))
    ));
    assert!(st.series(1).unwrap().iter().all(|s| s.name != "a"));
}

#[test]
fn derived_series_persist_across_reopen() {
    let (db, st) = sample_db();
    st.create_derived(1, "keep", ValueKind::Int, &ints_pts(&[(1.0, 4), (2.0, 5)]))
        .unwrap();
    let gone = st.create_derived(1, "gone", ValueKind::Int, &[]).unwrap();
    st.delete_derived(&gone).unwrap();
    drop(st);
    let st = open_store(db.path()).unwrap();
    let k = find(&*st, 1, "derived", Dir::None, "keep");
    assert_eq!((k.n, ints(&*st, &k)), (2, vec![4, 5]));
    assert!(st.series(1).unwrap().iter().all(|s| s.name != "gone"));
}
