use super::*;
use crate::v2::catalog::StatsAccumulator;
use crate::v2::testutil::{alpha_batch, flow, pts, zeta_batch, TmpDb, ALPHA, DEMO, ZETA};
use crate::v2::{create as create_store, open as open_store};
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

