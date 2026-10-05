use super::*;
use crate::v2::catalog::StatsAccumulator;
use crate::v2::testutil::{alpha_batch, flow, pts, zeta_batch, TmpDb, ZetaRow, ALPHA, ZETA};
use crate::v2::CreateOptions;
use std::time::Duration;

fn one_row(ts: i64) -> EventBatch {
    zeta_batch(&[(1, Dir::None, ts, 0, 1, 1, 1.0, "x")])
}

/// Writes `batches` (tables `ZETA` and `ALPHA` exist) and finishes with their statistics.
fn build(db: &TmpDb, batches: Vec<EventBatch>, flows: Vec<Flow>) -> Result<(), StoreError> {
    let s = create(db.path(), CreateOptions::default())?;
    s.create_tables(&[&ZETA, &ALPHA])?;
    let mut acc = StatsAccumulator::new();
    let mut w = s.writer()?;
    for b in batches {
        acc.observe(&b)?;
        w.write(b)?;
    }
    w.close()?;
    s.finish(Catalog {
        flows,
        series: acc.into_series(1),
        meta: vec![("writer".into(), "test".into())],
    })
}

fn finish_empty(s: Box<dyn IngestSession>) -> Result<(), StoreError> {
    s.finish(Catalog::default())
}

fn conn(db: &TmpDb) -> Connection {
    Connection::open(db.path()).unwrap()
}

fn count(db: &TmpDb, sql: &str) -> i64 {
    conn(db).query_row(sql, [], |r| r.get(0)).unwrap()
}

/// Writes until the writer thread is gone (it died asynchronously).
fn wait_until_gone(w: &mut dyn BatchWriter) -> Result<(), StoreError> {
    for _ in 0..300 {
        w.write(one_row(1))?;
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the writer thread never died");
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

fn find(st: &dyn Store, flow: i64, dir: Dir, name: &str) -> SeriesInfo {
    st.series(flow)
        .unwrap()
        .into_iter()
        .find(|s| s.name == name && s.dir == dir)
        .unwrap()
}

/// Flow 1 (send, four rows with a duplicate timestamp and extreme values) and flow 2 (recv).
fn sample_db() -> (TmpDb, Box<dyn Store>) {
    let db = TmpDb::new();
    let rows: [ZetaRow; 5] = [
        (1, Dir::Send, 30, 2, u64::MAX, -3, 0.5, "c"),
        (1, Dir::Send, 10, 0, 7, i64::MIN, -1.5, "a"),
        // Same timestamp as the next row: read back in seq order.
        (1, Dir::Send, 20, 5, (1 << 63) + 1, 4, 2.0, "e"),
        (1, Dir::Send, 20, 1, 1, 5, 3.0, "b"),
        (2, Dir::Recv, 5, 0, 9, 9, 9.0, "z"),
    ];
    build(
        &db,
        vec![zeta_batch(&rows)],
        vec![flow(1, 1000), flow(2, 2000)],
    )
    .unwrap();
    let st = crate::v2::open(db.path()).unwrap();
    (db, st)
}

#[test]
fn open_dispatches_and_reads_catalog() {
    let (db, st) = sample_db();
    assert!(!db.partial().exists());
    assert_eq!(st.engine(), Engine::Sqlite);

    let flows = st.flows().unwrap();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[1].tuple.sport, 2000);
    assert_eq!(flows[0].tuple, flow(1, 1000).tuple);
    assert_eq!(st.flow(2).unwrap().unwrap().id, 2);
    assert!(st.flow(3).unwrap().is_none());

    // Four columns per (flow, source, dir) group; an empty group has no series.
    assert_eq!(st.series(1).unwrap().len(), 4);
    assert_eq!(st.series(2).unwrap().len(), 4);
    assert!(st.series(3).unwrap().is_empty());
    let u = find(&*st, 1, Dir::Send, "u");
    assert_eq!(st.series_by_id(u.id).unwrap().unwrap(), u);
    assert!(st.series_by_id(9999).unwrap().is_none());
    assert_eq!((u.n, u.t_min, u.t_max), (4, Some(10), Some(30)));
    assert_eq!(u.v_max, Some(i64::MAX as f64));
    assert_eq!(u.tbl.as_deref(), Some("ev_zeta"));
}

#[test]
fn points_are_ordered_and_typed() {
    let (_db, st) = sample_db();
    let u = find(&*st, 1, Dir::Send, "u");
    let ts: Vec<f64> = points(&*st, &u, None).iter().map(|p| p.0).collect();
    assert_eq!(ts, [10.0, 20.0, 20.0, 30.0]);
    // u64 saturates to i64::MAX, small values are exact.
    assert_eq!(ints(&*st, &u), [7, 1, i64::MAX, i64::MAX]);
    let i = find(&*st, 1, Dir::Send, "i");
    assert_eq!(ints(&*st, &i)[0], i64::MIN);
    let f = find(&*st, 1, Dir::Send, "f");
    assert!(matches!(points(&*st, &f, None)[0].1, DataValue::Float(x) if x == -1.5));
    let t = find(&*st, 1, Dir::Send, "t");
    let texts: Vec<String> = points(&*st, &t, None)
        .into_iter()
        .map(|p| p.1.as_string())
        .collect();
    assert_eq!(texts, ["a", "b", "e", "c"]);
    // The other flow and direction are separate.
    assert_eq!(points(&*st, &find(&*st, 2, Dir::Recv, "u"), None).len(), 1);
}

#[test]
fn range_bounds_round_inward() {
    let (_db, st) = sample_db();
    let u = find(&*st, 1, Dir::Send, "u");
    let r = |lo, hi| points(&*st, &u, Some((lo, hi))).len();
    assert_eq!(r(10.0, 20.0), 3);
    assert_eq!(r(10.5, 19.9), 0);
    assert_eq!(r(9.1, 20.0), 3);
    assert_eq!(r(10.1, 30.9), 3);
    assert_eq!(r(20.0, 20.0), 2);
    assert_eq!(r(30.0, 10.0), 0);
    assert_eq!(r(f64::NEG_INFINITY, f64::INFINITY), 4);
    assert_eq!(r(f64::NAN, 1.0), 0);
}

#[test]
fn storage_format_on_disk() {
    let (db, _st) = sample_db();
    // The stored u64 is the i64 bit pattern.
    assert_eq!(
        count(&db, r#"SELECT "u" FROM "ev_zeta" WHERE "ts" = 30"#),
        -1
    );
    let c = conn(&db);
    let meta = |k: &str| -> String {
        c.query_row(sql::SELECT_META_VALUE, [k], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(meta("schema_version"), "2");
    assert_eq!(meta("writer"), "test");
    assert!(meta("created_at").ends_with('Z') && meta("created_at").len() == 20);
    // Indexes are built after the load.
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name IN ('ev_zeta_idx', 'ev_alpha_idx', 'derived_samples_idx')"
        ),
        3
    );
}

#[test]
fn small_commit_interval_keeps_all_rows() {
    let db = TmpDb::new();
    let s = create_with(db.path(), CreateOptions::default(), 3).unwrap();
    s.create_tables(&[&ZETA]).unwrap();
    let mut w = s.writer().unwrap();
    for k in 0..4 {
        let rows: Vec<ZetaRow> = (0..5)
            .map(|j| (1, Dir::None, k * 5 + j, k * 5 + j, 1, 1, 1.0, "x"))
            .collect();
        w.write(zeta_batch(&rows)).unwrap();
    }
    w.close().unwrap();
    finish_empty(s).unwrap();
    assert_eq!(count(&db, r#"SELECT count(*) FROM "ev_zeta""#), 20);
}

#[test]
fn concurrent_writers() {
    let db = TmpDb::new();
    let s = create(db.path(), CreateOptions::default()).unwrap();
    s.create_tables(&[&ZETA]).unwrap();
    std::thread::scope(|sc| {
        for flow in 1..=3i64 {
            let s = &s;
            sc.spawn(move || {
                let mut w = s.writer().unwrap();
                for k in 0..50 {
                    w.write(zeta_batch(&[(flow, Dir::Send, k, k, 1, 1, 1.0, "x")]))
                        .unwrap();
                }
                w.close().unwrap();
            });
        }
    });
    finish_empty(s).unwrap();
    assert_eq!(count(&db, r#"SELECT count(*) FROM "ev_zeta""#), 150);
}

#[test]
fn alpha_table_roundtrip() {
    let db = TmpDb::new();
    build(
        &db,
        vec![alpha_batch(&[(1, 5, 0, true, 9), (1, 6, 1, false, 65535)])],
        vec![flow(1, 1)],
    )
    .unwrap();
    let st = crate::v2::open(db.path()).unwrap();
    let b = find(&*st, 1, Dir::None, "b");
    let w = find(&*st, 1, Dir::None, "w");
    let bs: Vec<bool> = points(&*st, &b, None)
        .iter()
        .map(|p| matches!(p.1, DataValue::Boolean(true)))
        .collect();
    assert_eq!(bs, [true, false]);
    assert_eq!(ints(&*st, &w), [9, 65535]);
    assert_eq!((b.v_min, b.v_max), (Some(0.0), Some(1.0)));
}

#[test]
fn partial_file_lifecycle() {
    let db = TmpDb::new();
    let s = create(db.path(), CreateOptions::default()).unwrap();
    s.create_tables(&[&ZETA]).unwrap();
    let mut w = s.writer().unwrap();
    w.write(one_row(1)).unwrap();
    assert!(db.partial().exists());
    assert!(!db.path().exists());
    // Dropped with a writer still alive: no hang, partial removed, the writer errors out.
    drop(s);
    assert!(!db.partial().exists());
    assert!(!db.path().exists());
    assert!(matches!(
        wait_until_gone(&mut *w),
        Err(StoreError::WriterGone)
    ));

    // Dropped without writers.
    let s = create(db.path(), CreateOptions::default()).unwrap();
    assert!(db.partial().exists());
    drop(s);
    assert!(!db.partial().exists());
    assert!(!db.path().exists());

    // A stale partial from a crashed run is replaced.
    std::fs::write(db.partial(), b"junk").unwrap();
    let s = create(db.path(), CreateOptions::default()).unwrap();
    finish_empty(s).unwrap();
    assert!(!db.partial().exists());
    assert!(db.path().exists());
}

#[test]
fn failed_create_leaves_no_partial() {
    let db = TmpDb::new();
    // A directory in place of the partial file: removing it fails before any connection exists.
    std::fs::create_dir(db.partial()).unwrap();
    assert!(create(db.path(), CreateOptions::default()).is_err());
    std::fs::remove_dir(db.partial()).unwrap();
    // The connection opens, but setting the file up fails: the partial is removed again.
    let nodir = db.suffixed("-nodir/x.db");
    assert!(create(&nodir, CreateOptions::default()).is_err());
    assert!(!partial_path(&nodir).exists());
}

#[test]
fn existing_output_needs_force() {
    let db = TmpDb::new();
    std::fs::write(db.path(), b"precious").unwrap();
    assert!(matches!(
        create(db.path(), CreateOptions::default()),
        Err(StoreError::Exists(_))
    ));
    assert_eq!(std::fs::read(db.path()).unwrap(), b"precious");
    assert!(!db.partial().exists());

    // The old file and its sidecars survive until finish; force then replaces them.
    for suffix in ["-journal", "-wal", "-shm"] {
        std::fs::write(db.suffixed(suffix), b"old").unwrap();
    }
    let s = create(db.path(), CreateOptions { force: true }).unwrap();
    assert_eq!(std::fs::read(db.path()).unwrap(), b"precious");
    assert!(db.suffixed("-wal").exists());
    finish_empty(s).unwrap();
    assert!(crate::v2::open(db.path()).is_ok());
    for suffix in ["-journal", "-wal", "-shm"] {
        assert!(!db.suffixed(suffix).exists(), "{suffix}");
    }
}

#[test]
fn writer_error_surfaces() {
    let db = TmpDb::new();
    let s = create(db.path(), CreateOptions::default()).unwrap();
    // Table never created: the thread fails on the insert.
    let mut w = s.writer().unwrap();
    w.write(one_row(1)).unwrap();
    assert!(matches!(
        wait_until_gone(&mut *w),
        Err(StoreError::WriterGone)
    ));
    assert!(matches!(w.close(), Err(StoreError::WriterGone)));
    // The thread's own error wins in finish, and nothing is published.
    let e = finish_empty(s).unwrap_err();
    assert!(matches!(e, StoreError::Sqlite(_)), "{e:?}");
    assert!(e.to_string().contains("ev_zeta"));
    assert!(!db.partial().exists());
    assert!(!db.path().exists());
}

#[test]
fn finish_error_is_returned() {
    let db = TmpDb::new();
    let s = create(db.path(), CreateOptions::default()).unwrap();
    // Two flows with the same id violate the primary key.
    let r = s.finish(Catalog {
        flows: vec![flow(1, 1), flow(1, 2)],
        ..Catalog::default()
    });
    assert!(matches!(r, Err(StoreError::Sqlite(_))));
    assert!(!db.partial().exists());
    assert!(!db.path().exists());
}

#[test]
fn invalid_batches_are_rejected_by_write() {
    let db = TmpDb::new();
    let s = create(db.path(), CreateOptions::default()).unwrap();
    s.create_tables(&[&ZETA]).unwrap();
    let mut w = s.writer().unwrap();
    let mut b = EventBatch::new(&ZETA, 1);
    b.push_header(1, Dir::None, 1, 0);
    assert!(matches!(w.write(b), Err(StoreError::TypeMismatch(_))));
    // NaN would become NULL in SQLite; every engine rejects it up front.
    let nan = zeta_batch(&[(1, Dir::None, 1, 0, 1, 1, f64::NAN, "x")]);
    assert!(matches!(w.write(nan), Err(StoreError::TypeMismatch(m)) if m.contains("NaN")));
    // The session is still usable.
    w.write(one_row(1)).unwrap();
    w.close().unwrap();
    finish_empty(s).unwrap();
    assert_eq!(count(&db, r#"SELECT count(*) FROM "ev_zeta""#), 1);
}

#[test]
fn open_checks_schema_version() {
    let db = TmpDb::new();
    // No meta table (a v1 database, for example).
    conn(&db)
        .execute_batch("CREATE TABLE flows (id INTEGER)")
        .unwrap();
    assert!(matches!(
        crate::v2::open(db.path()),
        Err(StoreError::UnsupportedSchema { found: None })
    ));
    let c = conn(&db);
    c.execute_batch(
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO meta VALUES ('schema_version', '1')",
    )
    .unwrap();
    drop(c);
    match crate::v2::open(db.path()) {
        Err(StoreError::UnsupportedSchema { found }) => assert_eq!(found.as_deref(), Some("1")),
        other => panic!("{:?}", other.err()),
    }
    conn(&db).execute_batch("DELETE FROM meta").unwrap();
    assert!(matches!(
        crate::v2::open(db.path()),
        Err(StoreError::UnsupportedSchema { found: None })
    ));
}

#[test]
fn corrupt_catalog_is_reported() {
    let (db, st) = sample_db();
    drop(st);
    conn(&db)
        .execute_batch(
            "UPDATE series SET dir = 7 WHERE id = 1; UPDATE flows SET src = 'bogus' WHERE id = 2",
        )
        .unwrap();
    let st = crate::v2::open(db.path()).unwrap();
    assert!(matches!(st.series(1), Err(StoreError::Corrupt(m)) if m.contains("dir")));
    assert!(matches!(st.flow(2), Err(StoreError::Corrupt(m)) if m.contains("bogus")));
    assert!(st.flow(1).is_ok());
}

// ---- derived series ----------------------------------------------------------------------------

fn floats() -> Vec<DataPoint> {
    pts(&[
        (2.4, DataValue::Float(2.0)),
        (1.6, DataValue::Float(-1.0)),
        (1.6, DataValue::Float(f64::NAN)),
        (3.0, DataValue::Float(5.5)),
    ])
}

#[test]
fn derived_create_and_read() {
    let (db, st) = sample_db();
    let before = st.series(1).unwrap().len();
    let max_id = st.series(2).unwrap().iter().map(|s| s.id).max().unwrap();
    let d = st
        .create_derived(1, "goodput", ValueKind::Float, &floats())
        .unwrap();
    assert_eq!(d.id, max_id + 1);
    assert_eq!(d.kind, SeriesKind::Derived);
    assert_eq!(
        (d.source.as_str(), d.dir, d.value_type),
        ("derived", Dir::None, ColType::F64)
    );
    assert_eq!((d.n, d.t_min, d.t_max), (4, Some(2), Some(3)));
    assert_eq!((d.v_min, d.v_max), (Some(-1.0), Some(5.5)));
    assert_eq!(st.series(1).unwrap().len(), before + 1);
    assert_eq!(st.series_by_id(d.id).unwrap().unwrap(), d);

    // Ordered by (ts, seq); timestamps rounded; NaN round-trips.
    let all = points(&*st, &d, None);
    let ts: Vec<f64> = all.iter().map(|p| p.0).collect();
    assert_eq!(ts, [2.0, 2.0, 2.0, 3.0]);
    assert!(matches!(all[0].1, DataValue::Float(x) if x == 2.0));
    assert!(matches!(all[1].1, DataValue::Float(x) if x == -1.0));
    assert!(matches!(all[2].1, DataValue::Float(x) if x.is_nan()));
    assert_eq!(points(&*st, &d, Some((2.5, 3.0))).len(), 1);
    assert_eq!(count(&db, "SELECT count(*) FROM derived_samples"), 4);
}

#[test]
fn derived_ids_start_at_one() {
    let db = TmpDb::new();
    let s = create(db.path(), CreateOptions::default()).unwrap();
    finish_empty(s).unwrap();
    let st = crate::v2::open(db.path()).unwrap();
    let a = st.create_derived(1, "a", ValueKind::Int, &[]).unwrap();
    let b = st.create_derived(1, "b", ValueKind::Int, &[]).unwrap();
    assert_eq!((a.id, b.id), (1, 2));
}

#[test]
fn derived_duplicate_name() {
    let (_db, st) = sample_db();
    st.create_derived(1, "g", ValueKind::Float, &[]).unwrap();
    let n = st.series(1).unwrap().len();
    let dup = st.create_derived(1, "g", ValueKind::Int, &[]);
    assert!(matches!(dup, Err(StoreError::Exists(n)) if n == "g"));
    assert_eq!(st.series(1).unwrap().len(), n);
    // Same name in another flow is fine.
    st.create_derived(2, "g", ValueKind::Int, &[]).unwrap();
}

#[test]
fn derived_value_kinds() {
    let (_db, st) = sample_db();
    let i = st
        .create_derived(
            1,
            "i",
            ValueKind::Int,
            &pts(&[(1.0, DataValue::Int(-4)), (2.0, DataValue::Int(i64::MAX))]),
        )
        .unwrap();
    assert_eq!((i.v_min, i.v_max), (Some(-4.0), Some(i64::MAX as f64)));
    assert_eq!(ints(&*st, &i), [-4, i64::MAX]);
    let b = st
        .create_derived(
            1,
            "b",
            ValueKind::Bool,
            &pts(&[
                (1.0, DataValue::Boolean(true)),
                (2.0, DataValue::Boolean(false)),
            ]),
        )
        .unwrap();
    assert_eq!((b.v_min, b.v_max), (Some(0.0), Some(1.0)));
    let bs: Vec<bool> = points(&*st, &b, None)
        .iter()
        .map(|p| matches!(p.1, DataValue::Boolean(true)))
        .collect();
    assert_eq!(bs, [true, false]);
    let t = st
        .create_derived(
            1,
            "t",
            ValueKind::String,
            &pts(&[(1.0, DataValue::String("hi".into()))]),
        )
        .unwrap();
    assert_eq!((t.v_min, t.v_max), (None, None));
    assert_eq!(points(&*st, &t, None)[0].1.as_string(), "hi");
    let e = st.create_derived(1, "e", ValueKind::Int, &[]).unwrap();
    assert_eq!((e.n, e.t_min, e.t_max, e.v_min), (0, None, None, None));
    assert!(points(&*st, &e, None).is_empty());
}

#[test]
fn derived_invalid_input_changes_nothing() {
    let (db, st) = sample_db();
    let before = st.series(1).unwrap().len();
    let mixed = pts(&[(1.0, DataValue::Int(1)), (2.0, DataValue::Float(1.0))]);
    assert!(matches!(
        st.create_derived(1, "x", ValueKind::Int, &mixed),
        Err(StoreError::TypeMismatch(_))
    ));
    for t in [f64::NAN, f64::INFINITY] {
        let r = st.create_derived(1, "x", ValueKind::Int, &pts(&[(t, DataValue::Int(1))]));
        assert!(matches!(r, Err(StoreError::TypeMismatch(_))), "{t}");
    }
    assert_eq!(st.series(1).unwrap().len(), before);
    assert_eq!(count(&db, "SELECT count(*) FROM derived_samples"), 0);
}

#[test]
fn replace_keeps_id() {
    let (_db, st) = sample_db();
    let other = st.create_derived(1, "other", ValueKind::Int, &[]).unwrap();
    let d = st
        .create_derived(1, "goodput", ValueKind::Float, &floats())
        .unwrap();
    let r = st
        .replace_derived(&d, &pts(&[(9.0, DataValue::Float(1.0))]))
        .unwrap();
    assert_eq!(
        (r.id, r.name.as_str(), r.n, r.t_min, r.v_max),
        (d.id, "goodput", 1, Some(9), Some(1.0))
    );
    assert_eq!(st.series_by_id(d.id).unwrap().unwrap(), r);
    assert_eq!(points(&*st, &r, None).len(), 1);
    // Untouched neighbour, and the next new id is still max + 1.
    assert_eq!(st.series_by_id(other.id).unwrap().unwrap(), other);
    let next = st.create_derived(1, "next", ValueKind::Int, &[]).unwrap();
    assert_eq!(next.id, d.id + 1);
}

#[test]
fn replace_rolls_back_on_error() {
    let (_db, st) = sample_db();
    let d = st
        .create_derived(1, "g", ValueKind::Float, &floats())
        .unwrap();
    for bad in [
        pts(&[(1.0, DataValue::Int(1))]),
        pts(&[(f64::NAN, DataValue::Float(1.0))]),
    ] {
        assert!(matches!(
            st.replace_derived(&d, &bad),
            Err(StoreError::TypeMismatch(_))
        ));
    }
    assert_eq!(st.series_by_id(d.id).unwrap().unwrap(), d);
    assert_eq!(points(&*st, &d, None).len(), 4);
}

#[test]
fn delete_derived() {
    let (db, st) = sample_db();
    let before = st.series(1).unwrap().len();
    let d = st
        .create_derived(1, "g", ValueKind::Float, &floats())
        .unwrap();
    st.delete_derived(&d).unwrap();
    assert!(st.series_by_id(d.id).unwrap().is_none());
    assert_eq!(st.series(1).unwrap().len(), before);
    assert_eq!(count(&db, "SELECT count(*) FROM derived_samples"), 0);
    // The name is free again, the id of the deleted maximum is reused.
    let again = st.create_derived(1, "g", ValueKind::Int, &[]).unwrap();
    assert_eq!(again.id, d.id);
    // Deleting a series that is gone is NotFound.
    st.delete_derived(&again).unwrap();
    assert!(matches!(
        st.delete_derived(&again),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        st.replace_derived(&again, &[]),
        Err(StoreError::NotFound(_))
    ));
}

#[test]
fn replace_of_max_id_series() {
    let (_db, st) = sample_db();
    let a = st.create_derived(1, "a", ValueKind::Int, &[]).unwrap();
    let b = st
        .create_derived(1, "b", ValueKind::Int, &pts(&[(1.0, DataValue::Int(1))]))
        .unwrap();
    assert!(b.id > a.id);
    let r = st
        .replace_derived(
            &b,
            &pts(&[(2.0, DataValue::Int(5)), (3.0, DataValue::Int(6))]),
        )
        .unwrap();
    assert_eq!((r.id, r.n), (b.id, 2));
    assert_eq!(ints(&*st, &r), [5, 6]);
    assert_eq!(st.series_by_id(a.id).unwrap().unwrap(), a);
}

#[test]
fn stale_series_info_is_rejected() {
    let (_db, st) = sample_db();
    let d = st.create_derived(1, "g", ValueKind::Int, &[]).unwrap();
    let renamed = SeriesInfo {
        name: "other".into(),
        ..d.clone()
    };
    let moved = SeriesInfo {
        flow_id: 2,
        ..d.clone()
    };
    for s in [&renamed, &moved] {
        assert!(matches!(
            st.replace_derived(s, &[]),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(st.delete_derived(s), Err(StoreError::NotFound(_))));
    }
    assert_eq!(st.series_by_id(d.id).unwrap().unwrap(), d);
}

#[test]
fn raw_series_are_not_derived() {
    let (_db, st) = sample_db();
    let raw = find(&*st, 1, Dir::Send, "u");
    assert!(matches!(
        st.replace_derived(&raw, &[]),
        Err(StoreError::NotDerived)
    ));
    assert!(matches!(
        st.delete_derived(&raw),
        Err(StoreError::NotDerived)
    ));
    // A forged "derived" SeriesInfo pointing at a raw series is caught by the stored row.
    let forged = SeriesInfo {
        kind: SeriesKind::Derived,
        ..raw.clone()
    };
    assert!(matches!(
        st.delete_derived(&forged),
        Err(StoreError::NotDerived)
    ));
    assert!(matches!(
        st.replace_derived(&forged, &[]),
        Err(StoreError::NotDerived)
    ));
    assert_eq!(points(&*st, &raw, None).len(), 4);
    assert!(st.series_by_id(raw.id).unwrap().is_some());
}
