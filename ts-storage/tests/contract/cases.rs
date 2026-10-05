//! The contract: one function per case, each taking the engine to run on.

use ts_storage::{
    detect_engine, Catalog, ColType, CreateOptions, DataValue, Dir, Engine, IpTuple, SeriesInfo,
    SeriesKind, StatsAccumulator, Store, StoreError, ValueKind,
};

use crate::fixture::*;

// ---------------------------------------------------------------------------------------------
// Round trip of every type

const EXTREME_TIMES: [f64; 5] = [10.0, 20.0, 30.0, 40.0, 50.0];

/// Reads series `name` of the extreme rows (flow 1, send) after checking its timestamps.
fn extreme_series(st: &dyn Store, name: &str) -> SeriesInfo {
    let s = find(st, 1, "all", Dir::Send, name);
    assert_eq!(times(st, &s, None), EXTREME_TIMES, "timestamps of {name}");
    s
}

pub fn round_trip_integers_and_bools(engine: Engine) {
    let (_env, st) = open_all(engine, &extreme_rows(1));
    let int = |v: [i64; 5]| v.map(|x| format!("Int({x})")).to_vec();
    let boolean = |v: [bool; 5]| v.map(|x| format!("Boolean({x})")).to_vec();
    let max = i64::MAX;
    let expected = [
        ("b", boolean([true, false, false, false, false])),
        ("w8", int([255, 0, 0, 0, 0])),
        ("w16", int([65_535, 0, 0, 0, 0])),
        ("w32", int([4_294_967_295, 0, 0, 0, 0])),
        // u64::MAX, 2^63 and 2^63 + 1 read as i64::MAX; i64::MAX itself and 0 are exact.
        ("w64", int([max, max, max, max, 0])),
        ("i", int([-1, i64::MIN, max, 0, 0])),
    ];
    for (name, want) in expected {
        let s = extreme_series(&*st, name);
        assert_eq!(debug_values(&*st, &s, None), want, "values of {name}");
    }
}

pub fn round_trip_floats(engine: Engine) {
    let (_env, st) = open_all(engine, &extreme_rows(1));
    let s = extreme_series(&*st, "f");
    let got: Vec<f64> = read(&*st, &s, None)
        .iter()
        .map(|p| p.value.as_float().unwrap())
        .collect();
    assert_eq!(got, [-1.0, f64::MIN_POSITIVE, f64::MAX, 0.0, 2.5e-300]);
}

pub fn round_trip_text(engine: Engine) {
    let rows = extreme_rows(1);
    let (_env, st) = open_all(engine, &rows);
    let s = extreme_series(&*st, "t");
    let got: Vec<String> = read(&*st, &s, None)
        .iter()
        .map(|p| p.value.as_string())
        .collect();
    let want: Vec<String> = rows.iter().map(|r| r.t.clone()).collect();
    // Empty, quotes and SQL metacharacters, unicode, long, and a lone digit.
    assert_eq!(got, want);
    assert!(got[3].len() > 10_000);
}

pub fn u64_saturates_in_the_catalog(engine: Engine) {
    let (_env, st) = open_all(engine, &extreme_rows(1));
    let s = find(&*st, 1, "all", Dir::Send, "w64");
    assert_eq!((s.v_min, s.v_max), (Some(0.0), Some(i64::MAX as f64)));
}

pub fn engine_is_detected(engine: Engine) {
    let (env, st) = open_all(engine, &extreme_rows(1));
    assert_eq!(st.engine(), engine);
    assert_eq!(detect_engine(&env.path).unwrap(), engine);
}

// ---------------------------------------------------------------------------------------------
// Ordering and ranges

/// Flow 1: out of order, with timestamp 20 three times (seq 5, 1, 3); flow 2: one row at 20.
/// `w32` is the value to read back.
fn ranges_db(engine: Engine) -> (Env, Box<dyn Store>, SeriesInfo) {
    let r = |ts, seq, x| row32(1, Dir::Send, ts, seq, x);
    let rows = [
        r(30, 7, 70),
        r(20, 5, 50),
        r(10, 0, 0),
        r(20, 1, 10),
        r(40, 8, 80),
        r(20, 3, 30),
        row32(2, Dir::Send, 20, 0, 99),
    ];
    let (env, st) = open_all(engine, &rows);
    let s = find(&*st, 1, "all", Dir::Send, "w32");
    (env, st, s)
}

pub fn points_are_ordered_by_ts_then_seq(engine: Engine) {
    let (_env, st, s) = ranges_db(engine);
    assert_eq!(ints(&*st, &s, None), [0, 10, 30, 50, 70, 80]);
    assert_eq!(times(&*st, &s, None), [10.0, 20.0, 20.0, 20.0, 30.0, 40.0]);
    // Flows do not leak into each other.
    let other = find(&*st, 2, "all", Dir::Send, "w32");
    assert_eq!(ints(&*st, &other, None), [99]);
}

pub fn ranges_are_inclusive(engine: Engine) {
    let (_env, st, s) = ranges_db(engine);
    let range = |lo, hi| ints(&*st, &s, Some((lo, hi)));
    assert_eq!(range(20.0, 30.0), [10, 30, 50, 70]);
    assert_eq!(range(20.0, 20.0), [10, 30, 50]);
    assert_eq!(range(10.0, 40.0), [0, 10, 30, 50, 70, 80]);
}

pub fn ranges_round_inward(engine: Engine) {
    let (_env, st, s) = ranges_db(engine);
    let range = |lo, hi| ints(&*st, &s, Some((lo, hi)));
    // ceil(lower), floor(upper)
    assert_eq!(range(19.5, 30.5), [10, 30, 50, 70]);
    assert_eq!(range(9.5, 10.5), [0]);
    assert_eq!(range(20.5, 29.5), Vec::<i64>::new());
}

pub fn ranges_outside_or_empty(engine: Engine) {
    let (_env, st, s) = ranges_db(engine);
    let range = |lo, hi| ints(&*st, &s, Some((lo, hi)));
    assert!(range(30.0, 20.0).is_empty(), "inverted");
    assert!(range(41.0, 100.0).is_empty(), "after the data");
    assert!(range(-100.0, 9.0).is_empty(), "before the data");
    assert!(range(1e300, 1e301).is_empty(), "far after the data");
    assert_eq!(range(-1e300, 1e300).len(), 6, "everything");
}

/// Infinite bounds select everything; a NaN bound selects nothing.
pub fn ranges_with_non_finite_bounds(engine: Engine) {
    let (_env, st, s) = ranges_db(engine);
    let range = |lo, hi| ints(&*st, &s, Some((lo, hi))).len();
    assert_eq!(range(f64::NEG_INFINITY, f64::INFINITY), 6);
    assert_eq!(range(f64::NAN, 100.0), 0);
    assert_eq!(range(0.0, f64::NAN), 0);
}

// ---------------------------------------------------------------------------------------------
// Writers

/// Opens a session with tables `ALL` and `OTHER`.
fn session_with_tables(engine: Engine, env: &Env) -> Box<dyn ts_storage::IngestSession> {
    let session = ts_storage::create(engine, &env.path, CreateOptions::default()).unwrap();
    session.create_tables(&[&ALL, &OTHER]).unwrap();
    session
}

fn finish_with(
    session: Box<dyn ts_storage::IngestSession>,
    flows: Vec<ts_storage::Flow>,
    acc: StatsAccumulator,
) {
    session
        .finish(Catalog {
            flows,
            series: acc.into_series(1),
            meta: vec![],
        })
        .unwrap();
}

/// Four threads with a writer each; every writer alternates batches between the two tables and
/// has its own flow.
pub fn several_batches_and_writers(engine: Engine) {
    const THREADS: i64 = 4;
    let env = Env::new();
    let session = session_with_tables(engine, &env);
    let accs: Vec<StatsAccumulator> = std::thread::scope(|scope| {
        let handles: Vec<_> = (1..=THREADS)
            .map(|flow| {
                let session = &*session;
                scope.spawn(move || {
                    let mut acc = StatsAccumulator::new();
                    let mut w = session.writer().unwrap();
                    let (mut all_n, mut other_n) = (0u32, 0u32);
                    for batch in 0..6 {
                        let b = if batch % 2 == 0 {
                            let rows: Vec<_> = (all_n..all_n + 100)
                                .map(|k| row32(flow, Dir::Send, k.into(), k.into(), k))
                                .collect();
                            all_n += 100;
                            all_batch(&rows)
                        } else {
                            let rows: Vec<_> = (other_n..other_n + 50)
                                .map(|k| (flow, Dir::Recv, k.into(), k.into(), k, "y"))
                                .collect();
                            other_n += 50;
                            other_batch(&rows)
                        };
                        acc.observe(&b).unwrap();
                        w.write(b).unwrap();
                    }
                    w.close().unwrap();
                    acc
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut acc = StatsAccumulator::new();
    accs.into_iter().for_each(|a| acc.merge(a));
    finish_with(session, (1..=THREADS).map(|f| flow(f, f)).collect(), acc);

    let st = ts_storage::open(&env.path).unwrap();
    for f in 1..=THREADS {
        let a = find(&*st, f, "all", Dir::Send, "w32");
        assert_eq!(a.n, 300);
        assert_eq!(ints(&*st, &a, None), (0..300).collect::<Vec<i64>>());
        let x = find(&*st, f, "other", Dir::Recv, "x");
        assert_eq!(x.n, 150);
        assert_eq!(ints(&*st, &x, None), (0..150).collect::<Vec<i64>>());
        assert_eq!(st.series(f).unwrap().len(), 8 + 2);
    }
}

/// Two writers append rows of the same flow and table at the same time. Row `i` has timestamp
/// `i / 2` and `seq = i`; even rows come from one thread, odd rows from the other, so every
/// timestamp occurs twice, once from each writer.
pub fn two_writers_append_to_one_table_and_flow(engine: Engine) {
    const ROWS: u32 = 2000;
    let env = Env::new();
    let session = session_with_tables(engine, &env);
    let barrier = std::sync::Barrier::new(2);
    let accs: Vec<StatsAccumulator> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2u32)
            .map(|parity| {
                let (session, barrier) = (&*session, &barrier);
                scope.spawn(move || {
                    let mut acc = StatsAccumulator::new();
                    let mut w = session.writer().unwrap();
                    barrier.wait();
                    let mine: Vec<u32> = (0..ROWS).filter(|i| i % 2 == parity).collect();
                    for chunk in mine.chunks(100) {
                        let rows: Vec<_> = chunk
                            .iter()
                            .map(|&i| row32(1, Dir::Send, (i / 2).into(), i.into(), i))
                            .collect();
                        let b = all_batch(&rows);
                        acc.observe(&b).unwrap();
                        w.write(b).unwrap();
                    }
                    w.close().unwrap();
                    acc
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut acc = StatsAccumulator::new();
    accs.into_iter().for_each(|a| acc.merge(a));
    finish_with(session, vec![flow(1, 1)], acc);

    let st = ts_storage::open(&env.path).unwrap();
    let s = find(&*st, 1, "all", Dir::Send, "w32");
    assert_eq!(s.n, i64::from(ROWS));
    // Ordered by (ts, seq): exactly the row index order.
    assert_eq!(
        ints(&*st, &s, None),
        (0..i64::from(ROWS)).collect::<Vec<_>>()
    );
    let want: Vec<f64> = (0..ROWS).map(|i| f64::from(i / 2)).collect();
    assert_eq!(times(&*st, &s, None), want);
}

// ---------------------------------------------------------------------------------------------
// Catalog

/// Flow 1 has `ALL` rows in all three directions (six each) and two `OTHER` rows, flow 2 has
/// three `ALL` rows and an IPv6 source, flow 3 has no rows.
fn catalog_db(engine: Engine) -> (Env, Box<dyn Store>) {
    let mk = |flow, dir, ts: i64, k: i64| AllRow {
        b: k % 2 == 0,
        w8: (k * 7) as u8,
        w16: (k * 300) as u16,
        w32: (k * 70_000) as u32,
        w64: if k == 3 { u64::MAX } else { k as u64 * 1000 },
        i: k * 11 - 20,
        f: k as f64 * 0.25 - 1.0,
        t: format!("v{k}"),
        ..row(flow, dir, ts, k)
    };
    let mut rows = Vec::new();
    for k in 0..6 {
        rows.push(mk(1, Dir::Send, 100 + k, k));
        rows.push(mk(1, Dir::Recv, 5 + 2 * k, k + 10));
        rows.push(mk(1, Dir::None, 1000 - k, k + 20));
    }
    for k in 0..3 {
        rows.push(mk(2, Dir::Send, 7 + k, k));
    }
    let other = other_batch(&[(1, Dir::Send, 1, 0, 5, "a"), (1, Dir::Send, 2, 1, 9, "b")]);
    let env = Env::new();
    build(
        engine,
        &env.path,
        &[&ALL, &OTHER],
        vec![all_batch(&rows), other],
        vec![flow(1, 1000), flow_v6_to_v4(2, 2000), flow(3, 3000)],
    )
    .unwrap();
    let st = ts_storage::open(&env.path).unwrap();
    (env, st)
}

pub fn catalog_flows_by_tuple(engine: Engine) {
    let (_env, st) = catalog_db(engine);
    let got: Vec<(i64, IpTuple)> = st
        .flows()
        .unwrap()
        .into_iter()
        .map(|f| (f.id, f.tuple))
        .collect();
    let want = vec![
        (1, tuple(1000)),
        (2, flow_v6_to_v4(2, 2000).tuple),
        (3, tuple(3000)),
    ];
    assert_eq!(got, want);
    assert_eq!(st.flow(2).unwrap().unwrap().tuple, want[1].1);
    assert!(st.flow(4).unwrap().is_none());
}

pub fn catalog_series_per_flow(engine: Engine) {
    let (_env, st) = catalog_db(engine);
    // Eight series per `all` group (send, recv, none), two per `other` group, none for an empty
    // or unknown flow.
    assert_eq!(st.series(1).unwrap().len(), 3 * 8 + 2);
    assert_eq!(st.series(2).unwrap().len(), 8);
    assert!(st.series(3).unwrap().is_empty());
    assert!(st.series(4).unwrap().is_empty());

    let s = find(&*st, 1, "all", Dir::Send, "w16");
    assert_eq!(s.kind, SeriesKind::Raw);
    assert_eq!(s.value_type, ColType::U16);
    assert_eq!(s.tbl.as_deref(), Some("ev_all"));
    assert_eq!(s.col.as_deref(), Some("w16"));
    let x = find(&*st, 1, "other", Dir::Send, "x");
    assert_eq!(x.tbl.as_deref(), Some("ev_other"));
}

pub fn catalog_same_name_differs_by_dir(engine: Engine) {
    let (_env, st) = catalog_db(engine);
    let send = find(&*st, 1, "all", Dir::Send, "w16");
    let recv = find(&*st, 1, "all", Dir::Recv, "w16");
    let none = find(&*st, 1, "all", Dir::None, "w16");
    assert_eq!(send.name, recv.name);
    assert_eq!(send.name, none.name);
    assert!(send.id != recv.id && send.id != none.id && recv.id != none.id);
    assert_eq!((send.t_min, send.t_max), (Some(100), Some(105)));
    assert_eq!((recv.t_min, recv.t_max), (Some(5), Some(15)));
    assert_eq!((none.t_min, none.t_max), (Some(995), Some(1000)));
    // Reading follows the direction.
    assert_eq!(ints(&*st, &send, None), [0, 300, 600, 900, 1200, 1500]);
    assert_eq!(
        ints(&*st, &recv, None),
        [3000, 3300, 3600, 3900, 4200, 4500]
    );
}

/// The catalog statistics equal a brute-force computation over the points read.
fn check_stats(st: &dyn Store, s: &SeriesInfo) {
    let (mut t_min, mut t_max) = (None::<i64>, None::<i64>);
    let (mut v_min, mut v_max) = (None::<f64>, None::<f64>);
    let points = read(st, s, None);
    for p in &points {
        let t = p.timestamp as i64;
        t_min = Some(t_min.map_or(t, |m| m.min(t)));
        t_max = Some(t_max.map_or(t, |m| m.max(t)));
        let v = match &p.value {
            DataValue::Int(i) => Some(*i as f64),
            DataValue::Float(f) => Some(*f),
            DataValue::Boolean(b) => Some(f64::from(u8::from(*b))),
            DataValue::String(_) => None,
        };
        if let Some(v) = v {
            v_min = Some(v_min.map_or(v, |m: f64| m.min(v)));
            v_max = Some(v_max.map_or(v, |m: f64| m.max(v)));
        }
    }
    let what = format!("series {} {}/{:?}/{}", s.id, s.source, s.dir, s.name);
    assert_eq!(s.n, points.len() as i64, "n of {what}");
    assert_eq!((s.t_min, s.t_max), (t_min, t_max), "t range of {what}");
    assert_eq!((s.v_min, s.v_max), (v_min, v_max), "v range of {what}");
}

pub fn catalog_stats_match_brute_force(engine: Engine) {
    let (_env, st) = catalog_db(engine);
    let mut checked = 0;
    for f in st.flows().unwrap() {
        for s in st.series(f.id).unwrap() {
            check_stats(&*st, &s);
            checked += 1;
        }
    }
    assert_eq!(checked, 26 + 8);
    // Text series have no value range.
    let t = find(&*st, 1, "all", Dir::Send, "t");
    assert_eq!((t.v_min, t.v_max), (None, None));
}

/// Every series belongs to a flow of the catalog, and ids look up the same series.
pub fn catalog_ids_and_references(engine: Engine) {
    let (_env, st) = catalog_db(engine);
    let flow_ids: Vec<i64> = st.flows().unwrap().iter().map(|f| f.id).collect();
    let mut ids = Vec::new();
    for f in &flow_ids {
        for s in st.series(*f).unwrap() {
            assert_eq!(s.flow_id, *f);
            assert_eq!(st.series_by_id(s.id).unwrap().unwrap(), s);
            ids.push(s.id);
        }
    }
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n, "series ids are unique");
    assert!(st.series_by_id(i64::MAX).unwrap().is_none());
}

// ---------------------------------------------------------------------------------------------
// Derived series

/// Flows 1 and 2, one raw row each.
fn derived_db(engine: Engine) -> (Env, Box<dyn Store>) {
    open_all(
        engine,
        &[row32(1, Dir::Send, 10, 0, 1), row32(2, Dir::Send, 10, 0, 2)],
    )
}

fn create_int(st: &dyn Store, flow: i64, name: &str, pts: &[(f64, i64)]) -> SeriesInfo {
    st.create_derived(flow, name, ValueKind::Int, &int_points(pts))
        .unwrap()
}

pub fn derived_create_and_read(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let raw_count = st.series(1).unwrap().len();
    let a = create_int(&*st, 1, "rate", &[(3.0, 30), (1.0, 10), (2.0, 20)]);
    assert_eq!(a.kind, SeriesKind::Derived);
    assert_eq!(
        (a.source.as_str(), a.dir, a.name.as_str()),
        ("derived", Dir::None, "rate")
    );
    assert_eq!(a.value_type, ColType::I64);
    assert_eq!((a.tbl.as_deref(), a.col.as_deref()), (None, None));
    assert_eq!((a.n, a.t_min, a.t_max), (3, Some(1), Some(3)));
    assert_eq!((a.v_min, a.v_max), (Some(10.0), Some(30.0)));
    assert_eq!(st.series(1).unwrap().len(), raw_count + 1);
    assert_eq!(st.series_by_id(a.id).unwrap().unwrap(), a);
    assert_eq!(ints(&*st, &a, None), [10, 20, 30]);
    assert_eq!(times(&*st, &a, Some((1.5, 3.0))), [2.0, 3.0]);
}

/// Derived timestamps are rounded to integer nanoseconds.
pub fn derived_timestamps_are_rounded(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let s = create_int(&*st, 1, "rounded", &[(1.4, 1), (2.5, 2)]);
    assert_eq!(times(&*st, &s, None), [1.0, 3.0]);
}

pub fn derived_replace_keeps_the_id(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let a = create_int(&*st, 1, "rate", &[(1.0, 10)]);
    let b = create_int(&*st, 2, "rate", &[(1.0, 1)]);
    let a2 = st
        .replace_derived(&a, &int_points(&[(5.0, 7), (6.0, -7)]))
        .unwrap();
    assert_eq!(a2.id, a.id);
    assert_eq!((a2.flow_id, a2.name.as_str()), (1, "rate"));
    assert_eq!((a2.n, a2.t_min, a2.t_max), (2, Some(5), Some(6)));
    assert_eq!((a2.v_min, a2.v_max), (Some(-7.0), Some(7.0)));
    assert_eq!(st.series_by_id(a.id).unwrap().unwrap(), a2);
    assert_eq!(ints(&*st, &a2, None), [7, -7]);
    // The other flow's series is untouched.
    assert_eq!(ints(&*st, &b, None), [1]);
}

pub fn derived_replace_with_nothing(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let a = create_int(&*st, 1, "a", &[(1.0, 1)]);
    let empty = st.replace_derived(&a, &[]).unwrap();
    assert_eq!(empty.id, a.id);
    assert_eq!(
        (empty.n, empty.t_min, empty.t_max, empty.v_min, empty.v_max),
        (0, None, None, None, None)
    );
    assert!(read(&*st, &empty, None).is_empty());
    let again = st
        .replace_derived(&empty, &int_points(&[(1.0, 1)]))
        .unwrap();
    assert_eq!(again.id, a.id);
}

pub fn derived_delete(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let a = create_int(&*st, 1, "rate", &[(1.0, 1)]);
    let other = create_int(&*st, 2, "rate", &[(1.0, 1)]);
    st.delete_derived(&a).unwrap();
    assert!(st.series_by_id(a.id).unwrap().is_none());
    assert!(st.series(1).unwrap().iter().all(|s| s.name != "rate"));
    assert!(st.series_by_id(other.id).unwrap().is_some());
    // The name is free again.
    let again = create_int(&*st, 1, "rate", &[(9.0, 9)]);
    assert_eq!(ints(&*st, &again, None), [9]);
}

pub fn derived_survives_reopen(engine: Engine) {
    let (env, st) = derived_db(engine);
    create_int(&*st, 1, "a", &[(1.0, 1), (2.0, 2)]);
    st.create_derived(
        2,
        "text",
        ValueKind::String,
        &[dp(1.0, DataValue::String("x".into()))],
    )
    .unwrap();
    let before: Vec<_> = [1, 2]
        .iter()
        .flat_map(|f| st.series(*f).unwrap())
        .map(|s| {
            let p = debug_points(&*st, &s, None);
            (s, p)
        })
        .collect();
    drop(st);
    let st = ts_storage::open(&env.path).unwrap();
    for (s, p) in before {
        assert_eq!(st.series_by_id(s.id).unwrap().unwrap(), s);
        assert_eq!(debug_points(&*st, &s, None), p);
    }
}

pub fn derived_strings(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let text = [
        dp(1.0, DataValue::String(String::new())),
        dp(2.0, DataValue::String("it's \"q\"; --".into())),
        dp(3.0, DataValue::String("\u{e9}\u{2713}\u{1f600}".into())),
        dp(4.0, DataValue::String("long ".repeat(5000))),
    ];
    let s = st
        .create_derived(1, "text", ValueKind::String, &text)
        .unwrap();
    assert_eq!(s.value_type, ColType::Text);
    assert_eq!((s.n, s.v_min, s.v_max), (4, None, None));
    let got: Vec<String> = read(&*st, &s, None)
        .iter()
        .map(|p| p.value.as_string())
        .collect();
    let want: Vec<String> = text.iter().map(|p| p.value.as_string()).collect();
    assert_eq!(got, want);
}

/// A NaN value is storable in a derived series and ignored by the value range.
pub fn derived_nan_value_round_trips(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let pts = [
        dp(1.0, DataValue::Float(f64::NAN)),
        dp(2.0, DataValue::Float(0.5)),
    ];
    let s = st.create_derived(1, "f", ValueKind::Float, &pts).unwrap();
    assert_eq!((s.n, s.v_min, s.v_max), (2, Some(0.5), Some(0.5)));
    assert_eq!(debug_values(&*st, &s, None), ["Float(NaN)", "Float(0.5)"]);
}

pub fn derived_bool_float_int(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let bools = [
        dp(1.0, DataValue::Boolean(true)),
        dp(2.0, DataValue::Boolean(false)),
    ];
    let b = st
        .create_derived(1, "flag", ValueKind::Bool, &bools)
        .unwrap();
    assert_eq!(b.value_type, ColType::Bool);
    assert_eq!((b.v_min, b.v_max), (Some(0.0), Some(1.0)));
    assert_eq!(
        debug_values(&*st, &b, None),
        ["Boolean(true)", "Boolean(false)"]
    );

    let floats = [
        dp(1.0, DataValue::Float(-0.5)),
        dp(2.0, DataValue::Float(1e-300)),
    ];
    let f = st
        .create_derived(1, "ratio", ValueKind::Float, &floats)
        .unwrap();
    assert_eq!(f.value_type, ColType::F64);
    assert_eq!((f.v_min, f.v_max), (Some(-0.5), Some(1e-300)));
    assert_eq!(
        debug_values(&*st, &f, None),
        ["Float(-0.5)", "Float(1e-300)"]
    );

    let i = create_int(
        &*st,
        1,
        "ext",
        &[(1.0, i64::MIN), (2.0, i64::MAX), (3.0, 0)],
    );
    assert_eq!(ints(&*st, &i, None), [i64::MIN, i64::MAX, 0]);
    for s in [&b, &f, &i] {
        check_stats(&*st, s);
    }
}

// ---------------------------------------------------------------------------------------------
// Derived series: errors

pub fn derived_duplicate_name_exists(engine: Engine) {
    let (_env, st) = derived_db(engine);
    create_int(&*st, 1, "a", &[(1.0, 1)]);
    assert_err!(
        st.create_derived(1, "a", ValueKind::Int, &int_points(&[(1.0, 1)])),
        StoreError::Exists(_)
    );
    // Whatever the kind or the points.
    assert_err!(
        st.create_derived(1, "a", ValueKind::String, &[]),
        StoreError::Exists(_)
    );
}

pub fn derived_name_may_repeat_across_flows_and_raw_names(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let a = create_int(&*st, 1, "a", &[(1.0, 1)]);
    let b = create_int(&*st, 2, "a", &[(1.0, 1)]);
    assert_ne!(a.id, b.id);
    // Derived series live in their own source, so a raw series' name is free.
    st.create_derived(1, "w32", ValueKind::Int, &[]).unwrap();
}

pub fn derived_wrong_value_kind_is_a_type_mismatch(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let wrong = [dp(1.0, DataValue::Float(1.0))];
    assert_err!(
        st.create_derived(1, "w", ValueKind::Int, &wrong),
        StoreError::TypeMismatch(_)
    );
    let mixed = [
        dp(1.0, DataValue::Int(1)),
        dp(2.0, DataValue::String("x".into())),
    ];
    assert_err!(
        st.create_derived(1, "w", ValueKind::Int, &mixed),
        StoreError::TypeMismatch(_)
    );
    // A failed create leaves nothing behind.
    assert!(st.series(1).unwrap().iter().all(|s| s.name != "w"));
}

pub fn derived_non_finite_timestamp_is_a_type_mismatch(engine: Engine) {
    let (_env, st) = derived_db(engine);
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_err!(
            st.create_derived(1, "w", ValueKind::Int, &int_points(&[(bad, 1)])),
            StoreError::TypeMismatch(_)
        );
    }
    assert!(st.series(1).unwrap().iter().all(|s| s.name != "w"));
}

/// A replace that fails keeps the old series with its points and statistics.
pub fn derived_failed_replace_keeps_the_old_series(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let a = create_int(&*st, 1, "a", &[(1.0, 1), (2.0, 2)]);
    let wrong_kind = [dp(1.0, DataValue::Float(1.0))];
    assert_err!(
        st.replace_derived(&a, &wrong_kind),
        StoreError::TypeMismatch(_)
    );
    assert_err!(
        st.replace_derived(&a, &int_points(&[(f64::NAN, 1)])),
        StoreError::TypeMismatch(_)
    );
    // The bad point comes after a good one.
    assert_err!(
        st.replace_derived(&a, &int_points(&[(5.0, 5), (f64::INFINITY, 1)])),
        StoreError::TypeMismatch(_)
    );
    assert_eq!(st.series_by_id(a.id).unwrap().unwrap(), a);
    assert_eq!(ints(&*st, &a, None), [1, 2]);
}

fn raw_w32(st: &dyn Store) -> SeriesInfo {
    find(st, 1, "all", Dir::Send, "w32")
}

pub fn raw_series_cannot_be_replaced(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let raw = raw_w32(&*st);
    assert_err!(st.replace_derived(&raw, &[]), StoreError::NotDerived);
    assert_eq!(ints(&*st, &raw, None), [1]);
}

pub fn raw_series_cannot_be_deleted(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let raw = raw_w32(&*st);
    assert_err!(st.delete_derived(&raw), StoreError::NotDerived);
    assert_eq!(ints(&*st, &raw, None), [1]);
}

/// An info that claims `kind = Derived` for a raw row is still refused.
pub fn fake_derived_info_of_a_raw_series_is_not_derived(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let raw = raw_w32(&*st);
    let fake = SeriesInfo {
        kind: SeriesKind::Derived,
        ..raw.clone()
    };
    assert_err!(st.delete_derived(&fake), StoreError::NotDerived);
    assert_err!(st.replace_derived(&fake, &[]), StoreError::NotDerived);
    assert_eq!(ints(&*st, &raw, None), [1]);
}

/// An id that does not exist, or whose name or flow differ from the stored row.
pub fn missing_series_is_not_found(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let a = create_int(&*st, 1, "a", &[(1.0, 1)]);
    let ghost = SeriesInfo {
        id: 424_242,
        ..a.clone()
    };
    assert_err!(st.delete_derived(&ghost), StoreError::NotFound(_));
    assert_err!(st.replace_derived(&ghost, &[]), StoreError::NotFound(_));
    let renamed = SeriesInfo {
        name: "other".into(),
        ..a.clone()
    };
    assert_err!(st.replace_derived(&renamed, &[]), StoreError::NotFound(_));
    let moved = SeriesInfo {
        flow_id: 2,
        ..a.clone()
    };
    assert_err!(st.delete_derived(&moved), StoreError::NotFound(_));
    assert_eq!(st.series_by_id(a.id).unwrap().unwrap(), a);
}

/// The info of a deleted series.
pub fn stale_series_is_not_found(engine: Engine) {
    let (_env, st) = derived_db(engine);
    let a = create_int(&*st, 1, "a", &[(1.0, 1)]);
    st.delete_derived(&a).unwrap();
    assert_err!(st.delete_derived(&a), StoreError::NotFound(_));
    assert_err!(
        st.replace_derived(&a, &int_points(&[(1.0, 1)])),
        StoreError::NotFound(_)
    );
    // The stale replace did not resurrect it.
    assert!(st.series_by_id(a.id).unwrap().is_none());
}

// ---------------------------------------------------------------------------------------------
// Failures

pub fn nan_in_an_event_column_is_rejected(engine: Engine) {
    let env = Env::new();
    let session = session_with_tables(engine, &env);
    let nan = all_batch(&[
        AllRow {
            f: 1.0,
            ..row(1, Dir::Send, 1, 0)
        },
        AllRow {
            f: f64::NAN,
            ..row(1, Dir::Send, 2, 1)
        },
    ]);
    assert_err!(nan.validate(), StoreError::TypeMismatch(_));
    assert_err!(
        StatsAccumulator::new().observe(&nan),
        StoreError::TypeMismatch(_)
    );
    let mut w = session.writer().unwrap();
    assert_err!(w.write(nan), StoreError::TypeMismatch(_));
    // A valid batch after the rejected one is written; nothing of the rejected one is.
    let ok = all_batch(&[AllRow {
        f: 3.0,
        ..row(1, Dir::Send, 3, 2)
    }]);
    let mut acc = StatsAccumulator::new();
    acc.observe(&ok).unwrap();
    w.write(ok).unwrap();
    w.close().unwrap();
    finish_with(session, vec![flow(1, 1)], acc);
    let st = ts_storage::open(&env.path).unwrap();
    let f = find(&*st, 1, "all", Dir::Send, "f");
    assert_eq!(f.n, 1);
    assert_eq!(
        debug_points(&*st, &f, None),
        [(3.0, "Float(3.0)".to_string())]
    );
}

fn assert_nothing_left(env: &Env) {
    assert!(!env.path.exists());
    assert!(!env.partial().exists());
    assert_eq!(env.files(), Vec::<String>::new());
}

/// Dropped without `finish`, after writing.
pub fn abandoned_session_leaves_nothing(engine: Engine) {
    let env = Env::new();
    {
        let s = session_with_tables(engine, &env);
        let mut w = s.writer().unwrap();
        w.write(all_batch(&extreme_rows(1))).unwrap();
        w.close().unwrap();
        assert!(!env.path.exists(), "the file appears only on finish");
    }
    assert_nothing_left(&env);
    // The same right after creation.
    drop(ts_storage::create(engine, &env.path, CreateOptions::default()).unwrap());
    assert_nothing_left(&env);
}

/// The session is dropped while a writer that wrote rows is still open and unclosed.
pub fn abandoned_session_with_a_live_writer_leaves_nothing(engine: Engine) {
    let env = Env::new();
    let session = session_with_tables(engine, &env);
    let mut w = session.writer().unwrap();
    w.write(all_batch(&extreme_rows(1))).unwrap();
    drop(session);
    drop(w);
    assert_nothing_left(&env);
}

pub fn finished_file_has_no_sidecars(engine: Engine) {
    let env = Env::new();
    build_all(engine, &env.path, &extreme_rows(1), vec![flow(1, 1)]).unwrap();
    assert_eq!(env.files(), ["trace.db"]);
    drop(ts_storage::open(&env.path).unwrap());
    assert_eq!(env.files(), ["trace.db"]);
}

fn build_one_row(engine: Engine, env: &Env) {
    let rows = [row32(1, Dir::Send, 1, 0, 1)];
    build_all(engine, &env.path, &rows, vec![flow(1, 1)]).unwrap();
}

fn one_row_value(env: &Env) -> Vec<i64> {
    let st = ts_storage::open(&env.path).unwrap();
    ints(&*st, &find(&*st, 1, "all", Dir::Send, "w32"), None)
}

pub fn existing_file_needs_force(engine: Engine) {
    let env = Env::new();
    build_one_row(engine, &env);
    assert_err!(
        ts_storage::create(engine, &env.path, CreateOptions::default()),
        StoreError::Exists(_)
    );
    assert_eq!(one_row_value(&env), [1]);
}

/// Creating with `force` and abandoning the session keeps the old file.
pub fn force_keeps_the_old_file_until_finish(engine: Engine) {
    let env = Env::new();
    build_one_row(engine, &env);
    drop(ts_storage::create(engine, &env.path, CreateOptions { force: true }).unwrap());
    assert_eq!(one_row_value(&env), [1]);
    assert_eq!(env.files(), ["trace.db"]);
}

pub fn force_replaces_the_file_on_finish(engine: Engine) {
    let env = Env::new();
    build_one_row(engine, &env);
    let s = ts_storage::create(engine, &env.path, CreateOptions { force: true }).unwrap();
    s.create_tables(&[&ALL]).unwrap();
    s.finish(Catalog::default()).unwrap();
    let st = ts_storage::open(&env.path).unwrap();
    assert!(st.flows().unwrap().is_empty());
    assert_eq!(env.files(), ["trace.db"]);
}

pub fn schema_v1_file_is_unsupported(engine: Engine) {
    let env = Env::new();
    make_v1(engine, &env.path);
    assert_err!(
        ts_storage::open(&env.path),
        StoreError::UnsupportedSchema { found: None }
    );
}

// ---------------------------------------------------------------------------------------------
// Engine independent failures

pub fn non_database_files_are_unknown() {
    let env = Env::new();
    for (name, bytes) in [
        ("empty", &b""[..]),
        ("text", b"this is not a database file at all"),
        ("short", b"SQLite"),
        ("zeros", &[0u8; 4096][..]),
    ] {
        let p = env.write_file(name, bytes);
        assert_err!(ts_storage::open(&p), StoreError::UnknownEngine);
    }
    // A missing file is an I/O error, not an unknown engine.
    assert_err!(ts_storage::open(&env.file("missing")), StoreError::Io(_));
}

/// A file of an engine this build does not have; only its header is looked at.
#[allow(dead_code)]
pub fn file_of_a_disabled_engine(engine: Engine) {
    assert!(!engine.is_enabled());
    let env = Env::new();
    let mut bytes = match engine {
        Engine::DuckDb => [&[0u8; 8][..], b"DUCK"].concat(),
        Engine::Sqlite => b"SQLite format 3\0".to_vec(),
    };
    bytes.extend([0u8; 4096]);
    let p = env.write_file("disabled.db", &bytes);
    assert_err!(ts_storage::open(&p), StoreError::EngineDisabled(e) if e == engine);
    assert_err!(
        ts_storage::create(engine, &env.file("new.db"), CreateOptions::default()),
        StoreError::EngineDisabled(e) if e == engine
    );
}
