//! Cross-engine equivalence: one script on both engines, compared line by line.

use std::fmt::Write;
use std::path::Path;

use ts_storage::{
    open_store, DataValue, Dir, Engine, SeriesInfo, SeriesKind, Store, StoreError, ValueKind,
};

use crate::fixture::*;

/// A coarse, driver independent label of an error, so engines can be compared.
fn error_kind(e: &StoreError) -> &'static str {
    match e {
        StoreError::UnsupportedSchema { .. } => "UnsupportedSchema",
        StoreError::NotDerived => "NotDerived",
        StoreError::TypeMismatch(_) => "TypeMismatch",
        StoreError::NotFound(_) => "NotFound",
        StoreError::Corrupt(_) => "Corrupt",
        StoreError::Exists(_) => "Exists",
        StoreError::UnknownEngine => "UnknownEngine",
        StoreError::EngineDisabled(_) => "EngineDisabled",
        StoreError::WriterGone => "WriterGone",
        StoreError::Io(_) => "Io",
        _ => "Driver",
    }
}

/// The transcript of a script run.
#[derive(Default)]
struct Log(String);

impl Log {
    fn line(&mut self, text: impl std::fmt::Display) {
        writeln!(self.0, "{text}").unwrap();
    }

    /// Logs the outcome of an operation: the series, or the kind of the error.
    fn outcome(&mut self, what: &str, r: &Result<SeriesInfo, StoreError>) {
        match r {
            Ok(s) => self.line(format_args!("{what}: ok {s:?}")),
            Err(e) => self.line(format_args!("{what}: err {}", error_kind(e))),
        }
    }

    /// Everything observable through `Store`: flows, series, and every series' points in a
    /// number of ranges, including NaN and infinite bounds.
    fn dump(&mut self, st: &dyn Store) {
        let ranges = [
            None,
            Some((10.0, 20.0)),
            Some((10.5, 19.5)),
            Some((20.0, 20.0)),
            Some((30.0, 10.0)),
            Some((-1e30, 1e30)),
            Some((f64::NEG_INFINITY, f64::INFINITY)),
            Some((f64::NAN, 1e9)),
            Some((0.0, f64::NAN)),
        ];
        let mut flows = st.flows().unwrap();
        flows.sort_by_key(|f| f.id);
        for f in &flows {
            self.line(format_args!("{f:?}"));
            assert_eq!(
                format!("{:?}", st.flow(f.id).unwrap()),
                format!("{:?}", Some(f))
            );
        }
        self.line(format_args!(
            "flow 99: {:?}",
            st.flow(99).unwrap().map(|f| f.id)
        ));
        for fid in flows.iter().map(|f| f.id).chain([99]) {
            let mut series = st.series(fid).unwrap();
            series.sort_by_key(|s| s.id);
            for s in &series {
                self.line(format_args!("{s:?}"));
                let by_id = st.series_by_id(s.id).unwrap();
                self.line(format_args!("  by id: {}", by_id.as_ref() == Some(s)));
                for r in ranges {
                    self.line(format_args!("  {r:?}: {:?}", debug_points(st, s, r)));
                }
            }
        }
        self.line(format_args!("series 0: {:?}", st.series_by_id(0).unwrap()));
    }
}

/// Ingest: several batches in two tables, out of order, duplicates, extremes, an empty flow.
fn ingest(engine: Engine, path: &Path, log: &mut Log) {
    let mut rows = extreme_rows(1);
    let recv = extreme_rows(1).into_iter().map(|r| AllRow {
        dir: Dir::Recv,
        ts: r.ts + 5,
        seq: r.seq + 100,
        ..r
    });
    rows.extend(recv);
    rows.push(row32(1, Dir::None, 20, 5, 7));
    rows.push(row32(1, Dir::None, 20, 4, 8));
    rows.push(AllRow {
        i: -9,
        f: -0.5,
        ..row32(2, Dir::Send, 20, 0, 9)
    });
    let second = [
        AllRow {
            b: true,
            f: 1.5,
            t: "late".into(),
            ..row(2, Dir::Send, 15, 1)
        },
        AllRow {
            f: -2.0,
            ..row(2, Dir::Send, 15, 2)
        },
    ];
    let other = other_batch(&[
        (1, Dir::Send, 1, 0, 5, "a"),
        (1, Dir::Send, 1, 1, 6, ""),
        (2, Dir::Recv, 9, 0, u32::MAX, "z"),
    ]);
    let r = build(
        engine,
        path,
        &[&ALL, &OTHER],
        vec![all_batch(&rows), all_batch(&second), other],
        vec![flow(1, 1000), flow_v6_to_v4(2, 2000), flow(3, 3000)],
    );
    log.line(format_args!("ingest: {:?}", r.as_ref().map_err(error_kind)));
    r.unwrap();
}

/// Derived series: every operation, successes and failures, including probes where the
/// behaviour is not specified (NaN values, unknown flow, huge timestamps).
fn derived_ops(st: &dyn Store, log: &mut Log) {
    let strings = [
        dp(1.0, DataValue::String("a'b".into())),
        dp(2.0, DataValue::String(String::new())),
    ];
    let infs = [
        dp(1.0, DataValue::Float(0.0)),
        dp(2.0, DataValue::Float(f64::INFINITY)),
    ];
    let nan_value = [
        dp(1.0, DataValue::Float(f64::NAN)),
        dp(2.0, DataValue::Float(1.0)),
    ];
    let create =
        |flow, name, ty, pts: &[ts_storage::DataPoint]| st.create_derived(flow, name, ty, pts);

    let a = create(
        1,
        "a",
        ValueKind::Int,
        &int_points(&[(3.0, 3), (1.0, 1), (1.0, 2), (1.4, 5), (2.5, 6)]),
    );
    log.outcome("create a", &a);
    log.outcome("create a again", &create(1, "a", ValueKind::Int, &[]));
    log.outcome(
        "create text",
        &create(1, "txt", ValueKind::String, &strings),
    );
    log.outcome(
        "create flag",
        &create(
            2,
            "flag",
            ValueKind::Bool,
            &[dp(1.0, DataValue::Boolean(true))],
        ),
    );
    log.outcome("create float", &create(2, "fl", ValueKind::Float, &infs));
    log.outcome(
        "create float nan value",
        &create(2, "fnan", ValueKind::Float, &nan_value),
    );
    log.outcome("create empty", &create(3, "empty", ValueKind::Int, &[]));
    log.outcome(
        "create in unknown flow",
        &create(99, "x", ValueKind::Int, &int_points(&[(1.0, 1)])),
    );
    log.outcome(
        "create huge ts",
        &create(
            3,
            "huge",
            ValueKind::Int,
            &int_points(&[(1e19, 1), (-1e19, 2)]),
        ),
    );
    log.outcome(
        "create wrong kind",
        &create(1, "w", ValueKind::Int, &[dp(1.0, DataValue::Float(1.0))]),
    );
    log.outcome(
        "create nan ts",
        &create(1, "w", ValueKind::Int, &int_points(&[(f64::NAN, 1)])),
    );
    log.outcome(
        "create inf ts",
        &create(1, "w", ValueKind::Int, &int_points(&[(f64::INFINITY, 1)])),
    );

    let a = a.unwrap();
    log.outcome(
        "replace a",
        &st.replace_derived(&a, &int_points(&[(8.0, -8), (9.0, 8)])),
    );
    log.outcome(
        "replace a wrong kind",
        &st.replace_derived(&a, &[dp(1.0, DataValue::Boolean(true))]),
    );
    log.outcome(
        "replace a nan ts",
        &st.replace_derived(&a, &int_points(&[(f64::NAN, 1)])),
    );

    let raw = st
        .series(1)
        .unwrap()
        .into_iter()
        .find(|s| s.kind == SeriesKind::Raw)
        .unwrap();
    log.outcome("replace raw", &st.replace_derived(&raw, &[]));
    log.outcome("delete raw", &st.delete_derived(&raw).map(|_| raw.clone()));
    let ghost = SeriesInfo {
        id: 777,
        ..a.clone()
    };
    log.outcome("replace ghost", &st.replace_derived(&ghost, &[]));
    log.outcome(
        "delete ghost",
        &st.delete_derived(&ghost).map(|_| ghost.clone()),
    );
    let moved = SeriesInfo {
        flow_id: 2,
        ..a.clone()
    };
    log.outcome(
        "delete moved",
        &st.delete_derived(&moved).map(|_| moved.clone()),
    );

    let fl = st
        .series(2)
        .unwrap()
        .into_iter()
        .find(|s| s.name == "fl")
        .unwrap();
    log.outcome("delete fl", &st.delete_derived(&fl).map(|_| fl.clone()));
    log.outcome(
        "delete fl again",
        &st.delete_derived(&fl).map(|_| fl.clone()),
    );
    log.outcome(
        "recreate fl",
        &create(2, "fl", ValueKind::Int, &int_points(&[(1.0, 1)])),
    );
}

fn script(engine: Engine, path: &Path) -> String {
    let mut log = Log::default();
    ingest(engine, path, &mut log);
    let st = open_store(path).unwrap();
    log.line("dump after ingest");
    log.dump(&*st);
    derived_ops(&*st, &mut log);
    log.line("dump after derived operations");
    log.dump(&*st);
    // A fresh handle sees the same.
    drop(st);
    let st = open_store(path).unwrap();
    log.line("dump after reopen");
    log.dump(&*st);
    log.0
}

/// Fails with the first differing line and a few lines of context from both transcripts.
fn assert_same(sqlite: &str, duckdb: &str) {
    let (a, b): (Vec<_>, Vec<_>) = (sqlite.lines().collect(), duckdb.lines().collect());
    let Some(i) = (0..a.len().max(b.len())).find(|&i| a.get(i) != b.get(i)) else {
        return;
    };
    let context = |l: &[&str]| l[i.saturating_sub(3)..(i + 2).min(l.len())].join("\n");
    panic!(
        "transcripts differ at line {}\n--- sqlite\n{}\n--- duckdb\n{}",
        i + 1,
        context(&a),
        context(&b)
    );
}

/// The script's transcript is long; a much shorter one means a step silently did nothing.
const MIN_TRANSCRIPT_LINES: usize = 300;

#[test]
fn engines_are_observably_identical() {
    let (a, b) = (Env::new(), Env::new());
    let sqlite = script(Engine::Sqlite, &a.path);
    let duckdb = script(Engine::DuckDb, &b.path);
    assert!(sqlite.lines().count() > MIN_TRANSCRIPT_LINES);
    assert_same(&sqlite, &duckdb);
}

/// Signed zero: SQLite stores a REAL `-0.0` as `0.0`, DuckDB keeps the sign. Harmless for the
/// visualizer, so it is a known difference and not part of the script above.
#[test]
#[ignore = "known difference: SQLite stores -0.0 as 0.0, DuckDB keeps the sign"]
fn negative_zero_is_preserved_by_both_engines() {
    #[derive(Debug, PartialEq)]
    struct NegativeSigns {
        event_value: bool,
        event_v_min: bool,
        derived_value: bool,
        derived_v_min: bool,
    }
    let signs = |engine: Engine| {
        let env = Env::new();
        let rows = [AllRow {
            f: -0.0,
            ..row(1, Dir::Send, 1, 0)
        }];
        build_all(engine, &env.path, &rows, vec![flow(1, 1)]).unwrap();
        let st = open_store(&env.path).unwrap();
        let ev = find(&*st, 1, "all", Dir::Send, "f");
        let d = st
            .create_derived(1, "d", ValueKind::Float, &[dp(1.0, DataValue::Float(-0.0))])
            .unwrap();
        let d = st.series_by_id(d.id).unwrap().unwrap();
        let neg = |s: &SeriesInfo| {
            read(&*st, s, None)[0]
                .value
                .as_float()
                .unwrap()
                .is_sign_negative()
        };
        NegativeSigns {
            event_value: neg(&ev),
            event_v_min: ev.v_min.unwrap().is_sign_negative(),
            derived_value: neg(&d),
            derived_v_min: d.v_min.unwrap().is_sign_negative(),
        }
    };
    assert_eq!(signs(Engine::Sqlite), signs(Engine::DuckDb));
}
