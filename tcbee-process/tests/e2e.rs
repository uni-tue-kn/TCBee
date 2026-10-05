//! End-to-end tests of the pipeline on the fixtures in `tests/fixtures` (see its README).

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use tcbee_process::{run, Args, Engine, Summary, UNIT_RECORDS};
use ts_storage::{open_store, SeriesKind, Store};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Engines that this build includes, with a file extension for the output.
#[allow(clippy::vec_init_then_push, unused_mut)]
fn engines() -> Vec<(Engine, &'static str)> {
    let mut v = Vec::new();
    #[cfg(feature = "sqlite")]
    v.push((Engine::Sqlite, "sqlite"));
    #[cfg(feature = "duckdb")]
    v.push((Engine::DuckDb, "duck"));
    v
}

/// (file, source, dir code, records, columns) of tcbee_small; see the fixture README.
const SMALL: &[(&str, &str, u8, u64, usize)] = &[
    ("bbr.tcp", "bbr", 0, 500, 12),
    ("cubic.tcp", "cubic", 0, 2000, 14),
    ("tcp_probe.tcp", "tcp_probe", 0, 2000, 10),
    ("send_sock.tcp", "sock", 1, 2000, 25),
    ("recv_sock.tcp", "sock", 2, 2000, 25),
    ("send_cwnd.tcp", "cwnd", 1, 1000, 1),
    ("tcp4_send.tcp", "tcp4", 1, 2000, 4),
    ("tcp4_receive.tcp", "tcp4", 2, 2000, 4),
    ("tcp6_send.tcp", "tcp6", 1, 500, 4),
    ("tcp6_receive.tcp", "tcp6", 2, 500, 4),
];

/// Size of one `tcp4` record in the trace file.
const TCP4_RECORD: usize = 35;
/// Byte offsets inside a `tcp4` record: `time` (u64) first, `seq` (u32) after both addresses and
/// both ports, the divider in the last four bytes.
const TCP4_SEQ_OFFSET: usize = 20;

fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn stderr_of(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn process(
    engine: Engine,
    ext: &str,
    dir: &Path,
    source: &Path,
    threads: Option<usize>,
) -> (PathBuf, Summary) {
    let out = dir.join(format!("out.{ext}"));
    let mut args = Args::new(source, &out, engine);
    args.threads = threads;
    let summary = run(args).unwrap_or_else(|e| panic!("{engine:?}: {e:#}"));
    (out, summary)
}

/// What one series reads back as.
#[derive(Debug, PartialEq)]
struct SeriesDump {
    n: i64,
    t_min: Option<i64>,
    t_max: Option<i64>,
    value_type: String,
    v_min: Option<f64>,
    v_max: Option<f64>,
    /// Timestamp bits and the debug form of the value, in read order.
    points: Vec<(u64, String)>,
}

/// Everything readable through `Store`, keyed so that it does not depend on ids.
#[derive(Debug, PartialEq)]
struct Dump {
    /// Sorted debug forms of the flow tuples.
    flows: Vec<String>,
    /// "tuple|source|dir|name" -> series.
    series: BTreeMap<String, SeriesDump>,
}

fn dump(store: &dyn Store) -> Dump {
    let flows = store.flows().unwrap();
    let mut tuples: Vec<String> = flows.iter().map(|f| format!("{:?}", f.tuple)).collect();
    tuples.sort();
    let mut series = BTreeMap::new();
    for f in &flows {
        for s in store.series(f.id).unwrap() {
            assert_eq!(s.kind, SeriesKind::Raw);
            let mut points = Vec::new();
            store
                .for_each_point(&s, None, &mut |p| {
                    points.push((p.timestamp.to_bits(), format!("{:?}", p.value)))
                })
                .unwrap();
            assert_eq!(points.len() as i64, s.n, "{} n", s.name);
            let key = format!("{:?}|{}|{}|{}", f.tuple, s.source, s.dir.code(), s.name);
            let entry = SeriesDump {
                n: s.n,
                t_min: s.t_min,
                t_max: s.t_max,
                value_type: format!("{:?}", s.value_type),
                v_min: s.v_min,
                v_max: s.v_max,
                points,
            };
            assert!(series.insert(key, entry).is_none(), "duplicate series");
        }
    }
    Dump {
        flows: tuples,
        series,
    }
}

#[test]
fn small_fixture_summary_counts_records_and_rows() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, summary) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
        assert!(summary.skipped.is_empty());
        assert!(summary.output_bytes > 0);
        assert!(!summary.to_string().is_empty());

        let total: u64 = SMALL.iter().map(|x| x.3).sum();
        assert_eq!(summary.records, total);
        assert_eq!(summary.rows, total);
        let mut by_table: BTreeMap<&str, u64> = BTreeMap::new();
        for (_, source, _, records, _) in SMALL {
            *by_table.entry(source).or_default() += records;
        }
        assert_eq!(summary.rows_by_table, by_table);
        assert_eq!(summary.rows_by_table.values().sum::<u64>(), summary.rows);

        for (file, source, dir, records, _) in SMALL {
            let f = summary.files.iter().find(|f| f.file == *file).unwrap();
            assert_eq!(
                (f.source, f.dir.code(), f.records),
                (*source, *dir, *records)
            );
        }
    }
}

#[test]
fn small_fixture_series_cover_every_record() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, summary) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        let store = open_store(&out).unwrap();
        assert_eq!(store.engine(), engine);

        // (source.column, dir) -> rows per flow
        let mut per_group: BTreeMap<(String, u8), Vec<i64>> = BTreeMap::new();
        let flows = store.flows().unwrap();
        assert!(flows.len() >= 3, "{} flows", flows.len());
        assert_eq!(flows.len(), summary.flows);
        for f in &flows {
            assert_eq!(f.tuple.l4proto, 6);
            for s in store.series(f.id).unwrap() {
                assert!(s.n > 0);
                assert_eq!(s.tbl.as_deref(), Some(format!("ev_{}", s.source).as_str()));
                per_group
                    .entry((format!("{}.{}", s.source, s.name), s.dir.code()))
                    .or_default()
                    .push(s.n);
            }
        }
        // Per (source, dir) every column has one series per flow, and their rows add up to the
        // records of the file.
        for (_, source, dir, records, columns) in SMALL {
            let prefix = format!("{source}.");
            let group: Vec<_> = per_group
                .iter()
                .filter(|((name, d), _)| name.starts_with(&prefix) && d == dir)
                .collect();
            assert_eq!(group.len(), *columns, "{source} dir {dir}: columns");
            for (name, ns) in group {
                assert_eq!(ns.iter().sum::<i64>(), *records as i64, "{name:?}");
            }
        }
        assert_eq!(dump(&*store).series.len(), summary.series);
    }
}

#[test]
fn send_and_receive_sock_are_separate_series() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, _) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        let store = open_store(&out).unwrap();
        let mut found = false;
        for f in store.flows().unwrap() {
            let cwnd: Vec<_> = store
                .series(f.id)
                .unwrap()
                .into_iter()
                .filter(|s| s.source == "sock" && s.name == "snd_cwnd")
                .collect();
            let dirs: Vec<u8> = cwnd.iter().map(|s| s.dir.code()).collect();
            if dirs.contains(&1) && dirs.contains(&2) {
                found = true;
                assert_eq!(cwnd.len(), 2);
                assert_ne!(cwnd[0].id, cwnd[1].id);
                // Each direction is ordered on its own.
                for series in &cwnd {
                    let mut last = f64::MIN;
                    store
                        .for_each_point(series, None, &mut |p| {
                            assert!(p.timestamp >= last, "unordered series");
                            last = p.timestamp;
                        })
                        .unwrap();
                }
            }
        }
        assert!(found, "no flow with send and recv sock data");
    }
}

#[test]
fn engines_and_thread_counts_agree_point_by_point() {
    let mut dumps = Vec::new();
    for (engine, ext) in engines() {
        for threads in [Some(1), Some(4)] {
            let tmp = tempfile::tempdir().unwrap();
            let (out, _) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), threads);
            let store = open_store(&out).unwrap();
            dumps.push((format!("{engine:?} {threads:?}"), dump(&*store)));
        }
    }
    let (base_name, base) = &dumps[0];
    assert!(!base.series.is_empty());
    for (name, d) in &dumps[1..] {
        assert_eq!(d.flows, base.flows, "flows {name} vs {base_name}");
        assert_eq!(
            d.series.keys().collect::<Vec<_>>(),
            base.series.keys().collect::<Vec<_>>(),
            "series {name} vs {base_name}"
        );
        for (key, series) in &d.series {
            assert_eq!(series, &base.series[key], "{key}: {name} vs {base_name}");
        }
    }
}

#[test]
fn u64_max_is_saturated_and_stats_describe_read_values() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, _) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        let store = open_store(&out).unwrap();
        let saturated = store.flows().unwrap().iter().any(|f| {
            store.series(f.id).unwrap().iter().any(|s| {
                s.source == "sock"
                    && s.name == "max_pacing_rate"
                    && s.v_max == Some(i64::MAX as f64)
            })
        });
        assert!(saturated, "{engine:?}: u64::MAX not seen as i64::MAX");
    }
}

#[test]
fn truncated_tail_is_a_warning() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, summary) = process(engine, ext, tmp.path(), &fixture("tcbee_truncated"), None);
        assert_eq!((summary.records, summary.rows), (10, 10));
        assert_eq!(summary.warnings.len(), 1, "{:?}", summary.warnings);
        assert!(
            summary.warnings[0].contains("17 trailing bytes"),
            "{:?}",
            summary.warnings
        );
        let store = open_store(&out).unwrap();
        let points: usize = dump(&*store).series.values().map(|s| s.points.len()).sum();
        assert_eq!(points, 10 * 25);
    }
}

/// Writes a `tcp4_send.tcp` of `total` records of one flow into a new trace directory. Record `i`
/// has `seq = i` and a timestamp that repeats three times (so ordering needs the record index),
/// built from the first fixture record. `corrupt` lists records whose divider is broken.
fn write_tcp4_trace(
    dir: &Path,
    name: &str,
    file: &str,
    total: usize,
    corrupt: &[usize],
) -> PathBuf {
    let trace = dir.join(name);
    fs::create_dir_all(&trace).unwrap();
    let template = fs::read(fixture("tcbee_small").join("tcp4_send.tcp")).unwrap();
    let mut bytes = Vec::with_capacity(total * TCP4_RECORD);
    for i in 0..total {
        let mut rec = template[..TCP4_RECORD].to_vec();
        rec[..8].copy_from_slice(&(1_000 + i as u64 / 3).to_le_bytes());
        rec[TCP4_SEQ_OFFSET..TCP4_SEQ_OFFSET + 4].copy_from_slice(&(i as u32).to_le_bytes());
        if corrupt.contains(&i) {
            rec[TCP4_RECORD - 1] ^= 0xFF;
        }
        bytes.extend_from_slice(&rec);
    }
    fs::write(trace.join(file), bytes).unwrap();
    trace
}

/// A trace directory with one tcp4 file whose record 3 has a broken divider.
fn corrupt_trace(dir: &Path) -> PathBuf {
    write_tcp4_trace(dir, "tcbee_corrupt", "tcp4_send.tcp", 5, &[3])
}

/// Fails the test if the output, its `.partial` or any sidecar exists.
fn assert_no_output(out: &Path) {
    let name = out.file_name().unwrap().to_str().unwrap();
    let leftovers: Vec<_> = fs::read_dir(out.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(name))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

#[test]
fn corrupted_divider_fails_and_leaves_no_output() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let trace = corrupt_trace(tmp.path());
        let out = tmp.path().join(format!("out.{ext}"));
        let err = run(Args::new(&trace, &out, engine)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("tcp4_send.tcp"), "{msg}");
        assert!(msg.contains("offset 105"), "{msg}");
        assert!(msg.contains("divider"), "{msg}");
        assert_no_output(&out);
    }
}

/// The failing record sits in the second unit of one file while the other file's units are being
/// processed by other workers.
#[test]
fn error_deep_in_a_later_unit_aborts_the_run() {
    let total = UNIT_RECORDS as usize + 50_000;
    let bad = UNIT_RECORDS as usize + 40_000;
    let tmp = tempfile::tempdir().unwrap();
    let trace = write_tcp4_trace(tmp.path(), "tcbee_bad", "tcp4_send.tcp", total, &[bad]);
    fs::copy(trace.join("tcp4_send.tcp"), trace.join("tcp4_receive.tcp")).unwrap();
    // The receive copy is broken at the same place; the send file is the one reported first or
    // second, either way the run fails.
    for (engine, ext) in engines() {
        let out = tmp.path().join(format!("out.{ext}"));
        let mut args = Args::new(&trace, &out, engine);
        args.threads = Some(4);
        let err = run(args).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(".tcp"), "{msg}");
        assert!(
            msg.contains(&format!("offset {}", bad * TCP4_RECORD)),
            "{msg}"
        );
        assert_no_output(&out);
    }
}

/// Something else creates the output while the run is in progress: `finish` must refuse to
/// replace it.
#[test]
fn output_appearing_during_the_run_is_not_replaced() {
    let tmp = tempfile::tempdir().unwrap();
    let trace = write_tcp4_trace(
        tmp.path(),
        "tcbee_long",
        "tcp4_send.tcp",
        UNIT_RECORDS as usize + 200_000,
        &[],
    );
    for (engine, ext) in engines() {
        let out = tmp.path().join(format!("race.{ext}"));
        let partial = PathBuf::from(format!("{}.partial", out.display()));
        let done = std::sync::atomic::AtomicBool::new(false);
        let res = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::SeqCst) {
                    if partial.exists() {
                        fs::write(&out, b"squatter").unwrap();
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            });
            let res = run(Args::new(&trace, &out, engine));
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            res
        });
        match res {
            Err(e) => {
                assert_eq!(fs::read(&out).unwrap(), b"squatter", "{e:#}");
                assert!(!partial.exists());
            }
            Ok(_) => panic!("{engine:?}: the finished run replaced a file it did not create"),
        }
    }
}

#[test]
fn existing_output_without_force_fails_untouched_and_force_replaces() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join(format!("out.{ext}"));
        fs::write(&out, b"precious").unwrap();
        let err = run(Args::new(fixture("tcbee_small"), &out, engine)).unwrap_err();
        assert!(!format!("{err:#}").is_empty());
        assert_eq!(fs::read(&out).unwrap(), b"precious");
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);

        let mut args = Args::new(fixture("tcbee_small"), &out, engine);
        args.force = true;
        run(args).unwrap();
        assert_eq!(open_store(&out).unwrap().engine(), engine);
    }
}

/// With `--force`, a run that fails leaves the old file byte for byte as it was.
#[test]
fn forced_run_that_fails_keeps_the_old_file() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join(format!("out.{ext}"));
        run(Args::new(fixture("tcbee_small"), &out, engine)).unwrap();
        let before = fs::read(&out).unwrap();

        let trace = corrupt_trace(tmp.path());
        let mut args = Args::new(&trace, &out, engine);
        args.force = true;
        assert!(run(args).is_err());
        assert_eq!(fs::read(&out).unwrap(), before);
        // Only the output and the trace directory are left (no .partial).
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 2);
    }
}

#[test]
fn source_resolution() {
    let (engine, ext) = engines()[0];
    let tmp = tempfile::tempdir().unwrap();
    let one_file = fixture("tcbee_truncated").join("send_sock.tcp");
    // Any directory with trace files works, whatever its name.
    let renamed = tmp.path().join("my-recording");
    fs::create_dir(&renamed).unwrap();
    fs::copy(&one_file, renamed.join("send_sock.tcp")).unwrap();
    let out = tmp.path().join(format!("a.{ext}"));
    assert_eq!(run(Args::new(&renamed, &out, engine)).unwrap().records, 10);

    // A directory without trace files falls back to the latest tcbee_* below it.
    let base = tmp.path().join("base");
    fs::create_dir_all(base.join("tcbee_2020-01-01T00-00-00")).unwrap();
    let newer = base.join("tcbee_2021-01-01T00-00-00");
    fs::create_dir(&newer).unwrap();
    fs::copy(&one_file, newer.join("send_sock.tcp")).unwrap();
    let out = tmp.path().join(format!("b.{ext}"));
    let summary = run(Args::new(&base, &out, engine)).unwrap();
    assert_eq!(summary.records, 10);
    assert_eq!(summary.trace_dir, newer);

    // Nothing there at all.
    let empty = tmp.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let out = tmp.path().join(format!("c.{ext}"));
    assert!(run(Args::new(&empty, &out, engine)).is_err());
    assert!(run(Args::new(tmp.path().join("missing"), &out, engine)).is_err());
    assert_no_output(&out);
}

/// A file of more than one unit: record indexes must continue across units, so rows read back
/// in (ts, seq) order give exactly the sequence 0, 1, 2, ... (`SEQ_NUM` holds the record index).
#[test]
fn file_larger_than_one_unit_keeps_record_order() {
    let total = 2 * UNIT_RECORDS as usize + 50_000;
    let tmp = tempfile::tempdir().unwrap();
    let trace = write_tcp4_trace(tmp.path(), "tcbee_big", "tcp4_send.tcp", total, &[]);
    for (engine, ext) in engines() {
        let out = tmp.path().join(format!("out.{ext}"));
        let mut args = Args::new(&trace, &out, engine);
        args.threads = Some(3);
        let summary = run(args).unwrap();
        assert_eq!(
            (summary.records, summary.rows),
            (total as u64, total as u64)
        );

        let store = open_store(&out).unwrap();
        let flows = store.flows().unwrap();
        assert_eq!(flows.len(), 1);
        let series = store.series(flows[0].id).unwrap();
        let seq_series = series.iter().find(|s| s.name == "SEQ_NUM").unwrap();
        assert_eq!(seq_series.n, total as i64);
        let mut next = 0i64;
        let mut last_ts = f64::MIN;
        store
            .for_each_point(seq_series, None, &mut |p| {
                assert!(p.timestamp >= last_ts, "timestamps go backwards at {next}");
                last_ts = p.timestamp;
                assert_eq!(
                    p.value.as_int(),
                    Some(next),
                    "record order broken (duplicate or missing seq) at position {next}"
                );
                next += 1;
            })
            .unwrap();
        assert_eq!(next, total as i64);
    }
}

// --- the binary: exit codes

fn bin(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tcbee-process"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn bad_flags_exit_with_2() {
    for bad in [
        &[][..],
        &["-q", "-d"],
        &["-o", "x.unknown"],
        &["-q", "-t", "0"],
        &["--bogus"],
    ] {
        assert_eq!(bin(bad).status.code(), Some(2), "{bad:?}");
    }
    assert_eq!(bin(&["-h"]).status.code(), Some(0));
}

#[test]
fn binary_exit_codes() {
    let (_, ext) = engines()[0];
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join(format!("o.{ext}"));
    let small = fixture("tcbee_small");
    let ok = bin(&["-s", path_str(&small), "-o", path_str(&out), "-t", "2"]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr_of(&ok));
    assert!(stderr_of(&ok).contains("records"));
    let before = fs::read(&out).unwrap();

    let again = bin(&["-s", path_str(&small), "-o", path_str(&out)]);
    assert_eq!(again.status.code(), Some(1));
    assert_eq!(fs::read(&out).unwrap(), before);
    let forced = bin(&["-s", path_str(&small), "-o", path_str(&out), "-f"]);
    assert_eq!(forced.status.code(), Some(0));

    let trace = corrupt_trace(tmp.path());
    let bad_out = tmp.path().join(format!("bad.{ext}"));
    let bad = bin(&["-s", path_str(&trace), "-o", path_str(&bad_out)]);
    assert_eq!(bad.status.code(), Some(1));
    assert!(stderr_of(&bad).contains("divider"));
    assert_no_output(&bad_out);

    let truncated = fixture("tcbee_truncated");
    let t_out = tmp.path().join(format!("t.{ext}"));
    let trunc = bin(&["-s", path_str(&truncated), "-o", path_str(&t_out)]);
    assert_eq!(trunc.status.code(), Some(0));
    assert!(stderr_of(&trunc).contains("warning"));
}
