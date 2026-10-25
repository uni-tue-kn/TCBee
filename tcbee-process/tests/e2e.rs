//! End-to-end tests of the pipeline on the fixtures in `tests/fixtures` (see its README).

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use tcbee_process::{run, Args, Engine, Summary, UNIT_RECORDS};
use ts_storage::{SeriesKind, Store};

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
    ("mptcp_pm.tcp", "mptcp_pm", 0, 12, 17),
    ("cubic.tcp", "cubic", 0, 2000, 14),
    ("tcp_probe.tcp", "tcp_probe", 0, 2000, 10),
    ("send_sock.tcp", "sock", 1, 2000, 25),
    ("recv_sock.tcp", "sock", 2, 2000, 25),
    ("send_cwnd.tcp", "cwnd", 1, 1000, 1),
    ("tcp4_send.tcp", "tcp4", 1, 2000, 4),
    ("tcp4_receive.tcp", "tcp4", 2, 2000, 4),
    ("tcp6_send.tcp", "tcp6", 1, 500, 4),
    ("tcp6_receive.tcp", "tcp6", 2, 500, 4),
    ("send_sock_oc.tcp", "sock_oc", 1, 200, 25),
    ("send_cwnd_oc.tcp", "cwnd_oc", 1, 200, 1),
];

/// Size of one `tcp4` record in the trace file.
const TCP4_RECORD: usize = 52;
/// Size of the old `tcp4` records of the fixture, without `ecn` and `tstamp` (9 bytes before the
/// divider).
const TCP4_FIXTURE_RECORD: usize = 43;
/// Byte offsets inside a `tcp4` record: `time` and `hook_seq` (u64) first, `seq` (u32) after both
/// addresses and both ports, the divider in the last four bytes.
const TCP4_SEQ_OFFSET: usize = 28;

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
        let store = ts_storage::open(&out).unwrap();
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

/// The manifest of an on-change recording becomes `sampling.<source>.<dir>` catalog meta.
#[test]
fn manifest_tags_on_change_series() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let trace = tmp.path().join("tcbee_2026-01-01T00-00-00");
        std::fs::create_dir(&trace).unwrap();
        for f in std::fs::read_dir(fixture("tcbee_small")).unwrap() {
            let f = f.unwrap().path();
            std::fs::copy(&f, trace.join(f.file_name().unwrap())).unwrap();
        }
        std::fs::write(
            trace.join("manifest.json"),
            r#"{"format_version": 2, "sources": [{"file": "send_sock_oc.tcp",
               "sampling": {"mode": "on_change", "fields": ["snd_cwnd", "rto"]},
               "shadow": false, "recv_hook": "fexit/tcp_rcv_established"}]}"#,
        )
        .unwrap();
        let (out, summary) = process(engine, ext, tmp.path(), &trace, None);
        assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
        let meta = ts_storage::open(&out).unwrap().meta().unwrap();
        assert!(meta.contains(&(
            "sampling.sock_oc.1".to_string(),
            "on_change(snd_cwnd,rto)".to_string()
        )));
        assert!(!meta.iter().any(|(k, _)| k == "sampling.cwnd_oc.1"));
    }
}

/// On-change files land in their own source, never in the full series of the same flow.
#[test]
fn on_change_sock_is_a_separate_series() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, _) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        let store = ts_storage::open(&out).unwrap();
        let mut found = false;
        for f in store.flows().unwrap() {
            let series = store.series(f.id).unwrap();
            let cwnd = |source: &str| {
                series
                    .iter()
                    .find(|s| s.source == source && s.name == "snd_cwnd" && s.dir.code() == 1)
                    .map(|s| (s.id, s.n))
            };
            if let (Some(full), Some(oc)) = (cwnd("sock"), cwnd("sock_oc")) {
                found = true;
                assert_ne!(full.0, oc.0);
                assert!(oc.1 <= full.1);
            }
        }
        assert!(found, "no flow with full and on-change sock data");
    }
}

#[test]
fn send_and_receive_sock_are_separate_series() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, _) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        let store = ts_storage::open(&out).unwrap();
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

/// Sock records in the current layout have series for the added fields; the old-layout
/// fixture has none of them, as its records hold 0 there.
#[test]
fn added_sock_fields_are_series_only_where_recorded() {
    use tcbee_common::records::sock_trace_entry;
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let trace = tmp.path().join("tcbee_current");
        fs::create_dir_all(&trace).unwrap();
        let recs: Vec<_> = (0..4u64)
            .map(|i| sock_trace_entry {
                time: 1_000 + i,
                hook_seq: i + 1,
                addr_v4: 0x0200_000A_0100_000A,
                sport: 40000,
                dport: 5201,
                family: 2,
                ca_state: if i == 2 { 4 } else { 0 },
                delivered: 10 * i as u32,
                ..Default::default()
            })
            .collect();
        write_records(&trace, "send_sock.tcp", &recs);
        let (out, summary) = process(engine, ext, tmp.path(), &trace, None);
        assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
        let store = ts_storage::open(&out).unwrap();
        let series = store.series(1).unwrap();
        let ca = series.iter().find(|s| s.name == "ca_state").unwrap();
        assert_eq!((ca.n, ca.v_max), (4, Some(4.0)));
        let delivered = series.iter().find(|s| s.name == "delivered").unwrap();
        assert_eq!(delivered.v_max, Some(30.0));

        let old = tempfile::tempdir().unwrap();
        let (out, _) = process(engine, ext, old.path(), &fixture("tcbee_small"), None);
        let store = ts_storage::open(&out).unwrap();
        for f in store.flows().unwrap() {
            let names: Vec<String> = store
                .series(f.id)
                .unwrap()
                .into_iter()
                .filter(|s| s.source == "sock")
                .map(|s| s.name)
                .collect();
            assert!(!names.iter().any(|n| n == "ca_state" || n == "delivered"));
            assert!(names.is_empty() || names.iter().any(|n| n == "snd_cwnd"));
        }
        // The ids stay dense after leaving series out
        let all: Vec<i64> = store
            .flows()
            .unwrap()
            .iter()
            .flat_map(|f| store.series(f.id).unwrap())
            .map(|s| s.id)
            .collect();
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(sorted, (1..=all.len() as i64).collect::<Vec<_>>());
    }
}

/// TCP events become rows of their flow with a text series of labels, the markers of the
/// visualizer.
#[test]
fn tcp_events_become_labelled_series() {
    use tcbee_common::records::{
        tcp_event_entry, TCBEE_TCP_CA_STATE, TCBEE_TCP_RETRANSMIT, TCBEE_TCP_RTO,
    };
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let trace = tmp.path().join("tcbee_events");
        fs::create_dir_all(&trace).unwrap();
        let ev = |i: u64, kind, old_state, new_state| tcp_event_entry {
            time: 1_000 + i,
            hook_seq: i + 1,
            addr_v4: 0x0200_000A_0100_000A,
            sport: 40000,
            dport: 5201,
            family: 2,
            kind: kind as u8,
            old_state,
            new_state,
            ..Default::default()
        };
        let recs = [
            ev(0, TCBEE_TCP_RETRANSMIT, 0, 0),
            ev(1, TCBEE_TCP_CA_STATE, 0, 4),
            ev(2, TCBEE_TCP_RTO, 0, 0),
        ];
        write_records(&trace, "tcp_events.tcp", &recs);
        let (out, summary) = process(engine, ext, tmp.path(), &trace, None);
        assert_eq!(summary.rows, 3);
        let store = ts_storage::open(&out).unwrap();
        let flows = store.flows().unwrap();
        assert_eq!(flows.len(), 1);
        let series = store.series(flows[0].id).unwrap();
        let event = series
            .iter()
            .find(|s| s.source == "tcp_event" && s.name == "event")
            .unwrap();
        let mut labels = Vec::new();
        store
            .for_each_point(event, None, &mut |p| labels.push(format!("{:?}", p.value)))
            .unwrap();
        assert_eq!(
            labels,
            [
                "String(\"retransmit\")",
                "String(\"Open → Loss\")",
                "String(\"RTO\")"
            ]
        );
    }
}

/// Drops are labelled with the names of the recorder's drop reasons, which also become meta
/// rows; a reason the recording does not name keeps its number.
#[test]
fn drops_are_labelled_with_the_reason_names() {
    use tcbee_common::records::{tcp_event_entry, TCBEE_TCP_DROP};
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let trace = tmp.path().join("tcbee_drops");
        fs::create_dir_all(&trace).unwrap();
        let drop = |i: u64, reason| tcp_event_entry {
            time: 1_000 + i,
            hook_seq: i + 1,
            addr_v4: 0x0200_000A_0100_000A,
            sport: 40000,
            dport: 5201,
            family: 2,
            kind: TCBEE_TCP_DROP as u8,
            reason,
            ..Default::default()
        };
        write_records(
            &trace,
            "tcp_events.tcp",
            &[drop(0, 3), drop(1, 77), drop(2, 0x10002)],
        );
        fs::write(
            trace.join(tcbee_trace::DROP_REASONS_FILE),
            r#"{"2": "NOT_SPECIFIED", "3": "NO_SOCKET"}"#,
        )
        .unwrap();
        let (out, summary) = process(engine, ext, tmp.path(), &trace, Some(2));
        assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
        let store = ts_storage::open(&out).unwrap();
        let meta: BTreeMap<String, String> = store.meta().unwrap().into_iter().collect();
        assert_eq!(meta["drop_reason.3"], "NO_SOCKET");
        let series = store.series(1).unwrap();
        let event = series.iter().find(|s| s.name == "event").unwrap();
        let mut labels = Vec::new();
        store
            .for_each_point(event, None, &mut |p| labels.push(format!("{:?}", p.value)))
            .unwrap();
        assert_eq!(
            labels,
            [
                "String(\"drop NO_SOCKET\")",
                "String(\"drop, reason 77\")",
                "String(\"drop, reason 0x10002\")"
            ]
        );
    }
}

#[test]
fn engines_and_thread_counts_agree_point_by_point() {
    let mut dumps = Vec::new();
    for (engine, ext) in engines() {
        for threads in [Some(1), Some(4)] {
            let tmp = tempfile::tempdir().unwrap();
            let (out, _) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), threads);
            let store = ts_storage::open(&out).unwrap();
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

/// FNV-1a, a hash that stays the same across Rust releases (unlike `DefaultHasher`).
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Hash of every flow tuple, and per "source|dir" the hash of its series in key order.
fn digests(d: &Dump) -> BTreeMap<String, u64> {
    let mut groups: BTreeMap<String, String> = BTreeMap::new();
    groups.insert("flows".into(), d.flows.join("\n"));
    for (key, series) in &d.series {
        let fields: Vec<&str> = key.split('|').collect();
        groups
            .entry(format!("{}|{}", fields[1], fields[2]))
            .or_default()
            .push_str(&format!("{key}={series:?}\n"));
    }
    groups
        .into_iter()
        .map(|(group, text)| (group, fnv1a(text.as_bytes())))
        .collect()
}

/// Digests of tcbee_small as decoded at the time this test was written. A change means that some
/// value read from the fixture changed: on purpose (update the table) or by mistake.
const SMALL_DIGESTS: &[(&str, u64)] = &[
    ("bbr|0", 5969312066039208668),
    ("cubic|0", 18293315105502254295),
    ("cwnd_oc|1", 5004497889326637478),
    ("cwnd|1", 10154183732297103522),
    ("flows", 17654629037281800754),
    ("mptcp_pm|0", 603747683927564092),
    ("sock_oc|1", 8171228002259875761),
    ("sock|1", 3144412637236659025),
    ("sock|2", 6540169290698444424),
    ("tcp4|1", 16532087506000249234),
    ("tcp4|2", 6241242892840854424),
    ("tcp6|1", 16373615277353532148),
    ("tcp6|2", 17698873937259955636),
    ("tcp_probe|0", 438283687335302762),
];

#[test]
fn small_fixture_decodes_to_the_golden_digests() {
    let expected: BTreeMap<String, u64> = SMALL_DIGESTS
        .iter()
        .map(|(group, digest)| (group.to_string(), *digest))
        .collect();
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, _) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        let store = ts_storage::open(&out).unwrap();
        let actual = digests(&dump(&*store));
        assert_eq!(actual, expected, "{engine:?}");
    }
}

/// The two generated MPTCP connections of tcbee_small, one per flow, with the flow as subflow 1.
#[test]
fn small_fixture_groups_mptcp_connections() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, summary) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        assert_eq!(summary.connections, 2);
        let store = ts_storage::open(&out).unwrap();
        let flows = store.flows().unwrap();
        let sport = |flow_id| flows.iter().find(|f| f.id == flow_id).unwrap().tuple.sport;
        let conns = store.connections().unwrap();
        let keys: Vec<(String, i64)> = conns.iter().map(|c| (c.kind.clone(), c.key)).collect();
        assert_eq!(keys, [("mptcp".into(), 0x1000), ("mptcp".into(), 0x1001)]);
        assert!(conns
            .iter()
            .all(|c| c.flow_id.is_none() && c.start_ts < c.end_ts));
        let members: Vec<(i64, i64, Option<i64>)> = store
            .connection_flows()
            .unwrap()
            .iter()
            .map(|m| (m.connection_id, sport(m.flow_id), m.subflow_id))
            .collect();
        assert_eq!(
            members,
            [(1, 40000, Some(1)), (2, 40001, Some(1))],
            "{engine:?}"
        );
    }
}

#[test]
fn u64_max_is_saturated_and_stats_describe_read_values() {
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let (out, _) = process(engine, ext, tmp.path(), &fixture("tcbee_small"), None);
        let store = ts_storage::open(&out).unwrap();
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
        let store = ts_storage::open(&out).unwrap();
        let points: usize = dump(&*store).series.values().map(|s| s.points.len()).sum();
        assert_eq!(points, 10 * 25);
    }
}

/// Writes `recs` as the trace file `file` (bincode plus divider, as the recorder does).
fn write_records<T: serde::Serialize>(trace: &Path, file: &str, recs: &[T]) {
    let mut bytes = Vec::new();
    for r in recs {
        bytes.extend_from_slice(&bincode::serialize(r).unwrap());
        bytes.extend_from_slice(&tcbee_common::records::RECORD_DELIMITER);
    }
    fs::write(trace.join(file), bytes).unwrap();
}

/// Both ends of one connection recorded on one host: the client's MPTCP subflow carries its
/// token, the server end is a plain TCP socket (it fell back). The server's flow is the
/// reversed tuple of the subflow and must not join the client's connection, whichever socket
/// records describe it.
#[test]
fn plain_tcp_socket_on_the_reversed_tuple_stays_out_of_the_connection() {
    use tcbee_common::records::{sock_trace_entry, tcp_probe_entry};
    const AF_INET: u16 = 2;
    let (client, server) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    // addr_v4 as the recorder stores it: local address in the high half
    let addr_v4 = |local: [u8; 4], remote: [u8; 4]| {
        ((u32::from_le_bytes(local) as u64) << 32) | u32::from_le_bytes(remote) as u64
    };
    let sock = |i: u64, local, remote, sport, dport, conn_id| sock_trace_entry {
        time: 1_000 + i,
        hook_seq: i + 1,
        addr_v4: addr_v4(local, remote),
        sport,
        dport,
        family: AF_INET,
        conn_id,
        ..Default::default()
    };
    let subflow: Vec<_> = (0..3)
        .map(|i| sock(i, client, server, 40000, 5201, 7))
        .collect();
    // sockaddr_in in the first bytes of saddr/daddr: family, port, address
    let sockaddr = |addr: [u8; 4]| {
        let mut a = [0u8; 28];
        a[4..8].copy_from_slice(&addr);
        a
    };
    let probe = |i: u64| tcp_probe_entry {
        time: 1_000 + i,
        hook_seq: i + 1,
        saddr: sockaddr(server),
        daddr: sockaddr(client),
        sport: 5201,
        dport: 40000,
        family: AF_INET,
        ..Default::default()
    };
    let server_socks: Vec<_> = (0..3)
        .map(|i| sock(i, server, client, 5201, 40000, 0))
        .collect();
    let server_probes: Vec<_> = (0..3).map(probe).collect();
    for (name, server_file) in [("sock", "recv_sock.tcp"), ("tcp_probe", "tcp_probe.tcp")] {
        for (engine, ext) in engines() {
            let tmp = tempfile::tempdir().unwrap();
            let trace = tmp.path().join("tcbee_fallback");
            fs::create_dir_all(&trace).unwrap();
            write_records(&trace, "send_sock.tcp", &subflow);
            if name == "sock" {
                write_records(&trace, server_file, &server_socks);
            } else {
                write_records(&trace, server_file, &server_probes);
            }
            let (out, summary) = process(engine, ext, tmp.path(), &trace, None);
            assert_eq!(summary.connections, 1, "{name} {engine:?}");
            let store = ts_storage::open(&out).unwrap();
            let flows = store.flows().unwrap();
            let members: Vec<i64> = store
                .connection_flows()
                .unwrap()
                .iter()
                .map(|m| {
                    flows
                        .iter()
                        .find(|f| f.id == m.flow_id)
                        .unwrap()
                        .tuple
                        .sport
                })
                .collect();
            assert_eq!(
                members,
                [40000],
                "{name} {engine:?}: only the client subflow"
            );
        }
    }
}

/// The owner records and the snapshot become rows of flow_owners, on the flow of their tuple and
/// on the reversed one; an owner without a flow is counted
#[test]
fn owners_are_joined_to_their_flows() {
    use tcbee_common::records::{flow_owner_entry, sock_trace_entry, TCBEE_OWNER_CONNECT};
    use tcbee_trace::owners::{FlowOwners, ProcessInfo, SnapshotConnection};
    const AF_INET: u16 = 2;
    let addr_v4 = |local: [u8; 4], remote: [u8; 4]| {
        ((u32::from_le_bytes(local) as u64) << 32) | u32::from_le_bytes(remote) as u64
    };
    let (client, server) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let sock = |i: u64, local, remote, sport, dport| sock_trace_entry {
        time: 1_000 + i,
        hook_seq: i + 1,
        addr_v4: addr_v4(local, remote),
        sport,
        dport,
        family: AF_INET,
        ..Default::default()
    };
    let mut comm = [0u8; 16];
    comm[..4].copy_from_slice(b"curl");
    let owner = |time, sport| flow_owner_entry {
        time,
        hook_seq: 1,
        addr_v4: addr_v4(client, server),
        sport,
        dport: 443,
        family: AF_INET,
        kind: TCBEE_OWNER_CONNECT as u8,
        pid: 42,
        start_time: 1_230_000_000,
        comm,
        ..Default::default()
    };
    for (engine, ext) in engines() {
        let tmp = tempfile::tempdir().unwrap();
        let trace = tmp.path().join("tcbee_owners");
        fs::create_dir_all(&trace).unwrap();
        // Both directions of the connection of port 40000, nothing of port 40001
        write_records(
            &trace,
            "send_sock.tcp",
            &[
                sock(0, client, server, 40000, 443),
                sock(1, client, server, 50000, 22),
            ],
        );
        write_records(
            &trace,
            "recv_sock.tcp",
            &[sock(2, server, client, 443, 40000)],
        );
        write_records(
            &trace,
            "flow_owners.tcp",
            &[owner(900, 40000), owner(901, 40001)],
        );
        let mut json = FlowOwners::new(500, 100);
        json.connections.push(SnapshotConnection {
            local: "10.0.0.1:50000".parse().unwrap(),
            remote: "10.0.0.2:22".parse().unwrap(),
            netns: 7,
            state: "ESTABLISHED".into(),
            uid: 1000,
            inode: 9,
            pids: vec![7],
        });
        json.processes.push(ProcessInfo {
            pid: 42,
            start_ticks: 123,
            comm: "curl".into(),
            cmdline: vec!["curl".into(), "https://10.0.0.2".into()],
            ..ProcessInfo::default()
        });
        json.processes.push(ProcessInfo {
            pid: 7,
            start_ticks: 1,
            comm: "ssh".into(),
            ..ProcessInfo::default()
        });
        json.write(&trace).unwrap();

        let (out, summary) = process(engine, ext, tmp.path(), &trace, None);
        assert!(summary.skipped.is_empty(), "{:?}", summary.skipped);
        assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
        assert_eq!(
            (summary.owners, summary.unmatched_owners),
            (3, 1),
            "{engine:?}"
        );
        let store = ts_storage::open(&out).unwrap();
        let flows = store.flows().unwrap();
        let port = |id: i64| flows.iter().find(|f| f.id == id).unwrap().tuple.sport;
        let mut got: Vec<_> = store
            .flow_owners()
            .unwrap()
            .into_iter()
            .map(|o| (port(o.flow_id), o.comm, o.source, o.cmdline))
            .collect();
        got.sort();
        let curl = Some("curl https://10.0.0.2".to_string());
        assert_eq!(
            got,
            [
                (443, "curl".into(), "connect".into(), curl.clone()),
                (40000, "curl".into(), "connect".into(), curl),
                (50000, "ssh".into(), "snapshot".into(), None),
            ],
            "{engine:?}"
        );
    }
}

/// Writes a `tcp4_send.tcp` of `total` records of one flow into a new trace directory. Record `i`
/// has `seq = i` and a timestamp that repeats three times (so ordering needs the record index),
/// built from the first fixture record in the current layout. `corrupt` lists records whose
/// divider is broken.
fn write_tcp4_trace(
    dir: &Path,
    name: &str,
    file: &str,
    total: usize,
    corrupt: &[usize],
) -> PathBuf {
    let trace = dir.join(name);
    fs::create_dir_all(&trace).unwrap();
    let fixture = fs::read(fixture("tcbee_small").join("tcp4_send.tcp")).unwrap();
    let mut template = fixture[..TCP4_FIXTURE_RECORD - 4].to_vec();
    template.extend_from_slice(&[0; 9]);
    template.extend_from_slice(&fixture[TCP4_FIXTURE_RECORD - 4..TCP4_FIXTURE_RECORD]);
    let mut bytes = Vec::with_capacity(total * TCP4_RECORD);
    for i in 0..total {
        let mut rec = template[..TCP4_RECORD].to_vec();
        rec[..8].copy_from_slice(&(1_000 + i as u64 / 3).to_le_bytes());
        rec[8..16].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        rec[TCP4_SEQ_OFFSET..TCP4_SEQ_OFFSET + 4].copy_from_slice(&(i as u32).to_le_bytes());
        if corrupt.contains(&i) {
            rec[TCP4_RECORD - 1] ^= 0xFF;
        }
        bytes.extend_from_slice(&rec);
    }
    fs::write(trace.join(file), bytes).unwrap();
    trace
}

/// The metadata file of the recorder ends up as `run.*` meta rows; a broken one is a warning.
#[test]
fn run_metadata_becomes_meta_rows() {
    for (engine, ext) in engines() {
        let dir = tempfile::tempdir().unwrap();
        let trace = write_tcp4_trace(dir.path(), "tcbee_meta", "tcp4_send.tcp", 3, &[]);
        fs::write(
            trace.join(tcbee_trace::METADATA_FILE),
            r#"{"format":1,"kernel":{"release":"6.8.0"},"interfaces":[{"name":"eth0"}]}"#,
        )
        .unwrap();
        let (out, summary) = process(engine, ext, dir.path(), &trace, None);
        assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
        let meta: BTreeMap<String, String> = ts_storage::open(&out)
            .unwrap()
            .meta()
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(meta["run.format"], "1");
        assert_eq!(meta["run.kernel.release"], "6.8.0");
        assert_eq!(meta["run.interfaces.0.name"], "eth0");
        assert!(meta.contains_key("writer"));

        fs::write(trace.join(tcbee_trace::METADATA_FILE), "{").unwrap();
        let out_dir = tempfile::tempdir().unwrap();
        let (out, summary) = process(engine, ext, out_dir.path(), &trace, None);
        assert_eq!(summary.warnings.len(), 1, "{:?}", summary.warnings);
        let meta = ts_storage::open(&out).unwrap().meta().unwrap();
        assert!(meta.iter().all(|(k, _)| !k.starts_with("run.")));
    }
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
        assert!(msg.contains("offset 156"), "{msg}");
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
        assert_eq!(ts_storage::open(&out).unwrap().engine(), engine);
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

/// A file of more than one unit: rows read back in (ts, seq) order give exactly the sequence
/// 0, 1, 2, ... (`SEQ_NUM` holds the record index, every 3 records share a timestamp and
/// hook_seq breaks the tie).
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

        let store = ts_storage::open(&out).unwrap();
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
