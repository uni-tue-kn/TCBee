//! Schema, `push_row` and decode tests for every binding. Expected values are literals; the
//! comparisons with the old `EventIndexer` (marked `WP6: delete`) go away with it.

use std::{fs, net::IpAddr, path::PathBuf};

use tcbee_trace::TraceFile;
use ts_storage::{ColType, ColumnData, Dir, EventBatch, IpTuple};

use super::*;
use crate::bindings::event_indexer::EventIndexer;
use crate::event::Event;
use crate::reader::FromBuffer;

const MAX: i128 = u64::MAX as i128;

fn fixture(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tcbee_small")
        .join(file)
}

fn cell(b: &EventBatch, col: usize, row: usize) -> i128 {
    match &b.columns()[col] {
        ColumnData::Bool(v) => v[row] as i128,
        ColumnData::U8(v) => v[row] as i128,
        ColumnData::U16(v) => v[row] as i128,
        ColumnData::U32(v) => v[row] as i128,
        ColumnData::U64(v) => v[row] as i128,
        ColumnData::I64(v) => v[row] as i128,
        other => panic!("unexpected column {other:?}"),
    }
}

fn tuple(src: &str, dst: &str, sport: i64, dport: i64) -> IpTuple {
    IpTuple {
        src: src.parse::<IpAddr>().unwrap(),
        dst: dst.parse::<IpAddr>().unwrap(),
        sport,
        dport,
        l4proto: 6,
    }
}

struct Expect {
    source: &'static str,
    entry_size: usize,
    /// "name:Type" in column order, verbatim from the old `get_field_name` and the field types.
    columns: &'static str,
    file: &'static str,
    records: usize,
    ts0: i64,
    key0: IpTuple,
    /// Record 0, in the column type's value domain (u64 as unsigned).
    row0: &'static [i128],
}

/// Schema, `push_row` and record 0 against literals.
fn check<E: Event + Default>(x: &Expect) {
    let table = E::TABLE;
    assert_eq!(table.source, x.source);
    assert_eq!(E::ENTRY_SIZE, x.entry_size);
    let got: Vec<String> = table
        .columns
        .iter()
        .map(|c| format!("{}:{:?}", c.name, c.ty))
        .collect();
    assert_eq!(got.join(" "), x.columns);
    assert_eq!(table.columns.len(), x.row0.len());
    table.check().unwrap();

    // Every column filled exactly once with the declared type.
    let mut b = EventBatch::new(table, 1);
    b.push_header(1, Dir::Send, 2, 3);
    E::default().push_row(&mut b);
    b.validate().unwrap();

    let bytes = fs::read(fixture(x.file)).unwrap();
    assert_eq!(bytes.len(), x.records * x.entry_size, "{}", x.file);
    let mut batch = EventBatch::new(table, x.records);
    for (i, rec) in bytes.chunks(x.entry_size).enumerate() {
        let e = E::decode(rec).unwrap();
        assert!(e.check_divider());
        batch.push_header(0, Dir::None, e.ts_ns(), i as i64);
        e.push_row(&mut batch);
    }
    batch.validate().unwrap();
    assert_eq!(batch.len(), x.records);

    let e0 = E::decode(&bytes[..x.entry_size]).unwrap();
    assert_eq!(e0.ts_ns(), x.ts0);
    assert_eq!(e0.flow_key(), x.key0);
    for (c, want) in x.row0.iter().enumerate() {
        assert_eq!(
            cell(&batch, c, 0),
            *want,
            "column {}",
            table.columns[c].name
        );
    }
}

// WP6: delete (compares with the old EventIndexer, which goes away).
/// Names, values, timestamp and flow key of every fixture record equal the old indexer's.
fn old_parity<E: Event + EventIndexer + FromBuffer>(x: &Expect) {
    assert_eq!(<E as FromBuffer>::ENTRY_SIZE, x.entry_size);
    let old_max =
        <E as EventIndexer>::get_max_index(&<E as FromBuffer>::from_buffer(&vec![0; x.entry_size]));
    assert_eq!(old_max + 1, E::TABLE.columns.len());
    let bytes = fs::read(fixture(x.file)).unwrap();
    let mut batch = EventBatch::new(E::TABLE, x.records);
    for (i, rec) in bytes.chunks(x.entry_size).enumerate() {
        let e = E::decode(rec).unwrap();
        let old = <E as FromBuffer>::from_buffer(&rec.to_vec());
        assert_eq!(e.ts_ns() as f64, old.get_timestamp());
        assert_eq!(e.flow_key(), old.get_ip_tuple(), "record {i}");
        batch.push_header(0, Dir::None, e.ts_ns(), i as i64);
        e.push_row(&mut batch);
        for (c, def) in E::TABLE.columns.iter().enumerate() {
            assert_eq!(def.name, old.get_field_name(c));
            match old.get_field(c) {
                ts_storage::DataValue::Int(v) => {
                    assert_eq!(cell(&batch, c, i) as i64, v, "{} record {i}", def.name)
                }
                other => panic!("old binding returned {other:?}"),
            }
        }
    }
}

const SOCK_COLS: &str = "pacing_rate:U64 max_pacing_rate:U64 backoff:U8 rto:U32 ato:U32 \
    rcv_mss:U16 snd_cwnd:U32 bytes_acked:U64 snd_ssthresh:U32 total_retrans:U32 probes:U8 \
    lost:U32 sacked_out:U32 retrans:U32 rcv_ssthresh:U32 rttvar:U32 advmss:U16 reordering:U32 \
    rcv_rtt:U32 rcv_space:U32 bytes_received:U64 segs_out:U32 segs_in:U32 snd_wscale:U16 \
    rcv_wscale:U16";

#[test]
fn sock_send() {
    let x = Expect {
        source: "sock",
        entry_size: 160,
        columns: SOCK_COLS,
        file: "send_sock.tcp",
        records: 2000,
        ts0: 7812280640126,
        key0: tuple("192.168.1.22", "37.51.193.149", 50290, 8080),
        row0: &[
            MAX, MAX, 0, 1000, 0, 88, 10, 0, 2147483647, 0, 0, 0, 0, 0, 64240, 0, 1460, 3, 0, 0, 0,
            0, 0, 0, 0,
        ],
    };
    check::<sock_trace_entry>(&x);
    old_parity::<sock_trace_entry>(&x); // WP6: delete
}

#[test]
fn sock_recv() {
    let x = Expect {
        source: "sock",
        entry_size: 160,
        columns: SOCK_COLS,
        file: "recv_sock.tcp",
        records: 2000,
        ts0: 7812336311825,
        key0: tuple("192.168.1.22", "37.51.193.149", 50290, 8080),
        row0: &[
            1157216, MAX, 0, 225, 0, 536, 10, 1, 2147483647, 0, 4, 0, 0, 0, 64088, 200000, 1448, 3,
            0, 14480, 0, 4, 2, 0, 0,
        ],
    };
    check::<sock_trace_entry>(&x);
    old_parity::<sock_trace_entry>(&x); // WP6: delete
}

#[test]
fn tcp_probe() {
    let x = Expect {
        source: "tcp_probe",
        entry_size: 116,
        // SSTRESH: the typo is today's series name.
        columns: "MARK:U32 DATA_LEN:U16 SND_NXT:U32 SND_UNA:U32 SND_CWND:U32 SSTRESH:U32 \
            SND_WND:U32 SRTT:U32 RCV_WND:U32 SOCK_COOKIE:U64",
        file: "tcp_probe.tcp",
        records: 2000,
        ts0: 7812336316895,
        key0: tuple("192.168.1.22", "37.51.193.149", 50290, 8080),
        row0: &[
            0, 0, 3795928409, 3795926500, 10, 2147483647, 42600, 24196, 64512, 12292,
        ],
    };
    check::<TcpProbe>(&x);
    old_parity::<TcpProbe>(&x); // WP6: delete
}

#[test]
fn cubic() {
    let x = Expect {
        source: "cubic",
        entry_size: 114,
        columns: "cnt:U32 last_max_cwnd:U32 last_cwnd:U32 last_time:U32 bic_origin_point:U32 \
            bic_K:U32 delay_min:U32 epoch_start:U32 ack_cnt:U32 tcp_cwnd:U32 round_start:U32 \
            end_seq:U32 last_ack:U32 curr_rtt:U32",
        file: "cubic.tcp",
        records: 2000,
        ts0: 7812305775840,
        key0: tuple("192.168.1.22", "37.51.193.149", 50290, 8080),
        row0: &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3517337537, 3795926500, 3517337537, 4294967295,
        ],
    };
    check::<CubicEvent>(&x);
    old_parity::<CubicEvent>(&x); // WP6: delete
}

#[test]
fn bbr() {
    let x = Expect {
        source: "bbr",
        entry_size: 110,
        columns: "min_rtt_us:U32 min_rtt_stamp:U32 probe_rtt_done_stamp:U32 rtt_cnt:U32 \
            next_rtt_delivered:U32 cycle_mstamp:U64 lt_bw:U32 lt_last_delivered:U32 \
            lt_last_stamp:U32 lt_last_lost:U32 prior_cwnd:U32 full_bw:U32",
        file: "bbr.tcp",
        records: 500,
        ts0: 1_000_000_000_000,
        key0: tuple("10.0.0.1", "10.0.0.2", 40000, 5201),
        row0: &[300, 1000, 2000, 0, 0, MAX, 5000, 0, 4000, 0, 20, 90000],
    };
    check::<BbrEvent>(&x);
    old_parity::<BbrEvent>(&x); // WP6: delete
}

#[test]
fn cwnd() {
    let x = Expect {
        source: "cwnd",
        entry_size: 62,
        columns: "perf_snd_cwnd:U32",
        file: "send_cwnd.tcp",
        records: 1000,
        ts0: 1_000_000_000_000,
        key0: tuple("10.0.0.1", "10.0.0.2", 40000, 5201),
        row0: &[10],
    };
    check::<cwnd_trace_entry>(&x);
    old_parity::<cwnd_trace_entry>(&x); // WP6: delete
}

const PKT_COLS: &str = "SEQ_NUM:U32 ACK_NUM:U32 WINDOW:U16 FLAGS:U8";

#[test]
fn tcp4_send() {
    let x = Expect {
        source: "tcp4",
        entry_size: 35,
        columns: PKT_COLS,
        file: "tcp4_send.tcp",
        records: 2000,
        ts0: 7812280671956,
        key0: tuple("192.168.1.22", "37.51.193.149", 50290, 8080),
        row0: &[3795926499, 0, 64240, 2],
    };
    check::<Tcp4Packet>(&x);
    old_parity::<Tcp4Packet>(&x); // WP6: delete
}

#[test]
fn tcp4_receive() {
    let x = Expect {
        source: "tcp4",
        entry_size: 35,
        columns: PKT_COLS,
        file: "tcp4_receive.tcp",
        records: 2000,
        ts0: 7812304808828,
        key0: tuple("37.51.193.149", "192.168.1.22", 8080, 50290),
        row0: &[478884330, 3795926500, 42600, 18],
    };
    check::<Tcp4Packet>(&x);
    old_parity::<Tcp4Packet>(&x); // WP6: delete
}

#[test]
fn tcp6_send() {
    let x = Expect {
        source: "tcp6",
        entry_size: 59,
        columns: PKT_COLS,
        file: "tcp6_send.tcp",
        records: 500,
        ts0: 1_000_000_000_000,
        key0: tuple("2001:db8::1", "2001:db8::2", 40000, 5201),
        row0: &[5000, 0, 1000, 16],
    };
    check::<Tcp6Packet>(&x);
    old_parity::<Tcp6Packet>(&x); // WP6: delete
}

#[test]
fn tcp6_receive() {
    let x = Expect {
        source: "tcp6",
        entry_size: 59,
        columns: PKT_COLS,
        file: "tcp6_receive.tcp",
        records: 500,
        ts0: 1_000_000_000_000,
        key0: tuple("2001:db8::2", "2001:db8::1", 5201, 40000),
        row0: &[5000, 0, 1000, 16],
    };
    check::<Tcp6Packet>(&x);
    old_parity::<Tcp6Packet>(&x); // WP6: delete
}

// WP6: delete. When this goes, keep the branch coverage: the fixtures only cover the common v4
// branches, so port the crafted records below to literal expected tuples first.
/// `flow_key` takes a different branch per binding (family vs `addr_v4 != 0`, ...). Compare with
/// the old `get_ip_tuple` on crafted records.
#[test]
fn flow_key_branches_match_the_old_code() {
    let v6a = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let v6b = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 9];
    // 10.0.0.1 -> 10.0.0.2 as the kernel packs it.
    let v4 =
        (u32::from_le_bytes([10, 0, 0, 1]) as u64) << 32 | u32::from_le_bytes([10, 0, 0, 2]) as u64;

    let mut expected_some_v6 = 0;
    for family in [0u16, 2, 10] {
        for addr_v4 in [0u64, v4] {
            for (s, d) in [(v6a, v6b), (mapped, v6b), ([0; 16], [0; 16])] {
                let sock = sock_trace_entry {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    sport: 1,
                    dport: 2,
                    ..Default::default()
                };
                assert_eq!(Event::flow_key(&sock), sock.get_ip_tuple());
                let cw = cwnd_trace_entry {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    sport: 1,
                    dport: 2,
                    ..Default::default()
                };
                assert_eq!(Event::flow_key(&cw), cw.get_ip_tuple());
                let cu = CubicEvent {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    sport: 1,
                    dport: 2,
                    ..Default::default()
                };
                assert_eq!(Event::flow_key(&cu), cu.get_ip_tuple());
                let bb = BbrEvent {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    sport: 1,
                    dport: 2,
                    ..Default::default()
                };
                assert_eq!(Event::flow_key(&bb), bb.get_ip_tuple());
                let mut a28 = [0u8; 28];
                let mut b28 = [0u8; 28];
                a28[4..8].copy_from_slice(&[10, 0, 0, 1]);
                b28[4..8].copy_from_slice(&[10, 0, 0, 2]);
                a28[8..24].copy_from_slice(&s);
                b28[8..24].copy_from_slice(&d);
                let pr = TcpProbe {
                    family,
                    saddr: a28,
                    daddr: b28,
                    sport: 1,
                    dport: 2,
                    ..Default::default()
                };
                assert_eq!(Event::flow_key(&pr), pr.get_ip_tuple());
                let t6 = Tcp6Packet {
                    saddr: s,
                    daddr: d,
                    sport: 1,
                    dport: 2,
                    ..Default::default()
                };
                assert_eq!(Event::flow_key(&t6), t6.get_ip_tuple());
                if matches!(Event::flow_key(&sock).src, IpAddr::V6(_)) {
                    expected_some_v6 += 1;
                }
            }
        }
    }
    assert!(expected_some_v6 > 0);

    // The branches differ between bindings, and that is kept: family 10 with a non-zero
    // addr_v4 is v6 for sock but v4 for cubic.
    let sock = sock_trace_entry {
        family: 10,
        addr_v4: v4,
        src_v6: v6a,
        dst_v6: v6b,
        ..Default::default()
    };
    let cubic = CubicEvent {
        family: 10,
        addr_v4: v4,
        src_v6: v6a,
        dst_v6: v6b,
        ..Default::default()
    };
    assert_eq!(
        Event::flow_key(&sock).src,
        "2001:db8::1".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        Event::flow_key(&cubic).src,
        "10.0.0.1".parse::<IpAddr>().unwrap()
    );
    // v4-mapped tcp6 addresses become v4 tuples.
    let t6 = Tcp6Packet {
        saddr: mapped,
        daddr: mapped,
        ..Default::default()
    };
    assert_eq!(
        Event::flow_key(&t6).src,
        "10.0.0.9".parse::<IpAddr>().unwrap()
    );
    // tcp4 reads the u32 as is (host order).
    let t4 = Tcp4Packet {
        saddr: 0x0A00_0001,
        daddr: 0x0A00_0002,
        ..Default::default()
    };
    assert_eq!(
        Event::flow_key(&t4).src,
        "10.0.0.1".parse::<IpAddr>().unwrap()
    );
    assert_eq!(Event::flow_key(&t4).l4proto, 6);
}

#[test]
fn file_table_matches_a2() {
    let want = [
        (TraceFile::SendSock, "sock", Dir::Send),
        (TraceFile::RecvSock, "sock", Dir::Recv),
        (TraceFile::SendCwnd, "cwnd", Dir::Send),
        (TraceFile::RecvCwnd, "cwnd", Dir::Recv),
        (TraceFile::Tcp4Send, "tcp4", Dir::Send),
        (TraceFile::Tcp4Receive, "tcp4", Dir::Recv),
        (TraceFile::Tcp6Send, "tcp6", Dir::Send),
        (TraceFile::Tcp6Receive, "tcp6", Dir::Recv),
        (TraceFile::TcpProbe, "tcp_probe", Dir::None),
        (TraceFile::Cubic, "cubic", Dir::None),
        (TraceFile::Bbr, "bbr", Dir::None),
    ];
    for (file, source, dir) in want {
        let b = binding(file).unwrap();
        assert_eq!(b.table.source, source, "{file:?}");
        assert_eq!(b.dir, dir, "{file:?}");
    }
    assert!(binding(TraceFile::TcpRetransmitSynack).is_none());
    assert!(binding(TraceFile::TcpBadCsum).is_none());
    // Every trace file is either mapped or explicitly skipped.
    for f in TraceFile::all() {
        let _ = binding(*f);
    }
    let sizes: Vec<_> = TraceFile::all()
        .iter()
        .filter_map(|f| binding(*f).map(|b| (b.table.source, b.entry_size, b.table.columns.len())))
        .collect();
    for (s, size, n) in [
        ("sock", 160, 25),
        ("tcp_probe", 116, 10),
        ("cubic", 114, 14),
        ("bbr", 110, 12),
        ("cwnd", 62, 1),
        ("tcp6", 59, 4),
        ("tcp4", 35, 4),
    ] {
        assert!(sizes.contains(&(s, size, n)), "{s}");
    }
    let tables = event_tables();
    let mut names: Vec<_> = tables.iter().map(|t| t.source).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 7);
}

/// Decoding a record through the file table reaches the same row as the typed path.
#[test]
fn decode_fn_fills_a_batch() {
    let b = binding(TraceFile::SendSock).unwrap();
    let file = fs::File::open(fixture("send_sock.tcp")).unwrap();
    let mut batch = EventBatch::new(b.table, 10);
    let mut keys = Vec::new();
    (b.decode)(&file, 5..8, &mut |seq, row| {
        batch.push_header(0, b.dir, row.ts_ns(), seq as i64);
        row.push_row(&mut batch);
        keys.push(row.flow_key());
        Ok(())
    })
    .unwrap();
    batch.validate().unwrap();
    assert_eq!(batch.seqs(), [5, 6, 7]);
    assert_eq!(batch.dirs(), [1, 1, 1]);
    assert_eq!(keys.len(), 3);
    assert_eq!(b.table.columns[0].ty, ColType::U64);
}
