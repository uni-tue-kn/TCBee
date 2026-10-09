//! Schema, `push_row` and decode tests for every binding. Expected values are literals.

use std::{fs, net::IpAddr, path::PathBuf};

use tcbee_trace::TraceFile;
use ts_storage::{ColType, ColumnData, Dir, EventBatch, IpTuple};

use super::*;
use crate::event::Event;

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

const SOCK_COLS: &str = "pacing_rate:U64 max_pacing_rate:U64 backoff:U8 rto:U32 ato:U32 \
    rcv_mss:U16 snd_cwnd:U32 bytes_acked:U64 snd_ssthresh:U32 total_retrans:U32 probes:U8 \
    lost:U32 sacked_out:U32 retrans:U32 rcv_ssthresh:U32 rttvar:U32 advmss:U16 reordering:U32 \
    rcv_rtt:U32 rcv_space:U32 bytes_received:U64 segs_out:U32 segs_in:U32 snd_wscale:U16 \
    rcv_wscale:U16";

#[test]
fn sock_send() {
    let x = Expect {
        source: "sock",
        entry_size: 168,
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
}

#[test]
fn sock_recv() {
    let x = Expect {
        source: "sock",
        entry_size: 168,
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
}

#[test]
fn tcp_probe() {
    let x = Expect {
        source: "tcp_probe",
        entry_size: 124,
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
}

#[test]
fn cubic() {
    let x = Expect {
        source: "cubic",
        entry_size: 122,
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
}

#[test]
fn bbr() {
    let x = Expect {
        source: "bbr",
        entry_size: 118,
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
}

#[test]
fn cwnd() {
    let x = Expect {
        source: "cwnd",
        entry_size: 70,
        columns: "perf_snd_cwnd:U32",
        file: "send_cwnd.tcp",
        records: 1000,
        ts0: 1_000_000_000_000,
        key0: tuple("10.0.0.1", "10.0.0.2", 40000, 5201),
        row0: &[10],
    };
    check::<cwnd_trace_entry>(&x);
}

const PKT_COLS: &str = "SEQ_NUM:U32 ACK_NUM:U32 WINDOW:U16 FLAGS:U8";

#[test]
fn tcp4_send() {
    let x = Expect {
        source: "tcp4",
        entry_size: 43,
        columns: PKT_COLS,
        file: "tcp4_send.tcp",
        records: 2000,
        ts0: 7812280671956,
        key0: tuple("192.168.1.22", "37.51.193.149", 50290, 8080),
        row0: &[3795926499, 0, 64240, 2],
    };
    check::<Tcp4Packet>(&x);
}

#[test]
fn tcp4_receive() {
    let x = Expect {
        source: "tcp4",
        entry_size: 43,
        columns: PKT_COLS,
        file: "tcp4_receive.tcp",
        records: 2000,
        ts0: 7812304808828,
        key0: tuple("37.51.193.149", "192.168.1.22", 8080, 50290),
        row0: &[478884330, 3795926500, 42600, 18],
    };
    check::<Tcp4Packet>(&x);
}

#[test]
fn tcp6_send() {
    let x = Expect {
        source: "tcp6",
        entry_size: 67,
        columns: PKT_COLS,
        file: "tcp6_send.tcp",
        records: 500,
        ts0: 1_000_000_000_000,
        key0: tuple("2001:db8::1", "2001:db8::2", 40000, 5201),
        row0: &[5000, 0, 1000, 16],
    };
    check::<Tcp6Packet>(&x);
}

#[test]
fn tcp6_receive() {
    let x = Expect {
        source: "tcp6",
        entry_size: 67,
        columns: PKT_COLS,
        file: "tcp6_receive.tcp",
        records: 500,
        ts0: 1_000_000_000_000,
        key0: tuple("2001:db8::2", "2001:db8::1", 5201, 40000),
        row0: &[5000, 0, 1000, 16],
    };
    check::<Tcp6Packet>(&x);
}

/// Expected `flow_key` (as "src>dst") for crafted records, in the loop order of the test below:
/// family 0, 2, 10; `addr_v4` zero, then 10.0.0.1 -> 10.0.0.2 packed as the kernel does; address
/// pairs (2001:db8::1, 2001:db8::2), (v4-mapped 10.0.0.9, 2001:db8::2), (zeros). The fixtures only
/// cover the common IPv4 branches; this covers the rest. The tables differ per binding on
/// purpose (sock and cwnd test `family == AF_INET`, cubic and bbr test `addr_v4 != 0`, tcp_probe
/// reads the 28 byte kernel structs), so family 10 with a non-zero `addr_v4` is v6 for sock and
/// v4 for cubic.
const EXPECT_SOCK: &[&str] = &[
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "0.0.0.0>0.0.0.0",
    "0.0.0.0>0.0.0.0",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
];

const EXPECT_CWND: &[&str] = &[
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "0.0.0.0>0.0.0.0",
    "0.0.0.0>0.0.0.0",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
];

const EXPECT_CUBIC: &[&str] = &[
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
];

const EXPECT_BBR: &[&str] = &[
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
];

const EXPECT_PROBE: &[&str] = &[
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "10.0.0.1>10.0.0.2",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
];

const EXPECT_TCP6: &[&str] = &[
    "2001:db8::1>2001:db8::2",
    "10.0.0.9>2001:db8::2",
    "0.0.0.0>0.0.0.0",
];

fn k(t: IpTuple) -> String {
    format!("{}>{}", t.src, t.dst)
}

#[test]
fn flow_key_branches() {
    let v6a = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let v6b = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 9];
    // 10.0.0.1 -> 10.0.0.2 as the kernel packs it.
    let v4 =
        (u32::from_le_bytes([10, 0, 0, 1]) as u64) << 32 | u32::from_le_bytes([10, 0, 0, 2]) as u64;

    let (mut sock, mut cwnd, mut cubic, mut bbr, mut probe, mut tcp6) =
        (vec![], vec![], vec![], vec![], vec![], vec![]);
    for family in [0u16, 2, 10] {
        for addr_v4 in [0u64, v4] {
            for (s, d) in [(v6a, v6b), (mapped, v6b), ([0; 16], [0; 16])] {
                sock.push(k(Event::flow_key(&sock_trace_entry {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    ..Default::default()
                })));
                cwnd.push(k(Event::flow_key(&cwnd_trace_entry {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    ..Default::default()
                })));
                cubic.push(k(Event::flow_key(&CubicEvent {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    ..Default::default()
                })));
                bbr.push(k(Event::flow_key(&BbrEvent {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    ..Default::default()
                })));
                let mut a28 = [0u8; 28];
                let mut b28 = [0u8; 28];
                a28[4..8].copy_from_slice(&[10, 0, 0, 1]);
                b28[4..8].copy_from_slice(&[10, 0, 0, 2]);
                a28[8..24].copy_from_slice(&s);
                b28[8..24].copy_from_slice(&d);
                probe.push(k(Event::flow_key(&TcpProbe {
                    family,
                    saddr: a28,
                    daddr: b28,
                    ..Default::default()
                })));
                if family == 0 && addr_v4 == 0 {
                    tcp6.push(k(Event::flow_key(&Tcp6Packet {
                        saddr: s,
                        daddr: d,
                        ..Default::default()
                    })));
                }
            }
        }
    }
    assert_eq!(sock, EXPECT_SOCK);
    assert_eq!(cwnd, EXPECT_CWND);
    assert_eq!(cubic, EXPECT_CUBIC);
    assert_eq!(bbr, EXPECT_BBR);
    assert_eq!(probe, EXPECT_PROBE);
    assert_eq!(tcp6, EXPECT_TCP6);

    // tcp4 reads the u32 as is (host order), ports as read, l4proto 6.
    let t4 = Tcp4Packet {
        saddr: 0x0A00_0001,
        daddr: 0x0A00_0002,
        sport: 7,
        dport: 9,
        ..Default::default()
    };
    assert_eq!(Event::flow_key(&t4), tuple("10.0.0.1", "10.0.0.2", 7, 9));
}

#[test]
fn file_table_maps_every_trace_file() {
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
        ("sock", 168, 25),
        ("tcp_probe", 124, 10),
        ("cubic", 122, 14),
        ("bbr", 118, 12),
        ("cwnd", 70, 1),
        ("tcp6", 67, 4),
        ("tcp4", 43, 4),
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
