//! Schema, `push_row` and decode tests for every binding. Expected values are literals.

use std::{fs, net::IpAddr, path::PathBuf};

use tcbee_common::records::RECORD_DELIMITER;
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
    rcv_wscale:U16 ca_state:U8 packets_out:U32 delivered:U32 delivered_ce:U32 app_limited:U32 \
    chrono_type:U8 chrono_busy:U32 chrono_rwnd_limited:U32 chrono_sndbuf_limited:U32 \
    srtt:U32 mdev:U32 min_rtt:U32 snd_una:U32 snd_nxt:U32 lost_out:U32 rate_delivered:U32 \
    rate_interval_us:U32 wstamp_ns:U64 reord_seen:U32 dsack_dups:U32 wmem_queued:U32 \
    sndbuf:U32 notsent:U32";

#[test]
fn sock_send() {
    let x = Expect {
        source: "sock",
        entry_size: 172,
        columns: SOCK_COLS,
        file: "send_sock.tcp",
        records: 2000,
        ts0: 7812280640126,
        key0: tuple("192.168.1.22", "37.51.193.149", 50290, 8080),
        row0: &[
            MAX, MAX, 0, 1000, 0, 88, 10, 0, 2147483647, 0, 0, 0, 0, 0, 64240, 0, 1460, 3, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    };
    // The fixture is a real recording in the old layout
    check::<legacy::Sock172Entry>(&x);
}

#[test]
fn sock_recv() {
    let x = Expect {
        source: "sock",
        entry_size: 172,
        columns: SOCK_COLS,
        file: "recv_sock.tcp",
        records: 2000,
        ts0: 7812336311825,
        key0: tuple("192.168.1.22", "37.51.193.149", 50290, 8080),
        row0: &[
            1157216, MAX, 0, 225, 0, 536, 10, 1, 2147483647, 0, 4, 0, 0, 0, 64088, 200000, 1448, 3,
            0, 14480, 0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ],
    };
    check::<legacy::Sock172Entry>(&x);
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
    check::<tcp_probe_entry>(&x);
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
    check::<cubic_trace_entry>(&x);
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
    check::<bbr_trace_entry>(&x);
}

#[test]
fn mptcp_pm() {
    let x = Expect {
        source: "mptcp_pm",
        entry_size: 123,
        columns: "event:U8 token:U32 remote_token:U32 subflow_id:U32 error:I64 local_id:U8 \
            remote_id:U8 backup:U8 addr_id:U8 addr_family:U16 addr_port:U16 addr_0:U32 addr_1:U32 \
            addr_2:U32 addr_3:U32 data_seq:U64 data_len:U32",
        file: "mptcp_pm.tcp",
        records: 12,
        ts0: 1_000_000_000_000,
        key0: tuple("10.0.0.1", "10.0.0.2", 40000, 5201),
        row0: &[1, 0x1000, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    check::<mptcp_pm_entry>(&x);
}

#[test]
fn cwnd() {
    let x = Expect {
        source: "cwnd",
        entry_size: 74,
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
    check::<tcp4_packet_trace>(&x);
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
    check::<tcp4_packet_trace>(&x);
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
    check::<tcp6_packet_trace>(&x);
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
    check::<tcp6_packet_trace>(&x);
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
                cubic.push(k(Event::flow_key(&cubic_trace_entry {
                    family,
                    addr_v4,
                    src_v6: s,
                    dst_v6: d,
                    ..Default::default()
                })));
                bbr.push(k(Event::flow_key(&bbr_trace_entry {
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
                probe.push(k(Event::flow_key(&tcp_probe_entry {
                    family,
                    saddr: a28,
                    daddr: b28,
                    ..Default::default()
                })));
                if family == 0 && addr_v4 == 0 {
                    tcp6.push(k(Event::flow_key(&tcp6_packet_trace {
                        saddr_v6: s,
                        daddr_v6: d,
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
    let t4 = tcp4_packet_trace {
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
        (TraceFile::MptcpPm, "mptcp_pm", Dir::None),
        (TraceFile::TcpEvents, "tcp_event", Dir::None),
        (TraceFile::TimerSock, "sock_timer", Dir::None),
        (TraceFile::IngressSock, "sock_ingress", Dir::None),
        (TraceFile::EventSock, "sock_event", Dir::None),
        (TraceFile::SendSockOc, "sock_oc", Dir::Send),
        (TraceFile::RecvSockOc, "sock_oc", Dir::Recv),
        (TraceFile::SendCwndOc, "cwnd_oc", Dir::Send),
        (TraceFile::RecvCwndOc, "cwnd_oc", Dir::Recv),
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
        ("sock", 262, 48),
        ("tcp_probe", 124, 10),
        ("cubic", 122, 14),
        ("bbr", 118, 12),
        ("cwnd", 74, 1),
        ("tcp6", 67, 4),
        ("tcp4", 43, 4),
        ("mptcp_pm", 123, 17),
        ("tcp_event", 99, 13),
        ("sock_oc", 262, 48),
        ("cwnd_oc", 74, 1),
        ("sock_timer", 262, 48),
        ("sock_ingress", 262, 48),
        ("sock_event", 262, 48),
    ] {
        assert!(sizes.contains(&(s, size, n)), "{s}");
    }
    let tables = event_tables();
    let mut names: Vec<_> = tables.iter().map(|t| t.source).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), tables.len());
    assert_eq!(names.len(), 14);
}

/// Every binding's entry size is its record's bincode encoding plus the divider.
#[test]
fn entry_sizes_match_the_record_encoding() {
    for file in TraceFile::all() {
        if let Some(b) = binding(*file) {
            let expected = (b.encoded_size)() + RECORD_DELIMITER.len();
            assert_eq!(b.entry_size, expected, "{file:?}");
        }
    }
}

/// Decoding a record through the file table reaches the same row as the typed path.
#[test]
fn decode_fn_fills_a_batch() {
    let path = fixture("send_sock.tcp");
    let b = binding_for(TraceFile::SendSock, &path).unwrap().unwrap();
    let file = fs::File::open(&path).unwrap();
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

/// A record in the current sock layout carries the added columns.
#[test]
fn current_sock_record_has_the_added_columns() {
    let rec = sock_trace_entry {
        time: 5,
        hook_seq: 1,
        snd_cwnd: 10,
        ca_state: 4,
        packets_out: 7,
        delivered: 1000,
        delivered_ce: 3,
        app_limited: 999,
        chrono_type: 1,
        chrono_busy: 11,
        chrono_rwnd_limited: 12,
        chrono_sndbuf_limited: 13,
        conn_id: 0xABCD,
        ..Default::default()
    };
    let mut bytes = bincode::serialize(&rec).unwrap();
    bytes.extend_from_slice(&RECORD_DELIMITER);
    assert_eq!(bytes.len(), sock_trace_entry::ENTRY_SIZE);
    let e = sock_trace_entry::decode(&bytes).unwrap();
    assert_eq!(Event::connection_key(&e), 0xABCD);
    let mut batch = EventBatch::new(sock_trace_entry::TABLE, 1);
    batch.push_header(0, Dir::Send, e.ts_ns(), 0);
    e.push_row(&mut batch);
    let col = |name: &str| {
        let c = sock_trace_entry::TABLE
            .columns
            .iter()
            .position(|c| c.name == name)
            .unwrap();
        cell(&batch, c, 0)
    };
    assert_eq!(col("snd_cwnd"), 10);
    assert_eq!(col("ca_state"), 4);
    assert_eq!(col("delivered"), 1000);
    assert_eq!(col("app_limited"), 999);
    assert_eq!(col("chrono_sndbuf_limited"), 13);
}

/// Sock files are told apart by where their dividers are, and the old layout reports the
/// columns it does not have.
#[test]
fn sock_layout_is_detected_per_file() {
    let old = binding_for(TraceFile::SendSock, &fixture("send_sock.tcp"))
        .unwrap()
        .unwrap();
    assert_eq!(old.entry_size, 172);
    assert_eq!(old.missing_columns, legacy::SOCK172_MISSING);
    assert_eq!(old.table.source, "sock");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("send_sock.tcp");
    let mut bytes = Vec::new();
    for i in 0..3u64 {
        bytes.extend(
            bincode::serialize(&sock_trace_entry {
                time: i,
                ..Default::default()
            })
            .unwrap(),
        );
        bytes.extend_from_slice(&RECORD_DELIMITER);
    }
    fs::write(&path, &bytes).unwrap();
    let current = binding_for(TraceFile::SendSock, &path).unwrap().unwrap();
    assert_eq!(current.entry_size, 262);
    assert!(current.missing_columns.is_empty());

    // An empty file gets the current binding
    fs::write(&path, b"").unwrap();
    assert_eq!(
        binding_for(TraceFile::SendSock, &path)
            .unwrap()
            .unwrap()
            .entry_size,
        262
    );
    // Other files are not looked at
    assert!(binding_for(TraceFile::TcpBadCsum, &path).unwrap().is_none());
}

/// Event labels name the kind and, for state changes, both states.
#[test]
fn tcp_event_labels() {
    use tcbee_common::records::{
        tcp_event_entry, TCBEE_TCP_CA_STATE, TCBEE_TCP_DESTROY, TCBEE_TCP_RETRANSMIT,
        TCBEE_TCP_RTO, TCBEE_TCP_STATE,
    };
    let e = |kind, old_state, new_state, backoff| tcp_event_entry {
        kind: kind as u8,
        old_state,
        new_state,
        backoff,
        ..Default::default()
    };
    assert_eq!(
        tcp_event::label(&e(TCBEE_TCP_RETRANSMIT, 0, 0, 0)),
        "retransmit"
    );
    assert_eq!(
        tcp_event::label(&e(TCBEE_TCP_STATE, 1, 4, 0)),
        "ESTABLISHED → FIN_WAIT1"
    );
    assert_eq!(
        tcp_event::label(&e(TCBEE_TCP_CA_STATE, 0, 3, 0)),
        "Open → Recovery"
    );
    assert_eq!(
        tcp_event::label(&e(TCBEE_TCP_CA_STATE, 0, 9, 0)),
        "Open → 9"
    );
    assert_eq!(
        tcp_event::label(&e(TCBEE_TCP_RTO, 0, 0, 2)),
        "RTO, backoff 2"
    );
    assert_eq!(
        tcp_event::label(&e(TCBEE_TCP_DESTROY, 0, 0, 0)),
        "socket destroyed"
    );
    assert_eq!(tcp_event::label(&e(200, 0, 0, 0)), "event 200");
}

/// A TCP event decodes, keys its flow local -> remote like the sock records and fills every
/// column.
#[test]
fn tcp_event_round_trip() {
    use tcbee_common::records::{tcp_event_entry, TCBEE_TCP_RETRANSMIT};
    let rec = tcp_event_entry {
        time: 9,
        hook_seq: 2,
        // local 10.0.0.1 in the high half, remote 10.0.0.2 in the low half
        addr_v4: (u64::from(u32::from_le_bytes([10, 0, 0, 1])) << 32)
            | u64::from(u32::from_le_bytes([10, 0, 0, 2])),
        sport: 40000,
        dport: 5201,
        family: 2,
        kind: TCBEE_TCP_RETRANSMIT as u8,
        seq: 77,
        snd_cwnd: 10,
        ..Default::default()
    };
    let mut bytes = bincode::serialize(&rec).unwrap();
    bytes.extend_from_slice(&RECORD_DELIMITER);
    assert_eq!(bytes.len(), tcp_event_entry::ENTRY_SIZE);
    let e = tcp_event_entry::decode(&bytes).unwrap();
    assert_eq!(e.flow_key(), tuple("10.0.0.1", "10.0.0.2", 40000, 5201));
    let mut batch = EventBatch::new(tcp_event_entry::TABLE, 1);
    batch.push_header(0, Dir::None, e.ts_ns(), e.hook_seq());
    e.push_row(&mut batch);
    batch.validate().unwrap();
    match &batch.columns()[0] {
        ColumnData::Text(v) => assert_eq!(v, &["retransmit"]),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(cell(&batch, 7, 0), 77);
    assert_eq!(cell(&batch, 10, 0), 10);
}

/// The 172 B sock layout is the current one without `SOCK172_MISSING`: an old record is the
/// prefix of a current one up to rcv_wscale, followed by conn_id. When the sock layout changes
/// again, freeze the current one in `legacy.rs` like the other old layouts.
#[test]
fn sock172_layout_is_the_current_one_without_the_missing_columns() {
    let mut rec = sock_trace_entry {
        time: 1,
        hook_seq: 2,
        addr_v4: 3,
        sport: 4,
        dport: 5,
        family: 2,
        pacing_rate: 6,
        backoff: 7,
        snd_cwnd: 8,
        bytes_received: 9,
        rcv_wscale: 10,
        conn_id: 11,
        ..Default::default()
    };
    let current = bincode::serialize(&rec).unwrap();
    let old_len = legacy::Sock172Entry::ENTRY_SIZE - RECORD_DELIMITER.len();
    let mut old = current[..old_len - 4].to_vec();
    old.extend_from_slice(&rec.conn_id.to_le_bytes());
    old.extend_from_slice(&RECORD_DELIMITER);
    let decoded = legacy::Sock172Entry::decode(&old).unwrap();

    let mut want = EventBatch::new(sock_trace_entry::TABLE, 1);
    want.push_header(0, Dir::Send, 1, 2);
    rec.push_row(&mut want);
    let mut got = EventBatch::new(sock_trace_entry::TABLE, 1);
    got.push_header(0, Dir::Send, 1, 2);
    decoded.push_row(&mut got);
    assert_eq!(got.columns(), want.columns());
    assert_eq!(Event::flow_key(&decoded), Event::flow_key(&rec));

    // The missing columns stay 0 for old records
    rec.ca_state = 4;
    let mut changed = EventBatch::new(sock_trace_entry::TABLE, 1);
    changed.push_header(0, Dir::Send, 1, 2);
    rec.push_row(&mut changed);
    assert_ne!(got.columns(), changed.columns());
}

/// Every legacy layout's entry size is its frozen struct's bincode encoding plus the divider,
/// and no two layouts of a table have the same size.
#[test]
fn legacy_entry_sizes_match_their_encoding() {
    for (source, current) in [("sock", sock_trace_entry::ENTRY_SIZE), ("cwnd", 74)] {
        let mut sizes = vec![current];
        for l in legacy::layouts(source) {
            let b = (l.binding)(Dir::Send);
            assert_eq!(b.entry_size, l.entry_size, "{source}");
            assert_eq!(
                b.entry_size,
                (b.encoded_size)() + RECORD_DELIMITER.len(),
                "{source} {}",
                l.entry_size
            );
            assert_eq!(b.table.source, source);
            sizes.push(l.entry_size);
        }
        let n = sizes.len();
        sizes.sort();
        sizes.dedup();
        assert_eq!(sizes.len(), n, "{source}: two layouts of the same size");
    }
    assert_eq!(
        legacy::layouts("sock")
            .iter()
            .map(|l| l.entry_size)
            .collect::<Vec<_>>(),
        [172, 168, 201, 202, 226]
    );
    assert_eq!(
        legacy::layouts("cwnd")
            .iter()
            .map(|l| l.entry_size)
            .collect::<Vec<_>>(),
        [70]
    );
}

fn write_records<T: serde::Serialize>(path: &std::path::Path, recs: &[T], tail: usize) {
    let mut bytes = Vec::new();
    for r in recs {
        bytes.extend(bincode::serialize(r).unwrap());
        bytes.extend_from_slice(&RECORD_DELIMITER);
    }
    bytes.extend(std::iter::repeat_n(0u8, tail));
    fs::write(path, &bytes).unwrap();
}

fn decode_first(b: &Binding, path: &std::path::Path) -> (EventBatch, Vec<u32>) {
    let file = fs::File::open(path).unwrap();
    let mut batch = EventBatch::new(b.table, 4);
    let mut conns = Vec::new();
    (b.decode)(&file, 0..1, &mut |seq, row| {
        batch.push_header(0, b.dir, row.ts_ns(), seq as i64);
        row.push_row(&mut batch);
        conns.push(row.connection_key());
        Ok(())
    })
    .unwrap();
    (batch, conns)
}

fn col(b: &EventBatch, table: &EventTable, name: &str) -> i128 {
    cell(
        b,
        table.columns.iter().position(|c| c.name == name).unwrap(),
        0,
    )
}

/// Files in each older layout are detected, report the columns they lack and decode into the
/// current table; layouts without conn_id belong to no connection.
#[test]
fn legacy_layouts_are_detected_and_decoded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("send_sock.tcp");
    let p = legacy::SockPrefix {
        time: 7,
        hook_seq: 1,
        snd_cwnd: 33,
        rcv_wscale: 9,
        family: 2,
        ..Default::default()
    };

    write_records(&path, &[legacy::Sock168Entry { p }; 3], 0);
    let b = binding_for(TraceFile::SendSock, &path).unwrap().unwrap();
    assert_eq!(
        (b.entry_size, b.missing_columns),
        (168, legacy::SOCK172_MISSING)
    );
    let (batch, conns) = decode_first(&b, &path);
    assert_eq!(
        (
            col(&batch, b.table, "snd_cwnd"),
            col(&batch, b.table, "rcv_wscale")
        ),
        (33, 9)
    );
    assert_eq!(conns, [0]);

    let r201 = legacy::Sock201Entry {
        p,
        srtt: 100,
        packets_out: 5,
        delivered: 77,
        ca_state: 4,
        ..Default::default()
    };
    write_records(&path, &[r201; 3], 0);
    let b = binding_for(TraceFile::SendSock, &path).unwrap().unwrap();
    assert_eq!(
        (b.entry_size, b.missing_columns),
        (201, legacy::SOCK201_MISSING)
    );
    let (batch, conns) = decode_first(&b, &path);
    assert_eq!(
        (
            col(&batch, b.table, "packets_out"),
            col(&batch, b.table, "delivered"),
            col(&batch, b.table, "ca_state")
        ),
        (5, 77, 4)
    );
    assert_eq!(col(&batch, b.table, "app_limited"), 0);
    assert_eq!(conns, [0]);
    // the on-change files of build 4d3cffb7 hold the same records and keep their table
    let oc_path = dir.path().join("send_sock_oc.tcp");
    write_records(&oc_path, &[r201; 3], 0);
    let b = binding_for(TraceFile::SendSockOc, &oc_path)
        .unwrap()
        .unwrap();
    assert_eq!(
        (b.entry_size, b.table.source, b.missing_columns),
        (201, "sock_oc", legacy::SOCK201_MISSING)
    );

    let r202 = legacy::Sock202Entry {
        p,
        ca_state: 3,
        chrono_busy: 44,
        conn_id: 0xBEEF,
        ..Default::default()
    };
    write_records(&path, &[r202; 3], 0);
    let b = binding_for(TraceFile::SendSock, &path).unwrap().unwrap();
    assert_eq!(
        (b.entry_size, b.missing_columns),
        (202, legacy::SOCK202_MISSING)
    );
    let (batch, conns) = decode_first(&b, &path);
    assert_eq!(
        (
            col(&batch, b.table, "ca_state"),
            col(&batch, b.table, "chrono_busy"),
            col(&batch, b.table, "srtt")
        ),
        (3, 44, 0)
    );
    assert_eq!(conns, [0xBEEF]);

    let r226 = legacy::Sock226Entry {
        p,
        ca_state: 4,
        srtt: 120,
        lost_out: 2,
        conn_id: 0xCAFE,
        ..Default::default()
    };
    write_records(&path, &[r226; 3], 0);
    let b = binding_for(TraceFile::SendSock, &path).unwrap().unwrap();
    assert_eq!(
        (b.entry_size, b.missing_columns),
        (226, legacy::SOCK226_MISSING)
    );
    let (batch, conns) = decode_first(&b, &path);
    assert_eq!(
        (
            col(&batch, b.table, "ca_state"),
            col(&batch, b.table, "srtt"),
            col(&batch, b.table, "lost_out"),
            col(&batch, b.table, "notsent")
        ),
        (4, 120, 2, 0)
    );
    assert_eq!(conns, [0xCAFE]);

    let cpath = dir.path().join("send_cwnd.tcp");
    write_records(
        &cpath,
        &[legacy::Cwnd70Entry {
            time: 3,
            hook_seq: 1,
            snd_cwnd: 21,
            family: 2,
            ..Default::default()
        }; 2],
        0,
    );
    let b = binding_for(TraceFile::SendCwnd, &cpath).unwrap().unwrap();
    assert_eq!((b.entry_size, b.table.source), (70, "cwnd"));
    let (batch, conns) = decode_first(&b, &cpath);
    assert_eq!(col(&batch, b.table, "perf_snd_cwnd"), 21);
    assert_eq!(conns, [0]);
}

/// Empty files and files whose last record was cut off get a layout; records that fit several
/// layouts are an error, unless later records or the file's length decide.
#[test]
fn layout_probe_handles_empty_cut_and_ambiguous_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("send_sock.tcp");
    fs::write(&path, b"").unwrap();
    assert_eq!(
        binding_for(TraceFile::SendSock, &path)
            .unwrap()
            .unwrap()
            .entry_size,
        262
    );
    // only a partial first record: no complete record in any layout -> the current one
    fs::write(&path, [0u8; 50]).unwrap();
    assert_eq!(
        binding_for(TraceFile::SendSock, &path)
            .unwrap()
            .unwrap()
            .entry_size,
        262
    );
    // a 201 B file whose last record was cut off by a kill
    let p = legacy::SockPrefix {
        time: 1,
        ..Default::default()
    };
    write_records(
        &path,
        &[legacy::Sock201Entry {
            p,
            ..Default::default()
        }; 3],
        17,
    );
    assert_eq!(
        binding_for(TraceFile::SendSock, &path)
            .unwrap()
            .unwrap()
            .entry_size,
        201
    );
    // all 0xFF: dividers at every size; 606 B only divides into 202 B records (a legacy layout)
    fs::write(&path, [0xFFu8; 606]).unwrap();
    assert_eq!(
        binding_for(TraceFile::SendSock, &path)
            .unwrap()
            .unwrap()
            .entry_size,
        202
    );
    // 201 * 202 B of 0xFF divide into both: refused, not guessed
    fs::write(&path, vec![0xFFu8; 201 * 202]).unwrap();
    assert!(binding_for(TraceFile::SendSock, &path).is_err());
    // the same length, the first records 0xFF, then dividers only every 202 B: the later
    // records decide
    let mut data = vec![0u8; 201 * 202];
    data[..8 * 262].fill(0xFF);
    for end in (202..=data.len()).step_by(202) {
        data[end - RECORD_DELIMITER.len()..end].copy_from_slice(&RECORD_DELIMITER);
    }
    fs::write(&path, data).unwrap();
    assert_eq!(
        binding_for(TraceFile::SendSock, &path)
            .unwrap()
            .unwrap()
            .entry_size,
        202
    );
    // a killed writer's preallocated zeros within the deeper records rule out every size: the
    // length decides among the sizes that fit the first records
    let mut data = vec![0u8; 20 * 202];
    data[..8 * 262].fill(0xFF);
    fs::write(&path, data).unwrap();
    assert_eq!(
        binding_for(TraceFile::SendSock, &path)
            .unwrap()
            .unwrap()
            .entry_size,
        202
    );
}

/// The 172 B layout lacks the run-metadata fields and everything the 202 B layout lacks, so
/// that a field added to the sock record later goes into both lists
#[test]
fn sock172_missing_ends_with_sock202_missing() {
    assert!(legacy::SOCK172_MISSING.ends_with(legacy::SOCK202_MISSING));
    assert!(legacy::SOCK202_MISSING.ends_with(legacy::SOCK226_MISSING));
    assert!(legacy::SOCK201_MISSING.ends_with(legacy::SOCK226_MISSING));
}

/// Write timer records (-k) decode into their own table and keep the hook tag in ato.
#[test]
fn timer_records_go_to_their_own_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("timer_sock.tcp");
    let rec = tcbee_common::records::sock_trace_entry {
        time: 7,
        hook_seq: 1,
        snd_cwnd: 1,
        backoff: 2,
        ato: 2 << 8,
        ..Default::default()
    };
    write_records(&path, &[rec; 3], 0);
    let b = binding_for(TraceFile::TimerSock, &path).unwrap().unwrap();
    assert_eq!((b.table.source, b.dir), ("sock_timer", Dir::None));
    let (batch, _) = decode_first(&b, &path);
    assert_eq!(
        (col(&batch, b.table, "backoff"), col(&batch, b.table, "ato")),
        (2, 512)
    );
}
