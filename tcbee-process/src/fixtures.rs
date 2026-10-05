//! Test fixtures under `tests/fixtures/`.
//!
//! `cubic`, `tcp_probe`, `*_sock` and `tcp4_*` of `tcbee_small` are the first 2000 records of a
//! real trace and cannot be regenerated (see the README). The generator only writes what that
//! trace lacks (`bbr`, `send_cwnd`, `tcp6_*`, the empty files) and the truncated fixture:
//! `cargo test --features fixture-gen -- --ignored regenerate_fixtures`.
//! The tests in `checks` run without the feature and verify the checked-in files.

#[cfg(feature = "fixture-gen")]
mod generate {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use serde::Serialize;

    use crate::bindings::{
        bbr::BbrEvent, cwnd::cwnd_trace_entry, sock::sock_trace_entry, tcp6_packet::Tcp6Packet,
    };
    use crate::event::Event;

    const DIV: [u8; 4] = 0xFFFF_FFFFu32.to_be_bytes();
    const T0: u64 = 1_000_000_000_000;
    const AF_INET: u16 = 2;

    /// IPv4 address as the kernel structs with `addr_v4` store it: source in the high half, both
    /// halves in network byte order read as little endian.
    fn addr_v4(src: [u8; 4], dst: [u8; 4]) -> u64 {
        ((u32::from_le_bytes(src) as u64) << 32) | u32::from_le_bytes(dst) as u64
    }

    const SRC: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [10, 0, 0, 2];
    const V6_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const V6_DST: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    /// Flow of record `i`: even records belong to flow 0 (sport 40000), odd ones to flow 1 (40001).
    fn sport(i: u64) -> u16 {
        40000 + (i % 2) as u16
    }

    /// Timestamp of record `i`: the two flows share a timestamp (pairs), 1 ms apart. With
    /// `dups`, every 50th pair repeats the timestamp of the pair before, which gives duplicate
    /// timestamps within a flow.
    fn ts(i: u64, dups: bool) -> u64 {
        let mut pair = i / 2;
        if dups && pair % 50 == 49 {
            pair -= 1;
        }
        T0 + pair * 1_000_000
    }

    fn write<T: Serialize + Event>(dir: &Path, name: &str, recs: impl Iterator<Item = T>) {
        let mut out = Vec::new();
        for r in recs {
            let b = bincode::serialize(&r).unwrap();
            assert_eq!(b.len(), T::ENTRY_SIZE, "{name}: ENTRY_SIZE mismatch");
            out.extend_from_slice(&b);
        }
        fs::write(dir.join(name), out).unwrap();
    }

    fn cwnd(i: u64) -> cwnd_trace_entry {
        cwnd_trace_entry {
            time: ts(i, true),
            addr_v4: addr_v4(SRC, DST),
            sport: sport(i),
            dport: 5201,
            family: AF_INET,
            snd_cwnd: 10 + (i / 2) as u32,
            div: DIV,
            ..Default::default()
        }
    }

    fn bbr(i: u64) -> BbrEvent {
        let n = i as u32;
        BbrEvent {
            time: ts(i, true),
            addr_v4: addr_v4(SRC, DST),
            sport: sport(i),
            dport: 5201,
            family: AF_INET,
            min_rtt_us: 300 + n,
            min_rtt_stamp: 1000 + n,
            probe_rtt_done_stamp: 2000 + n,
            rtt_cnt: n,
            next_rtt_delivered: 10 * n,
            cycle_mstamp: u64::MAX - i,
            lt_bw: 5000 + n,
            lt_last_delivered: 3 * n,
            lt_last_stamp: 4000 + n,
            lt_last_lost: n / 10,
            prior_cwnd: 20 + n,
            full_bw: 90_000 + n,
            div: DIV,
            ..Default::default()
        }
    }

    fn tcp6(i: u64, recv: bool) -> Tcp6Packet {
        let (saddr, daddr, sport, dport) = if recv {
            (V6_DST, V6_SRC, 5201, sport(i))
        } else {
            (V6_SRC, V6_DST, sport(i), 5201)
        };
        Tcp6Packet {
            time: ts(i, true),
            saddr,
            daddr,
            sport,
            dport,
            seq: 5000 + 1440 * i as u32,
            ack: 7 * i as u32,
            window: 1000 + i as u16,
            flags: 0x10,
            div: DIV,
        }
    }

    #[test]
    #[ignore = "rewrites checked-in files"]
    fn regenerate_fixtures() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let small = root.join("tcbee_small");
        let trunc = root.join("tcbee_truncated");
        fs::create_dir_all(&small).unwrap();
        fs::create_dir_all(&trunc).unwrap();

        write(&small, "bbr.tcp", (0..500).map(bbr));
        write(&small, "send_cwnd.tcp", (0..1000).map(cwnd));
        write(&small, "tcp6_receive.tcp", (0..500).map(|i| tcp6(i, true)));
        write(&small, "tcp6_send.tcp", (0..500).map(|i| tcp6(i, false)));
        for empty in ["tcp_retransmit_synack", "tcp_bad_csum", "recv_cwnd"] {
            fs::write(small.join(format!("{empty}.tcp")), b"").unwrap();
        }

        // First 10 sock records of the real send_sock.tcp plus 17 bytes of the eleventh.
        let mut bytes = fs::read(small.join("send_sock.tcp")).unwrap();
        bytes.truncate(10 * sock_trace_entry::ENTRY_SIZE + 17);
        fs::write(trunc.join("send_sock.tcp"), bytes).unwrap();
    }
}

mod checks {
    use std::{collections::HashSet, fs, path::PathBuf};

    use tcbee_trace::{TCBeeTrace, TraceFile};

    use crate::bindings::{
        bbr::BbrEvent, cubic::CubicEvent, cwnd::cwnd_trace_entry, sock::sock_trace_entry,
        tcp4_packet::Tcp4Packet, tcp6_packet::Tcp6Packet, tcp_probe::TcpProbe,
    };
    use crate::event::Event;

    fn dir(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    /// Decode every whole record of a fixture file and check its divider.
    fn load<T: Event>(d: &str, file: &str) -> Vec<T> {
        let bytes = fs::read(dir(d).join(file)).unwrap();
        assert_eq!(bytes.len() % T::ENTRY_SIZE, 0, "{file}");
        bytes
            .chunks(T::ENTRY_SIZE)
            .map(|c| {
                let r = T::decode(c).unwrap();
                assert!(r.check_divider(), "{file}: bad divider");
                r
            })
            .collect()
    }

    fn check<T: Event>(file: &str, records: usize) -> Vec<T> {
        let recs = load::<T>("tcbee_small", file);
        assert_eq!(recs.len(), records, "{file}");
        recs
    }

    /// Keep the counts in sync with `tests/fixtures/README.md`.
    #[test]
    fn small_fixture() {
        let trace = TCBeeTrace::open(dir("tcbee_small")).unwrap();
        assert_eq!(trace.available_traces().len(), TraceFile::all().len());
        let total: u64 = TraceFile::all()
            .iter()
            .map(|&f| fs::metadata(trace.path_for(f)).unwrap().len())
            .sum();
        assert!(total < 2 * 1024 * 1024, "fixtures too large: {total}");

        check::<BbrEvent>("bbr.tcp", 500);
        check::<CubicEvent>("cubic.tcp", 2000);
        check::<TcpProbe>("tcp_probe.tcp", 2000);
        check::<sock_trace_entry>("recv_sock.tcp", 2000);
        check::<cwnd_trace_entry>("recv_cwnd.tcp", 0);
        check::<Tcp4Packet>("tcp4_receive.tcp", 2000);
        check::<Tcp4Packet>("tcp4_send.tcp", 2000);
        check::<Tcp6Packet>("tcp6_receive.tcp", 500);
        for empty in ["tcp_retransmit_synack.tcp", "tcp_bad_csum.tcp"] {
            assert_eq!(
                fs::metadata(dir("tcbee_small").join(empty)).unwrap().len(),
                0
            );
        }

        // Real data: u64::MAX and several flows.
        let send = check::<sock_trace_entry>("send_sock.tcp", 2000);
        assert!(send.iter().any(|r| r.max_pacing_rate == u64::MAX));
        assert!(send.iter().map(|r| r.sport).collect::<HashSet<_>>().len() > 1);

        // Generated: duplicate timestamps within a flow, non-decreasing.
        let cw = check::<cwnd_trace_entry>("send_cwnd.tcp", 1000);
        let flow0: Vec<u64> = cw.iter().step_by(2).map(|r| r.time).collect();
        assert!(flow0.windows(2).any(|w| w[0] == w[1]));
        assert!(flow0.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(cw[0].flow_key().src.to_string(), "10.0.0.1");
        assert_eq!(cw[0].flow_key().dst.to_string(), "10.0.0.2");

        let t6 = check::<Tcp6Packet>("tcp6_send.tcp", 500);
        assert_eq!(t6[0].flow_key().src.to_string(), "2001:db8::1");
        assert_eq!(t6[1].sport, 40001);
        let bbr = check::<BbrEvent>("bbr.tcp", 500);
        assert_eq!(bbr[0].cycle_mstamp, u64::MAX);
    }

    #[test]
    fn truncated_fixture() {
        let es = sock_trace_entry::ENTRY_SIZE;
        let trace = TCBeeTrace::open(dir("tcbee_truncated")).unwrap();
        assert_eq!(trace.available_traces(), vec![TraceFile::SendSock]);

        let bytes = fs::read(trace.path_for(TraceFile::SendSock)).unwrap();
        assert_eq!(bytes.len(), 10 * es + 17);
        let full = fs::read(dir("tcbee_small").join("send_sock.tcp")).unwrap();
        assert_eq!(bytes[..10 * es], full[..10 * es]);
        assert_eq!(load_bytes(&bytes[..10 * es]), 10);
    }

    fn load_bytes(b: &[u8]) -> usize {
        b.chunks(sock_trace_entry::ENTRY_SIZE)
            .map(|c| sock_trace_entry::decode(c).unwrap())
            .inspect(|r| assert!(r.check_divider()))
            .count()
    }
}
