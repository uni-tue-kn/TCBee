//! The ring buffer ids, map names and the STATS length exist twice: in the eBPF sources and in
//! `tcbee_common::stats`. This test reads the C sources and checks that both agree, including
//! which map each program writes for which ring buffer id.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use tcbee_common::stats::*;
use tcbee_trace::TraceFile;

fn bpf_source(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tcbee/src/bpf")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `#define NAME 123` lines of `src` whose name starts with `prefix`
fn defines(src: &str, prefix: &str) -> BTreeMap<String, u32> {
    src.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "#define").then_some(())?;
            let name = words.next()?.strip_prefix(prefix)?;
            Some((name.to_string(), words.next()?.parse().ok()?))
        })
        .collect()
}

/// Ring buffer ids of `tcbee_common::stats`, by name without the `RB_` prefix
macro_rules! rust_ids {
    ($($id:ident),+ $(,)?) => {
        BTreeMap::from([$((stringify!($id).strip_prefix("RB_").unwrap().to_string(), $id)),+])
    };
}

#[test]
fn ring_buffer_ids_match_counters_h() {
    let mut c = defines(&bpf_source("counters.h"), "RB_");
    assert_eq!(c.remove("COUNT"), Some(RB_COUNT));
    let rust = rust_ids!(
        RB_TCP4_EGRESS,
        RB_TCP4_INGRESS,
        RB_TCP6_EGRESS,
        RB_TCP6_INGRESS,
        RB_SOCK_SEND,
        RB_SOCK_RECV,
        RB_CWND_SEND,
        RB_CWND_RECV,
        RB_TCP_PROBE,
        RB_RETRANSMIT_SYNACK,
        RB_BAD_CSUM,
        RB_CUBIC,
        RB_BBR,
        RB_MPTCP_PM,
        RB_TCP_EVENTS,
        RB_SOCK_TIMER,
        RB_SOCK_INGRESS,
        RB_SOCK_EVENT,
    );
    assert_eq!(c, rust);
    let mut ids: Vec<u32> = rust.into_values().collect();
    ids.sort_unstable();
    assert_eq!(ids, (0..RB_COUNT).collect::<Vec<_>>());
}

#[test]
fn stats_length_matches_maps_h() {
    let len = defines(&bpf_source("maps.h"), "TCBEE_STATS_LEN");
    assert_eq!(len.get(""), Some(&STATS_LEN));
}

#[test]
fn ring_buffer_maps_match_maps_h() {
    let maps_h = bpf_source("maps.h");
    let declared: Vec<&str> = maps_h
        .lines()
        .filter_map(|line| line.strip_prefix("RINGBUFS_PER_CPU(")?.strip_suffix(");"))
        .collect();
    let rust: Vec<&str> = RINGBUFS.iter().map(|ringbuf| ringbuf.map).collect();
    assert_eq!(declared, rust);
}

/// Every `&MAP, RB_ID` argument pair at the call sites in the programs (reserve() and the
/// helpers that take a ring buffer and its id) names the map that `RINGBUFS[RB_ID]` says, and
/// every ring buffer appears in such a pair.
#[test]
fn programs_use_the_map_of_each_ring_buffer_id() {
    let ids = defines(&bpf_source("counters.h"), "RB_");
    let program = bpf_source("tcbee.bpf.c");
    let identifier = |s: &str| -> String {
        s.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect()
    };
    let mut seen = BTreeSet::new();
    for (i, _) in program.match_indices('&') {
        let map = identifier(&program[i + 1..]);
        let after = program[i + 1 + map.len()..].trim_start();
        let Some(id) = after
            .strip_prefix(',')
            .and_then(|s| s.trim_start().strip_prefix("RB_"))
        else {
            continue;
        };
        let id = identifier(id);
        let rb = ids[&id];
        assert_eq!(map, RINGBUFS[rb as usize].map, "RB_{id}");
        seen.insert(rb);
    }
    assert_eq!(seen, (0..RB_COUNT).collect());
}

/// Every trace file is written by exactly one ring buffer, and the direction in the file name
/// matches the map name. The on-change files (`*_oc.tcp`) are written by the ring buffer of
/// their full counterpart, in on-change mode instead of it.
#[test]
fn every_trace_file_has_one_ring_buffer() {
    let mut files: Vec<&str> = RINGBUFS.iter().map(|r| r.file.filename()).collect();
    files.sort_unstable();
    let (on_change, mut all): (Vec<&str>, Vec<&str>) = TraceFile::all()
        .iter()
        .map(|f| f.filename())
        .partition(|name| name.ends_with("_oc.tcp"));
    all.sort_unstable();
    assert_eq!(files, all);
    for name in on_change {
        let full = name.replace("_oc.tcp", ".tcp");
        assert!(
            files.contains(&full.as_str()),
            "{name} has no full counterpart"
        );
    }

    for ringbuf in &RINGBUFS {
        let file = ringbuf.file.filename();
        let sends = ["SEND", "EGRESS"].iter().any(|w| ringbuf.map.contains(w));
        let receives = ["RECV", "RECEIVE", "INGRESS"]
            .iter()
            .any(|w| ringbuf.map.contains(w));
        assert_eq!(sends, file.contains("send"), "{} -> {file}", ringbuf.map);
        assert_eq!(
            receives,
            ["recv", "receive", "ingress"]
                .iter()
                .any(|w| file.contains(w)),
            "{} -> {file}",
            ringbuf.map
        );
    }
}
