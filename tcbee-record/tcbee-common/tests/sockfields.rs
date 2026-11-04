//! The field table of `tcbee_trace::sockfields` names the fields of `sock_trace_entry` by
//! hand. This test checks it against the generated struct: the same fields in the same order
//! with the same sizes, and the header where the ring record has it.

use std::mem::offset_of;

use tcbee_common::records::sock_trace_entry;
use tcbee_trace::sockfields::{self, FULL, HEADER, HEADER_BYTES, HEADER_RING_BYTES};

/// Fields (name, size) of a struct in `records_gen.rs`, in order
fn generated_fields(name: &str) -> Vec<(String, usize)> {
    let src = include_str!("../src/records_gen.rs");
    let start = src
        .find(&format!("pub struct {name} {{"))
        .unwrap_or_else(|| panic!("{name} in records_gen.rs"));
    let body = &src[start..src[start..].find('}').unwrap() + start];
    body.lines()
        .filter_map(|line| {
            let (field, ty) = line.trim().strip_prefix("pub ")?.split_once(": ")?;
            let size = match ty.trim_end_matches(',') {
                "u8" => 1,
                "u16" => 2,
                "u32" => 4,
                "u64" => 8,
                "[u8; 16usize]" => 16,
                other => panic!("unexpected type {other} of {field}"),
            };
            Some((field.to_string(), size))
        })
        .collect()
}

#[test]
fn table_matches_sock_trace_entry() {
    let table: Vec<(String, usize)> = FULL
        .iter()
        .map(|(name, size)| (name.to_string(), *size))
        .collect();
    assert_eq!(table, generated_fields("sock_trace_entry"));
    assert!(FULL.starts_with(HEADER));
    let header: usize = HEADER.iter().map(|(_, size)| size).sum();
    assert_eq!(header, HEADER_BYTES);
    assert_eq!(offset_of!(sock_trace_entry, pacing_rate), HEADER_RING_BYTES);
    assert_eq!(sockfields::full_bytes(), 258);
}
