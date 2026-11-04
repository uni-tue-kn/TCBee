//! The field groups of a sock record that `--sock-fields` selects, and the layout of the
//! records that hold only some of them.
//!
//! A field-selected record starts with the core (the sock record header, `ato` and
//! `conn_id`, which tcbee-process needs for the flow, the hook and the connection), followed
//! by the selected groups in `Group::ALL` order. In the ring buffer each group is a C struct
//! of `bpf/sockfields.h` at an offset aligned to its widest field; its fields are sorted by
//! size, so no group has padding between its fields. The record length is rounded up to 8
//! bytes, the kernel's ring buffer stride. Trace files hold the packed fields in the same
//! order: `SockShape::runs` copies them out of a ring record, and `SockShape::expand` turns a
//! packed record into a packed full `sock_trace_entry` with the unselected fields zero.

use crate::name_list::{self, ListError, NamedSet};

/// A field of the full sock record: name and size in bytes
pub type Field = (&'static str, usize);

/// The fields of the full sock record (`sock_trace_entry` in `bpf/records.h`) in declaration
/// order, which is also their order in the packed record of a trace file
pub const FULL: &[Field] = &[
    ("time", 8),
    ("hook_seq", 8),
    ("addr_v4", 8),
    ("src_v6", 16),
    ("dst_v6", 16),
    ("sport", 2),
    ("dport", 2),
    ("family", 2),
    ("pacing_rate", 8),
    ("max_pacing_rate", 8),
    ("backoff", 1),
    ("rto", 4),
    ("ato", 4),
    ("rcv_mss", 2),
    ("snd_cwnd", 4),
    ("bytes_acked", 8),
    ("snd_ssthresh", 4),
    ("total_retrans", 4),
    ("probes", 1),
    ("lost", 4),
    ("sacked_out", 4),
    ("retrans", 4),
    ("rcv_ssthresh", 4),
    ("rttvar", 4),
    ("advmss", 2),
    ("reordering", 4),
    ("rcv_rtt", 4),
    ("rcv_space", 4),
    ("bytes_received", 8),
    ("segs_out", 4),
    ("segs_in", 4),
    ("snd_wscale", 2),
    ("rcv_wscale", 2),
    ("ca_state", 1),
    ("packets_out", 4),
    ("delivered", 4),
    ("delivered_ce", 4),
    ("app_limited", 4),
    ("chrono_type", 1),
    ("chrono_busy", 4),
    ("chrono_rwnd_limited", 4),
    ("chrono_sndbuf_limited", 4),
    ("srtt", 4),
    ("mdev", 4),
    ("min_rtt", 4),
    ("snd_una", 4),
    ("snd_nxt", 4),
    ("lost_out", 4),
    ("rate_delivered", 4),
    ("rate_interval_us", 4),
    ("wstamp_ns", 8),
    ("reord_seen", 4),
    ("dsack_dups", 4),
    ("wmem_queued", 4),
    ("sndbuf", 4),
    ("notsent", 4),
    ("conn_id", 4),
];

/// The fields of the sock record header (`TCBEE_SOCK_HEADER`), which take the first
/// `HEADER_BYTES` of a ring record, padded to `HEADER_RING_BYTES`
pub const HEADER: &[Field] = &[
    ("time", 8),
    ("hook_seq", 8),
    ("addr_v4", 8),
    ("src_v6", 16),
    ("dst_v6", 16),
    ("sport", 2),
    ("dport", 2),
    ("family", 2),
];
pub const HEADER_BYTES: usize = 62;
pub const HEADER_RING_BYTES: usize = 64;
/// The core after the header: `ato` (hook tag, event state) and `conn_id`, `struct
/// sock_sel_core` in `bpf/sockfields.h`
pub const CORE_TAIL: &[Field] = &[("ato", 4), ("conn_id", 4)];
pub const CORE_RING_BYTES: usize = 72;

/// Fields that no field-selected record holds: always 0 in the full record
pub const NEVER: &[&str] = &["snd_wscale", "rcv_wscale"];

/// A group of sock record fields that `--sock-fields` selects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Pacing rate and limit, departure time of the next packet
    Pacing,
    /// Retransmission timer state of the connection socket
    Icsk,
    /// The congestion window alone
    Cwnd,
    /// The rest of the congestion control and loss state
    Cc,
    /// Receive side
    Rcv,
    /// Round-trip times
    Rtt,
    /// Congestion state, packets in flight and delivery rate
    Delivery,
    /// Time limited by the application, the receive window or the send buffer
    Chrono,
    /// Sequence numbers, reorderings and duplicates
    Seq,
    /// Send buffer use
    Sndbuf,
}

impl Group {
    pub const ALL: [Group; 10] = [
        Group::Pacing,
        Group::Icsk,
        Group::Cwnd,
        Group::Cc,
        Group::Rcv,
        Group::Rtt,
        Group::Delivery,
        Group::Chrono,
        Group::Seq,
        Group::Sndbuf,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Group::Pacing => "pacing",
            Group::Icsk => "icsk",
            Group::Cwnd => "cwnd",
            Group::Cc => "cc",
            Group::Rcv => "rcv",
            Group::Rtt => "rtt",
            Group::Delivery => "delivery",
            Group::Chrono => "chrono",
            Group::Seq => "seq",
            Group::Sndbuf => "sndbuf",
        }
    }

    /// The group's fields in the order of its struct in `bpf/sockfields.h`: by size,
    /// largest first
    pub fn fields(self) -> &'static [Field] {
        match self {
            Group::Pacing => &[("pacing_rate", 8), ("max_pacing_rate", 8), ("wstamp_ns", 8)],
            Group::Icsk => &[("rto", 4), ("rcv_mss", 2), ("backoff", 1)],
            Group::Cwnd => &[("snd_cwnd", 4)],
            Group::Cc => &[
                ("bytes_acked", 8),
                ("snd_ssthresh", 4),
                ("total_retrans", 4),
                ("lost", 4),
                ("sacked_out", 4),
                ("retrans", 4),
                ("reordering", 4),
                ("segs_out", 4),
                ("probes", 1),
            ],
            Group::Rcv => &[
                ("bytes_received", 8),
                ("rcv_ssthresh", 4),
                ("rcv_rtt", 4),
                ("rcv_space", 4),
                ("segs_in", 4),
                ("advmss", 2),
            ],
            Group::Rtt => &[("srtt", 4), ("mdev", 4), ("min_rtt", 4), ("rttvar", 4)],
            Group::Delivery => &[
                ("packets_out", 4),
                ("delivered", 4),
                ("delivered_ce", 4),
                ("app_limited", 4),
                ("rate_delivered", 4),
                ("rate_interval_us", 4),
                ("lost_out", 4),
                ("ca_state", 1),
            ],
            Group::Chrono => &[
                ("chrono_busy", 4),
                ("chrono_rwnd_limited", 4),
                ("chrono_sndbuf_limited", 4),
                ("chrono_type", 1),
            ],
            Group::Seq => &[
                ("snd_una", 4),
                ("snd_nxt", 4),
                ("reord_seen", 4),
                ("dsack_dups", 4),
            ],
            Group::Sndbuf => &[("wmem_queued", 4), ("sndbuf", 4), ("notsent", 4)],
        }
    }

    /// Bytes of the group's fields
    pub fn packed_bytes(self) -> usize {
        self.fields().iter().map(|(_, size)| size).sum()
    }

    /// Alignment of the group's struct: its widest field
    pub fn align(self) -> usize {
        self.fields()
            .iter()
            .map(|(_, size)| *size)
            .max()
            .unwrap_or(1)
    }

    /// Size of the group's struct: its fields, padded to its alignment
    pub fn ring_bytes(self) -> usize {
        round_up(self.packed_bytes(), self.align())
    }

    fn bit(self) -> u16 {
        1 << self as u16
    }
}

fn round_up(n: usize, to: usize) -> usize {
    n.div_ceil(to) * to
}

/// The groups `--sock-fields` selects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFields(u16);

impl SockFields {
    /// Every group: the full record's fields, in a field-selected layout
    pub const ALL: SockFields = SockFields((1 << Group::ALL.len()) - 1);

    /// Parses `--sock-fields`, a list of groups in the `name_list` grammar (`all` and
    /// `default` name every group)
    pub fn parse(spec: &str) -> Result<SockFields, ListError> {
        name_list::parse(spec, SockFields::ALL)
    }

    pub fn of(groups: &[Group]) -> SockFields {
        groups
            .iter()
            .fold(SockFields(0), |set, group| set.with(*group))
    }

    pub fn contains(self, group: Group) -> bool {
        self.0 & group.bit() != 0
    }

    pub fn groups(self) -> impl Iterator<Item = Group> {
        Group::ALL.into_iter().filter(move |g| self.contains(*g))
    }

    /// The groups as a bit mask, bit `n` for `Group::ALL[n]`
    pub fn mask(self) -> u16 {
        self.0
    }

    pub fn from_mask(mask: u16) -> Option<SockFields> {
        (mask & !SockFields::ALL.0 == 0).then_some(SockFields(mask))
    }

    /// The names of the selected groups, for the manifest
    pub fn names(self) -> Vec<&'static str> {
        self.groups().map(Group::name).collect()
    }
}

impl NamedSet for SockFields {
    type Item = Group;
    const KIND: &'static str = "sock field group";
    const ITEMS: &'static [Group] = &Group::ALL;

    fn item_name(group: Group) -> &'static str {
        group.name()
    }

    fn empty() -> SockFields {
        SockFields(0)
    }

    fn with(self, group: Group) -> SockFields {
        SockFields(self.0 | group.bit())
    }

    fn without(self, group: Group) -> SockFields {
        SockFields(self.0 & !group.bit())
    }

    fn contains(self, group: Group) -> bool {
        SockFields::contains(self, group)
    }

    fn is_empty(self) -> bool {
        // The core alone is a valid record, but a list naming no group is a mistake
        self.0 == 0
    }
}

/// Group offset of a group that a record does not hold, `SOCK_SEL_ABSENT` in
/// `bpf/sockfields.h`
pub const ABSENT: u16 = 0xffff;

/// The layout of a field-selected sock record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockShape {
    pub fields: SockFields,
    /// Offset of each group of `Group::ALL` in a ring record, `ABSENT` if not selected
    pub offsets: [u16; Group::ALL.len()],
    /// Bytes of a ring record, a multiple of 8
    pub ring_len: usize,
    /// Bytes of a packed record (without the trace file's delimiter)
    pub file_len: usize,
}

impl SockShape {
    pub fn of(fields: SockFields) -> SockShape {
        let mut offsets = [ABSENT; Group::ALL.len()];
        let mut end = CORE_RING_BYTES;
        let mut file_len = HEADER_BYTES + packed(CORE_TAIL);
        for (i, group) in Group::ALL.into_iter().enumerate() {
            if fields.contains(group) {
                let at = round_up(end, group.align());
                offsets[i] = at as u16;
                end = at + group.ring_bytes();
                file_len += group.packed_bytes();
            }
        }
        SockShape {
            fields,
            offsets,
            ring_len: round_up(end, 8),
            file_len,
        }
    }

    /// The byte runs (offset, length) of a ring record that make up its packed record, in
    /// order
    pub fn runs(&self) -> Vec<(usize, usize)> {
        let mut runs = vec![(0, HEADER_BYTES), (HEADER_RING_BYTES, packed(CORE_TAIL))];
        for (i, group) in Group::ALL.into_iter().enumerate() {
            if self.offsets[i] != ABSENT {
                runs.push((self.offsets[i] as usize, group.packed_bytes()));
            }
        }
        runs
    }

    /// The fields of a packed record in order
    pub fn packed_fields(&self) -> Vec<Field> {
        let mut fields: Vec<Field> = HEADER.iter().chain(CORE_TAIL).copied().collect();
        for group in self.fields.groups() {
            fields.extend_from_slice(group.fields());
        }
        fields
    }

    /// Names of the full record's fields that the records do not hold
    pub fn missing(&self) -> Vec<&'static str> {
        let held: Vec<&str> = self.packed_fields().iter().map(|(name, _)| *name).collect();
        FULL.iter()
            .map(|(name, _)| *name)
            .filter(|name| !held.contains(name))
            .collect()
    }

    /// Copy runs (packed offset, full packed offset, length) that turn a packed record into a
    /// packed full record, one per field
    pub fn expansion(&self) -> Vec<(usize, usize, usize)> {
        let full = full_offsets();
        let mut at = 0;
        self.packed_fields()
            .into_iter()
            .map(|(name, size)| {
                let run = (at, full_offset(&full, name), size);
                at += size;
                run
            })
            .collect()
    }

    /// Writes the packed full record of the packed record `packed` to `full` (zeroed first)
    pub fn expand(&self, expansion: &[(usize, usize, usize)], packed: &[u8], full: &mut [u8]) {
        full.fill(0);
        for &(from, to, len) in expansion {
            full[to..to + len].copy_from_slice(&packed[from..from + len]);
        }
    }
}

fn packed(fields: &[Field]) -> usize {
    fields.iter().map(|(_, size)| size).sum()
}

/// Bytes of the packed full record
pub fn full_bytes() -> usize {
    packed(FULL)
}

fn full_offsets() -> Vec<(&'static str, usize)> {
    let mut at = 0;
    FULL.iter()
        .map(|(name, size)| {
            let field = (*name, at);
            at += size;
            field
        })
        .collect()
}

fn full_offset(full: &[(&'static str, usize)], name: &str) -> usize {
    full.iter()
        .find(|(n, _)| *n == name)
        .map(|(_, at)| *at)
        .expect("every group field is a field of the full record")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_cover_the_full_record_once() {
        let mut names: Vec<&str> = HEADER
            .iter()
            .chain(CORE_TAIL)
            .map(|(name, _)| *name)
            .collect();
        for group in Group::ALL {
            names.extend(group.fields().iter().map(|(name, _)| *name));
        }
        names.extend_from_slice(NEVER);
        names.sort();
        let mut full: Vec<&str> = FULL.iter().map(|(name, _)| *name).collect();
        full.sort();
        assert_eq!(names, full);
        for group in Group::ALL {
            for (name, size) in group.fields() {
                assert!(
                    FULL.contains(&(name, *size)),
                    "{name} has the size of the full record"
                );
            }
            let sizes: Vec<usize> = group.fields().iter().map(|(_, size)| *size).collect();
            assert!(
                sizes.windows(2).all(|w| w[0] >= w[1]),
                "{group:?} sorted by size"
            );
        }
        assert_eq!(full_bytes(), 262 - 4);
    }

    #[test]
    fn group_structs() {
        // The sizes asserted for the structs in bpf/sockfields.h
        let sizes: Vec<usize> = Group::ALL.iter().map(|g| g.ring_bytes()).collect();
        assert_eq!(sizes, [24, 8, 4, 40, 32, 16, 32, 16, 16, 12]);
    }

    #[test]
    fn shapes() {
        let cwnd = SockShape::of(SockFields::of(&[Group::Cwnd]));
        assert_eq!(cwnd.ring_len, 80);
        assert_eq!(cwnd.file_len, 74);
        assert_eq!(
            cwnd.offsets[Group::ALL.iter().position(|g| *g == Group::Cwnd).unwrap()],
            72
        );
        assert_eq!(cwnd.runs(), [(0, 62), (64, 8), (72, 4)]);

        let all = SockShape::of(SockFields::ALL);
        assert_eq!(all.file_len, full_bytes() - 4);
        assert_eq!(all.missing(), NEVER);
        for (i, group) in Group::ALL.into_iter().enumerate() {
            let at = all.offsets[i] as usize;
            assert_eq!(at % group.align(), 0);
            assert!(at + group.ring_bytes() <= all.ring_len);
        }
        assert_eq!(all.ring_len % 8, 0);
        let packed: usize = all.runs().iter().map(|(_, len)| len).sum();
        assert_eq!(packed, all.file_len);
    }

    #[test]
    fn expand_puts_every_field_back() {
        // A full packed record whose bytes count up, reduced to every subset of two groups
        let full: Vec<u8> = (0..full_bytes()).map(|i| i as u8).collect();
        let full_at = full_offsets();
        for a in Group::ALL {
            for b in Group::ALL {
                let shape = SockShape::of(SockFields::of(&[a, b]));
                let packed: Vec<u8> = shape
                    .packed_fields()
                    .iter()
                    .flat_map(|(name, size)| {
                        let at = full_offset(&full_at, name);
                        full[at..at + size].to_vec()
                    })
                    .collect();
                assert_eq!(packed.len(), shape.file_len);
                let mut back = vec![0xaa; full_bytes()];
                shape.expand(&shape.expansion(), &packed, &mut back);
                let missing = shape.missing();
                for (name, at) in &full_at {
                    let size = FULL.iter().find(|(n, _)| n == name).unwrap().1;
                    let want: Vec<u8> = if missing.contains(name) {
                        vec![0; size]
                    } else {
                        full[*at..at + size].to_vec()
                    };
                    assert_eq!(back[*at..at + size], want[..], "{name} with {a:?}, {b:?}");
                }
            }
        }
    }

    #[test]
    fn parse_groups() {
        assert_eq!(SockFields::parse("all"), Ok(SockFields::ALL));
        assert_eq!(
            SockFields::parse("cwnd, rtt"),
            Ok(SockFields::of(&[Group::Cwnd, Group::Rtt]))
        );
        assert_eq!(
            SockFields::parse("all,-chrono").map(|f| f.contains(Group::Chrono)),
            Ok(false)
        );
        assert!(SockFields::parse("cwnd,ttl").is_err());
        assert!(SockFields::parse("").is_err());
        assert_eq!(
            SockFields::from_mask(SockFields::ALL.mask()),
            Some(SockFields::ALL)
        );
        assert_eq!(SockFields::from_mask(1 << 15), None);
    }
}
