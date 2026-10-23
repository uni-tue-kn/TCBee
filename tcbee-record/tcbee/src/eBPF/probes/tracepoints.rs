use std::error::Error;

use anyhow::anyhow;
use libbpf_rs::{Link, MapMut, ProgramMut};
use serde::Serialize;
use tcbee_common::{
    records::{tcp_bad_csum_entry, tcp_probe_entry, tcp_retransmit_synack_entry},
    stats::{RB_BAD_CSUM, RB_RETRANSMIT_SYNACK, RB_TCP_PROBE},
};
use tcbee_trace::name_list::{self, NamedSet};

use crate::{
    eBPF::{
        probes::attach,
        rings,
        skel::{OpenTcbeeProgs, TcbeeSkel},
    },
    writer::Writer,
};

/// A tracepoint of `-t`, by its `--tp` name: a classic tracepoint with a program of its own
/// (`TracepointTracer`) or a TCP event hook (`TCP_EVENT_HOOKS`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tracepoint {
    Probe,
    Synack,
    BadCsum,
    Retransmit,
    RstSent,
    RstReceived,
    State,
    CaState,
    Rto,
    Destroy,
    /// kfree_skb: packets of TCP flows the kernel drops, with the reason
    Drops,
}

impl Tracepoint {
    pub const ALL: [Tracepoint; 11] = [
        Tracepoint::Probe,
        Tracepoint::Synack,
        Tracepoint::BadCsum,
        Tracepoint::Retransmit,
        Tracepoint::RstSent,
        Tracepoint::RstReceived,
        Tracepoint::State,
        Tracepoint::CaState,
        Tracepoint::Rto,
        Tracepoint::Destroy,
        Tracepoint::Drops,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Tracepoint::Probe => "probe",
            Tracepoint::Synack => "synack",
            Tracepoint::BadCsum => "bad_csum",
            Tracepoint::Retransmit => "retransmit",
            Tracepoint::RstSent => "rst_sent",
            Tracepoint::RstReceived => "rst_received",
            Tracepoint::State => "state",
            Tracepoint::CaState => "ca_state",
            Tracepoint::Rto => "rto",
            Tracepoint::Destroy => "destroy",
            Tracepoint::Drops => "drops",
        }
    }

    pub fn from_name(name: &str) -> Option<Tracepoint> {
        Tracepoint::ALL.into_iter().find(|tp| tp.name() == name)
    }

    /// Whether a plain `-t` records it
    pub const fn in_default(self) -> bool {
        !matches!(self, Tracepoint::Drops)
    }

    const fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// The tracepoints `-t` records
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracepointSet(u16);

impl TracepointSet {
    /// None, as without `-t`
    pub const EMPTY: TracepointSet = TracepointSet(0);
    /// What a plain `-t` records: all but the opt-in drops
    pub const DEFAULT: TracepointSet = {
        let mut bits = 0;
        let mut i = 0;
        while i < Tracepoint::ALL.len() {
            if Tracepoint::ALL[i].in_default() {
                bits |= Tracepoint::ALL[i].bit();
            }
            i += 1;
        }
        TracepointSet(bits)
    };
    pub const ALL: TracepointSet = TracepointSet::of(&Tracepoint::ALL);
    /// The TCP events, which `-e` records: the ones it recorded before -t had them, and the
    /// destroyed sockets, which came with -t
    pub const EVENTS: TracepointSet = TracepointSet::of(&[
        Tracepoint::Retransmit,
        Tracepoint::RstSent,
        Tracepoint::RstReceived,
        Tracepoint::State,
        Tracepoint::CaState,
        Tracepoint::Rto,
        Tracepoint::Destroy,
    ]);

    pub const fn of(tracepoints: &[Tracepoint]) -> TracepointSet {
        let mut bits = 0;
        let mut i = 0;
        while i < tracepoints.len() {
            bits |= tracepoints[i].bit();
            i += 1;
        }
        TracepointSet(bits)
    }

    pub fn union(self, other: TracepointSet) -> TracepointSet {
        TracepointSet(self.0 | other.0)
    }

    pub fn contains(self, tracepoint: Tracepoint) -> bool {
        self.0 & tracepoint.bit() != 0
    }

    /// Whether the sets have a tracepoint in common
    pub fn intersects(self, other: TracepointSet) -> bool {
        self.0 & other.0 != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Parses `--tp`, a list of tracepoint names (`name_list`) that changes the default set
    pub fn parse(arg: &str) -> anyhow::Result<TracepointSet> {
        name_list::parse(arg, TracepointSet::DEFAULT).map_err(|e| anyhow!("--tp: {}", e))
    }
}

impl NamedSet for TracepointSet {
    type Item = Tracepoint;
    const KIND: &'static str = "tracepoint";
    const ITEMS: &'static [Tracepoint] = &Tracepoint::ALL;

    fn item_name(tracepoint: Tracepoint) -> &'static str {
        tracepoint.name()
    }

    fn empty() -> TracepointSet {
        TracepointSet::EMPTY
    }

    fn with(self, tracepoint: Tracepoint) -> TracepointSet {
        TracepointSet(self.0 | tracepoint.bit())
    }

    fn without(self, tracepoint: Tracepoint) -> TracepointSet {
        TracepointSet(self.0 & !tracepoint.bit())
    }

    fn contains(self, tracepoint: Tracepoint) -> bool {
        TracepointSet::contains(self, tracepoint)
    }

    fn is_empty(self) -> bool {
        TracepointSet::is_empty(self)
    }
}

/// The classic tracepoints of `-t`; the other ones are TCP event hooks
pub struct TracepointTracer {}

impl TracepointTracer {
    /// The tracepoints with a program of this tracer
    pub const TRACEPOINTS: TracepointSet =
        TracepointSet::of(&[Tracepoint::Probe, Tracepoint::Synack, Tracepoint::BadCsum]);

    pub fn configure(progs: &mut OpenTcbeeProgs<'_>, set: TracepointSet) {
        progs
            .tcp_probe
            .set_autoload(set.contains(Tracepoint::Probe));
        progs
            .tcp_retransmit_synack
            .set_autoload(set.contains(Tracepoint::Synack));
        progs
            .tcp_bad_csum
            .set_autoload(set.contains(Tracepoint::BadCsum));
    }

    pub fn spawn(
        skel: &TcbeeSkel<'_>,
        set: TracepointSet,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        let (progs, maps) = (&skel.progs, &skel.maps);
        if set.contains(Tracepoint::Probe) {
            Self::spawn_one::<tcp_probe_entry>(
                &progs.tcp_probe,
                &maps.TCP_PROBE_QUEUE,
                RB_TCP_PROBE,
                dir,
                writer,
                links,
            )?;
        }
        if set.contains(Tracepoint::Synack) {
            Self::spawn_one::<tcp_retransmit_synack_entry>(
                &progs.tcp_retransmit_synack,
                &maps.TCP_RETRANSMIT_SYNACK_QUEUE,
                RB_RETRANSMIT_SYNACK,
                dir,
                writer,
                links,
            )?;
        }
        if set.contains(Tracepoint::BadCsum) {
            Self::spawn_one::<tcp_bad_csum_entry>(
                &progs.tcp_bad_csum,
                &maps.TCP_BAD_CSUM_QUEUE,
                RB_BAD_CSUM,
                dir,
                writer,
                links,
            )?;
        }
        Ok(())
    }

    // T is the record type of the ring buffer
    fn spawn_one<T: Serialize + Copy + Send + 'static>(
        program: &ProgramMut<'_>,
        map: &MapMut<'_>,
        rb: u32,
        dir: &str,
        writer: &mut Writer,
        links: &mut Vec<Link>,
    ) -> Result<(), Box<dyn Error>> {
        // Attaches to the tracepoint named in the program's section
        attach(program, links)?;
        writer.register::<T>(rb, rings::of(map)?, dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracepoint_lists() {
        let default = TracepointSet::DEFAULT;
        assert!(default.contains(Tracepoint::Probe) && default.contains(Tracepoint::Destroy));
        assert!(!default.contains(Tracepoint::Drops));
        assert_eq!(TracepointSet::parse("default").unwrap(), default);
        assert_eq!(
            TracepointSet::parse("probe, rto").unwrap(),
            TracepointSet::of(&[Tracepoint::Probe, Tracepoint::Rto])
        );
        let changed = TracepointSet::parse("+drops,-probe").unwrap();
        assert!(changed.contains(Tracepoint::Drops) && !changed.contains(Tracepoint::Probe));
        assert!(changed.contains(Tracepoint::State));
        assert_eq!(
            TracepointSet::parse("all,-drops").unwrap(),
            TracepointSet::DEFAULT
        );
        assert_eq!(
            TracepointSet::parse("probe,+drops,ca-state").unwrap(),
            TracepointSet::of(&[Tracepoint::Probe, Tracepoint::Drops, Tracepoint::CaState])
        );
        assert!(TracepointSet::parse("probe,cwnd").is_err());
        assert!(TracepointSet::parse(" , ").is_err());
        assert!(TracepointSet::parse("-all").is_err());
    }

    #[test]
    fn names_round_trip() {
        for tracepoint in Tracepoint::ALL {
            assert_eq!(Tracepoint::from_name(tracepoint.name()), Some(tracepoint));
        }
    }
}
