//! On-change emission: which socket fields a probe watches, and the manifest that tells
//! readers a trace file holds step series rather than one record per hook run.

use std::{fmt, fs, io, path::Path};

use serde::{Deserialize, Serialize};

/// Declares `SockField` from one list: variant, column name, bit
macro_rules! sock_fields {
    ($($variant:ident => $name:literal = $bit:literal),* $(,)?) => {
        /// Fields of `sock_trace_entry` an on-change probe can watch. The discriminant is the
        /// bit in the watch mask; it mirrors `enum tcbee_sock_field` in `bpf/onchange.h`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u32)]
        pub enum SockField {
            $($variant = $bit,)*
        }

        impl SockField {
            pub const ALL: &'static [SockField] = &[$(SockField::$variant,)*];

            /// Column name, as in `sock_trace_entry`
            pub fn name(self) -> &'static str {
                match self {
                    $(SockField::$variant => $name,)*
                }
            }
        }
    };
}

sock_fields! {
    PacingRate => "pacing_rate" = 0,
    MaxPacingRate => "max_pacing_rate" = 1,
    Backoff => "backoff" = 2,
    Rto => "rto" = 3,
    RcvMss => "rcv_mss" = 4,
    SndCwnd => "snd_cwnd" = 5,
    BytesAcked => "bytes_acked" = 6,
    SndSsthresh => "snd_ssthresh" = 7,
    TotalRetrans => "total_retrans" = 8,
    Probes => "probes" = 9,
    Lost => "lost" = 10,
    SackedOut => "sacked_out" = 11,
    Retrans => "retrans" = 12,
    RcvSsthresh => "rcv_ssthresh" = 13,
    Rttvar => "rttvar" = 14,
    Advmss => "advmss" = 15,
    Reordering => "reordering" = 16,
    RcvRtt => "rcv_rtt" = 17,
    RcvSpace => "rcv_space" = 18,
    BytesReceived => "bytes_received" = 19,
    SegsOut => "segs_out" = 20,
    SegsIn => "segs_in" = 21,
}

impl SockField {
    pub fn bit(self) -> u32 {
        self as u32
    }

    /// Fields that change on almost every send or ACK: watching one of them writes nearly
    /// every run, which removes the gain of on-change emission.
    pub fn changes_per_packet(self) -> bool {
        matches!(
            self,
            SockField::PacingRate
                | SockField::BytesAcked
                | SockField::Rttvar
                | SockField::BytesReceived
                | SockField::SegsOut
                | SockField::SegsIn
        )
    }

    pub fn from_name(name: &str) -> Option<SockField> {
        SockField::ALL.iter().copied().find(|f| f.name() == name)
    }
}

/// A set of watched socket fields, the `SOCK_WATCH_MASK` of the eBPF programs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WatchSet(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchSetError {
    UnknownField(String),
    /// `field/N` (change only beyond 1/N of the last value) is planned, so the syntax is
    /// rejected with a clear message rather than as an unknown field
    Quantised(String),
    Empty,
}

impl fmt::Display for WatchSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WatchSetError::UnknownField(name) => write!(
                f,
                "unknown field {name:?}, expected one of: {}",
                SockField::ALL
                    .iter()
                    .map(|f| f.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            WatchSetError::Quantised(spec) => {
                write!(f, "{spec:?}: quantised fields are not supported yet")
            }
            WatchSetError::Empty => write!(f, "no field to watch"),
        }
    }
}

impl std::error::Error for WatchSetError {}

impl WatchSet {
    /// Congestion control state: cwnd, ssthresh, retransmissions, backoff, RTO, reordering,
    /// MSS. None of them changes on every packet.
    pub const CC: WatchSet = WatchSet(
        1 << SockField::SndCwnd as u32
            | 1 << SockField::SndSsthresh as u32
            | 1 << SockField::TotalRetrans as u32
            | 1 << SockField::Backoff as u32
            | 1 << SockField::Rto as u32
            | 1 << SockField::Reordering as u32
            | 1 << SockField::RcvMss as u32,
    );

    /// Receive side state: MSS, receive buffer autotuning and window clamp, receiver RTT
    /// estimate. On a receiver ingress runs per data segment, so this is the set that
    /// saves there. rcv_space is adjusted when the application reads (tcp_rcv_space_adjust)
    /// and rcv_ssthresh also when a window is sent, so such a change is recorded at the
    /// next hook run.
    pub const RCV: WatchSet = WatchSet(
        1 << SockField::RcvMss as u32
            | 1 << SockField::RcvSpace as u32
            | 1 << SockField::RcvSsthresh as u32
            | 1 << SockField::RcvRtt as u32,
    );

    /// A preset (`cc`, `rcv`) or a comma-separated list of field names
    pub fn parse(spec: &str) -> Result<WatchSet, WatchSetError> {
        match spec.trim() {
            "cc" => return Ok(WatchSet::CC),
            "rcv" => return Ok(WatchSet::RCV),
            _ => {}
        }
        let mut mask = 0;
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if part.contains('/') {
                return Err(WatchSetError::Quantised(part.to_string()));
            }
            let field = SockField::from_name(part)
                .ok_or_else(|| WatchSetError::UnknownField(part.to_string()))?;
            mask |= 1 << field.bit();
        }
        if mask == 0 {
            return Err(WatchSetError::Empty);
        }
        Ok(WatchSet(mask))
    }

    pub fn mask(self) -> u32 {
        self.0
    }

    pub fn contains(self, field: SockField) -> bool {
        self.0 & (1 << field.bit()) != 0
    }

    pub fn fields(self) -> impl Iterator<Item = SockField> {
        SockField::ALL
            .iter()
            .copied()
            .filter(move |f| self.contains(*f))
    }
}

/// Kernel hooks the sock probe (`-k`) runs at (`--sock-hooks`). On-change mode uses ingress,
/// timer and egress: ingress and timer write the receive file, egress the send file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    /// After a received segment was processed (fexit/tcp_rcv_established in ESTABLISHED,
    /// fexit/tcp_rcv_state_process in the other states)
    Ingress,
    /// After a retransmission, loss probe, RACK reordering or zero window probe timer ran
    /// (fexit/tcp_write_timer_handler), also when it was deferred to tcp_release_cb
    Timer,
    /// Before every transmitted segment (fentry/__tcp_transmit_skb), with the state before
    /// the transmission. One run per segment: the expensive hook on a sender.
    Egress,
    /// Before a received segment is processed in ESTABLISHED (fentry/tcp_rcv_established),
    /// with the state before it. Only without on-change.
    IngressEntry,
    /// The socket event hooks, only without on-change: a TCP state change, a congestion
    /// state change, a retransmitted segment, the cwnd restart after idle, receive buffer
    /// growth
    State,
    CaState,
    Retransmit,
    Restart,
    Rcvbuf,
}

impl Hook {
    pub const ALL: [Hook; 9] = [
        Hook::Ingress,
        Hook::Timer,
        Hook::Egress,
        Hook::IngressEntry,
        Hook::State,
        Hook::CaState,
        Hook::Retransmit,
        Hook::Restart,
        Hook::Rcvbuf,
    ];
    /// The socket event hooks, which write `event_sock.tcp`
    pub const SOCK_EVENTS: [Hook; 5] = [
        Hook::State,
        Hook::CaState,
        Hook::Retransmit,
        Hook::Restart,
        Hook::Rcvbuf,
    ];
    /// The hooks that on-change mode can compare at
    pub const ON_CHANGE: [Hook; 3] = [Hook::Ingress, Hook::Timer, Hook::Egress];

    pub fn name(self) -> &'static str {
        match self {
            Hook::Ingress => "ingress",
            Hook::Timer => "timer",
            Hook::Egress => "egress",
            Hook::IngressEntry => "ingress-entry",
            Hook::State => "state",
            Hook::CaState => "ca-state",
            Hook::Retransmit => "retransmit",
            Hook::Restart => "restart",
            Hook::Rcvbuf => "rcvbuf",
        }
    }

    /// Attach points of the hook's programs
    pub fn kernel_hooks(self) -> &'static [&'static str] {
        match self {
            Hook::Ingress => &["fexit/tcp_rcv_established", "fexit/tcp_rcv_state_process"],
            Hook::Timer => &["fexit/tcp_write_timer_handler"],
            Hook::Egress => &["fentry/__tcp_transmit_skb"],
            Hook::IngressEntry => &["fentry/tcp_rcv_established"],
            Hook::State => &["tp_btf/inet_sock_set_state"],
            Hook::CaState => &["tp_btf/tcp_cong_state_set"],
            Hook::Retransmit => &["tp_btf/tcp_retransmit_skb"],
            Hook::Restart => &["fexit/tcp_cwnd_restart"],
            Hook::Rcvbuf => &["tp_btf/tcp_rcvbuf_grow"],
        }
    }

    /// The hook as sock records carry it in bits 8-15 of `ato`, `enum tcbee_onchg_hook` in
    /// `bpf/onchange.h` (checked in tcbee-common). 0 for the egress and ingress-entry
    /// programs without on-change, which leave `ato` at 0. State and congestion state
    /// records carry the new state in bits 16-23.
    pub const fn tag(self) -> u32 {
        match self {
            Hook::Ingress => 1,
            Hook::Timer => 2,
            Hook::Egress => 3,
            Hook::IngressEntry => 0,
            Hook::State => 4,
            Hook::CaState => 5,
            Hook::Retransmit => 6,
            Hook::Restart => 7,
            Hook::Rcvbuf => 8,
        }
    }

    /// Whether the hook runs once per transmitted or received segment
    pub fn per_packet(self) -> bool {
        matches!(self, Hook::Ingress | Hook::Egress | Hook::IngressEntry)
    }

    pub fn from_name(name: &str) -> Option<Hook> {
        Hook::ALL.into_iter().find(|h| h.name() == name)
    }

    const fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// The hooks the sock probe runs at
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookSet(u16);

impl Default for HookSet {
    fn default() -> HookSet {
        HookSet::DEFAULT
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookSetError {
    UnknownHook(String),
    Empty,
}

impl fmt::Display for HookSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookSetError::UnknownHook(name) => write!(
                f,
                "unknown hook {name:?}, expected one of: {}",
                Hook::ALL.map(Hook::name).join(", ")
            ),
            HookSetError::Empty => write!(f, "no hook"),
        }
    }
}

impl std::error::Error for HookSetError {}

impl HookSet {
    /// Ingress and timer: every change ACK processing and the retransmission timers make,
    /// without a run per transmitted segment
    pub const DEFAULT: HookSet = HookSet(Hook::Ingress.bit() | Hook::Timer.bit());

    /// The hooks of `-k` without on-change: the write timer and the socket events, none that
    /// runs per packet. A saturated sender loses goodput to a hook on its send path, and a
    /// receiver to one per received segment, so those are opt-in.
    pub const FULL_DEFAULT: HookSet = HookSet(
        Hook::Timer.bit()
            | Hook::State.bit()
            | Hook::CaState.bit()
            | Hook::Retransmit.bit()
            | Hook::Restart.bit()
            | Hook::Rcvbuf.bit(),
    );
    /// The hooks of `-k` before the socket events: every transmitted and received segment
    /// and the write timer
    pub const PER_PACKET: HookSet =
        HookSet(Hook::Egress.bit() | Hook::IngressEntry.bit() | Hook::Timer.bit());

    /// A comma-separated list of hook names. A list of only `+name` and `-name` items
    /// changes `base` instead.
    pub fn parse_changes(spec: &str, base: HookSet) -> Result<HookSet, HookSetError> {
        let parts: Vec<&str> = spec
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        if parts.is_empty() || !parts.iter().all(|p| p.starts_with(['+', '-'])) {
            return HookSet::parse(spec);
        }
        let mut bits = base.0;
        for part in parts {
            let (sign, name) = part.split_at(1);
            let hook =
                Hook::from_name(name).ok_or_else(|| HookSetError::UnknownHook(name.to_string()))?;
            if sign == "-" {
                bits &= !hook.bit();
            } else {
                bits |= hook.bit();
            }
        }
        if bits == 0 {
            return Err(HookSetError::Empty);
        }
        Ok(HookSet(bits))
    }

    /// A comma-separated list of hook names
    pub fn parse(spec: &str) -> Result<HookSet, HookSetError> {
        let mut bits = 0;
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let hook =
                Hook::from_name(part).ok_or_else(|| HookSetError::UnknownHook(part.to_string()))?;
            bits |= hook.bit();
        }
        if bits == 0 {
            return Err(HookSetError::Empty);
        }
        Ok(HookSet(bits))
    }

    pub fn contains(self, hook: Hook) -> bool {
        self.0 & hook.bit() != 0
    }

    pub fn without(self, hook: Hook) -> HookSet {
        HookSet(self.0 & !hook.bit())
    }

    pub fn hooks(self) -> impl Iterator<Item = Hook> {
        Hook::ALL.into_iter().filter(move |h| self.contains(*h))
    }

    /// Whether a hook writes the receive file (ingress or timer)
    pub fn receive(self) -> bool {
        self.contains(Hook::Ingress) || self.contains(Hook::Timer)
    }

    /// Whether a hook writes the send file (egress)
    pub fn send(self) -> bool {
        self.contains(Hook::Egress)
    }
}

/// Written next to the trace files when any probe runs in on-change mode. A trace directory
/// without it is format version 1: every source writes one record per hook run.
pub const MANIFEST_FILE: &str = "manifest.json";
pub const MANIFEST_VERSION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u16,
    pub sources: Vec<SourceMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMeta {
    /// Trace file name, e.g. `send_sock_oc.tcp`
    pub file: String,
    pub sampling: Sampling,
    /// Every run is written, with the decision as a reason code in `ato`
    pub shadow: bool,
    /// Kernel hook of the receive side, `fexit/tcp_rcv_established` in on-change mode. Kept
    /// for readers of the first manifest version; `hooks` lists every hook of the file.
    pub recv_hook: String,
    /// Kernel hooks whose records the file holds, e.g. `fexit/tcp_rcv_established` and
    /// `fexit/tcp_write_timer_handler`. Empty in manifests written before the hooks were
    /// listed, when the send file came from fentry/__tcp_transmit_skb and the receive file
    /// from `recv_hook`.
    #[serde(default)]
    pub hooks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum Sampling {
    EveryRun,
    /// A record only when a watched field (or the socket state) changed, after a drop and
    /// on the first run of a flow at a hook
    OnChange {
        fields: Vec<String>,
    },
}

impl Manifest {
    pub fn write(&self, dir: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(dir.join(MANIFEST_FILE), json)
    }

    /// None if the directory has no manifest (format version 1)
    pub fn read(dir: &Path) -> io::Result<Option<Manifest>> {
        match fs::read_to_string(dir.join(MANIFEST_FILE)) {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The entry of one trace file; files the manifest does not list write every run
    pub fn source(&self, file: &str) -> Option<&SourceMeta> {
        self.sources.iter().find(|s| s.file == file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_follow_the_order() {
        for (i, f) in SockField::ALL.iter().enumerate() {
            assert_eq!(f.bit(), i as u32);
            assert_eq!(SockField::from_name(f.name()), Some(*f));
        }
    }

    #[test]
    fn parse_preset_and_lists() {
        assert_eq!(WatchSet::parse("cc").unwrap(), WatchSet::CC);
        assert_eq!(
            WatchSet::parse("rcv").unwrap(),
            WatchSet::parse("rcv_mss,rcv_space,rcv_ssthresh,rcv_rtt").unwrap()
        );
        assert!(WatchSet::RCV.fields().all(|f| !f.changes_per_packet()));
        let set = WatchSet::parse("snd_cwnd, total_retrans,snd_cwnd").unwrap();
        assert_eq!(
            set.fields().collect::<Vec<_>>(),
            [SockField::SndCwnd, SockField::TotalRetrans]
        );
        assert!(WatchSet::CC.fields().all(|f| !f.changes_per_packet()));
    }

    #[test]
    fn parse_errors() {
        assert_eq!(
            WatchSet::parse("cwnd"),
            Err(WatchSetError::UnknownField("cwnd".into()))
        );
        assert_eq!(
            WatchSet::parse("pacing_rate/16"),
            Err(WatchSetError::Quantised("pacing_rate/16".into()))
        );
        assert_eq!(WatchSet::parse(" , "), Err(WatchSetError::Empty));
    }

    #[test]
    fn parse_hooks() {
        assert_eq!(HookSet::default(), HookSet::parse("ingress,timer").unwrap());
        let all = HookSet::parse("egress, ingress,timer,egress").unwrap();
        assert_eq!(all.hooks().collect::<Vec<_>>(), Hook::ON_CHANGE);
        assert!(all.send() && all.receive());
        let ingress = HookSet::parse("ingress").unwrap();
        assert!(ingress.receive() && !ingress.send() && !ingress.contains(Hook::Timer));
        let egress = HookSet::parse("egress").unwrap();
        assert!(egress.send() && !egress.receive());
        assert_eq!(
            HookSet::parse("ingress,rx"),
            Err(HookSetError::UnknownHook("rx".into()))
        );
        assert_eq!(HookSet::parse(""), Err(HookSetError::Empty));
    }

    #[test]
    fn full_default_has_no_per_packet_hook() {
        let full = HookSet::FULL_DEFAULT;
        assert!(full.hooks().all(|h| !h.per_packet()));
        assert!(full.contains(Hook::Timer));
        assert!(Hook::SOCK_EVENTS.iter().all(|h| full.contains(*h)));
    }

    #[test]
    fn parse_hook_changes() {
        let full = HookSet::PER_PACKET;
        assert_eq!(
            HookSet::parse_changes("ingress", full),
            HookSet::parse("ingress")
        );
        let changed = HookSet::parse_changes("+ingress,-egress", full).unwrap();
        assert!(changed.contains(Hook::Ingress) && !changed.contains(Hook::Egress));
        assert!(changed.contains(Hook::IngressEntry) && changed.contains(Hook::Timer));
        assert_eq!(
            full.without(Hook::Timer),
            HookSet::parse("egress,ingress-entry").unwrap()
        );
        assert_eq!(
            HookSet::parse_changes("-timer,-egress,-ingress-entry", full),
            Err(HookSetError::Empty)
        );
        assert_eq!(
            HookSet::parse_changes("+rx", full),
            Err(HookSetError::UnknownHook("rx".into()))
        );
    }

    /// Manifests of the first on-change version have no hook list
    #[test]
    fn manifest_without_hooks() {
        let json = r#"{"format_version": 2, "sources": [{"file": "recv_sock_oc.tcp",
            "sampling": {"mode": "on_change", "fields": ["snd_cwnd"]}, "shadow": false,
            "recv_hook": "fexit/tcp_rcv_established"}]}"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert!(m.sources[0].hooks.is_empty());
    }

    #[test]
    fn manifest_round_trip() {
        let dir = std::env::temp_dir().join(format!("tcbee-manifest-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(Manifest::read(&dir).unwrap(), None);
        let m = Manifest {
            format_version: MANIFEST_VERSION,
            sources: vec![SourceMeta {
                file: "send_sock_oc.tcp".into(),
                sampling: Sampling::OnChange {
                    fields: vec!["snd_cwnd".into()],
                },
                shadow: false,
                recv_hook: "fexit/tcp_rcv_established".into(),
                hooks: vec!["fentry/__tcp_transmit_skb".into()],
            }],
        };
        m.write(&dir).unwrap();
        assert_eq!(Manifest::read(&dir).unwrap(), Some(m.clone()));
        assert!(m.source("send_sock_oc.tcp").is_some());
        assert!(m.source("send_sock.tcp").is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
