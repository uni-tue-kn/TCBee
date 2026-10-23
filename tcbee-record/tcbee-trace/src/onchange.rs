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
