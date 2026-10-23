//! The kernel hooks of the sock probe (`-k`, `--sock-hooks`) and of on-change mode
//! (`--on-change-hooks`), and how sock records tell which hook wrote them.

use crate::name_list::{self, ListError, NamedSet};

/// Bits 8-15 of a sock record's `ato` hold the tag of its hook (`Hook::record_tag`);
/// `SOCK_HOOK_SHIFT` in `bpf/onchange.h`
pub const HOOK_SHIFT: u32 = 8;
/// Bits 16-23 of the `ato` of a state or congestion state record hold the new state;
/// `SOCK_EVENT_STATE_SHIFT` in `bpf/onchange.h`
pub const STATE_SHIFT: u32 = 16;

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

    /// The hook's value in `enum tcbee_sock_hook` (`bpf/onchange.h`, checked in tcbee-common).
    /// None for ingress-entry, whose program writes no tag.
    pub const fn tag(self) -> Option<u32> {
        match self {
            Hook::Ingress => Some(1),
            Hook::Timer => Some(2),
            Hook::Egress => Some(3),
            Hook::IngressEntry => None,
            Hook::State => Some(4),
            Hook::CaState => Some(5),
            Hook::Retransmit => Some(6),
            Hook::Restart => Some(7),
            Hook::Rcvbuf => Some(8),
        }
    }

    /// What the hook's records carry in bits 8-15 of `ato`: its tag, but 0 from the egress
    /// and ingress-entry programs without on-change (`send_sock.tcp`, `recv_sock.tcp`), which
    /// leave `ato` at 0
    pub const fn record_tag(self, on_change: bool) -> u32 {
        match (self, self.tag()) {
            (Hook::Egress, _) if !on_change => 0,
            (_, Some(tag)) => tag,
            (_, None) => 0,
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

impl HookSet {
    /// The hooks of on-change mode by default, ingress and timer: every change ACK processing
    /// and the retransmission timers make, without a run per transmitted segment
    pub const DEFAULT: HookSet = HookSet::of(&[Hook::Ingress, Hook::Timer]);

    /// The hooks of `-k` without on-change: the write timer and the socket events, none that
    /// runs per packet. A saturated sender loses goodput to a hook on its send path, and a
    /// receiver to one per received segment, so those are opt-in.
    pub const FULL_DEFAULT: HookSet = HookSet::of(&[
        Hook::Timer,
        Hook::State,
        Hook::CaState,
        Hook::Retransmit,
        Hook::Restart,
        Hook::Rcvbuf,
    ]);

    pub const fn of(hooks: &[Hook]) -> HookSet {
        let mut bits = 0;
        let mut i = 0;
        while i < hooks.len() {
            bits |= hooks[i].bit();
            i += 1;
        }
        HookSet(bits)
    }

    /// Parses a list of hook names (`name_list`); `default` is the set that a list of only
    /// changes starts from
    pub fn parse(spec: &str, default: HookSet) -> Result<HookSet, ListError> {
        name_list::parse(spec, default)
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

impl NamedSet for HookSet {
    type Item = Hook;
    const KIND: &'static str = "hook";
    const ITEMS: &'static [Hook] = &Hook::ALL;

    fn item_name(hook: Hook) -> &'static str {
        hook.name()
    }

    fn empty() -> HookSet {
        HookSet(0)
    }

    fn with(self, hook: Hook) -> HookSet {
        HookSet(self.0 | hook.bit())
    }

    fn without(self, hook: Hook) -> HookSet {
        HookSet::without(self, hook)
    }

    fn contains(self, hook: Hook) -> bool {
        HookSet::contains(self, hook)
    }

    fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hooks() {
        let default = HookSet::DEFAULT;
        let all = HookSet::parse("egress, ingress,timer,egress", default).unwrap();
        assert_eq!(all.hooks().collect::<Vec<_>>(), Hook::ON_CHANGE);
        assert!(all.send() && all.receive());
        let ingress = HookSet::of(&[Hook::Ingress]);
        assert!(ingress.receive() && !ingress.send() && !ingress.contains(Hook::Timer));
        let egress = HookSet::of(&[Hook::Egress]);
        assert!(egress.send() && !egress.receive());
        assert_eq!(
            HookSet::parse("ingress_entry,ca-state", default),
            Ok(HookSet::of(&[Hook::IngressEntry, Hook::CaState]))
        );
        assert!(HookSet::parse("ingress,rx", default).is_err());
        assert!(HookSet::parse("", default).is_err());
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
        let base = HookSet::of(&[Hook::Egress, Hook::IngressEntry, Hook::Timer]);
        assert_eq!(
            HookSet::parse("ingress", base),
            Ok(HookSet::of(&[Hook::Ingress]))
        );
        let changed = HookSet::parse("+ingress,-egress", base).unwrap();
        assert!(changed.contains(Hook::Ingress) && !changed.contains(Hook::Egress));
        assert!(changed.contains(Hook::IngressEntry) && changed.contains(Hook::Timer));
        assert_eq!(
            HookSet::parse("timer,+egress", base),
            Ok(HookSet::of(&[Hook::Timer, Hook::Egress]))
        );
        assert_eq!(
            HookSet::parse("-timer,-egress,-ingress-entry", base),
            Err(ListError::Empty { kind: "hook" })
        );
        assert!(HookSet::parse("+rx", base).is_err());
    }

    /// Only the default per-segment programs leave the tag out
    #[test]
    fn record_tags() {
        for hook in Hook::ALL {
            assert_eq!(hook.record_tag(true), hook.tag().unwrap_or(0));
        }
        assert_eq!(Hook::Egress.record_tag(false), 0);
        assert_eq!(Hook::IngressEntry.record_tag(false), 0);
        assert_eq!(Hook::Ingress.record_tag(false), 1);
        assert_eq!(Hook::Rcvbuf.record_tag(false), 8);
    }
}
