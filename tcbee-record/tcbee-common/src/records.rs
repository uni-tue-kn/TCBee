//! Ring buffer records and map keys, generated from `tcbee/src/bpf/records.h` into
//! `records_gen.rs` (see `tests/records_gen.rs`).
//!
//! The trace files are bincode serialised field by field, so changing a field's order or
//! type here changes the on-disk format. The size asserts catch accidental changes.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

include!("records_gen.rs");

/// Written after every record in a trace file. Readers check it to detect misaligned files.
pub const RECORD_DELIMITER: [u8; 4] = [0xFF; 4];

use core::mem::size_of;

const _: () = assert!(size_of::<tcp4_packet_trace>() == 48);
const _: () = assert!(size_of::<tcp6_packet_trace>() == 72);
const _: () = assert!(size_of::<sock_trace_entry>() == 280);
const _: () = assert!(size_of::<cwnd_trace_entry>() == 72);
const _: () = assert!(size_of::<cubic_trace_entry>() == 120);
const _: () = assert!(size_of::<bbr_trace_entry>() == 176);
const _: () = assert!(size_of::<reno_trace_entry>() == 96);
const _: () = assert!(size_of::<tcp_probe_entry>() == 128);
const _: () = assert!(size_of::<tcp_retransmit_synack_entry>() == 64);
const _: () = assert!(size_of::<tcp_bad_csum_entry>() == 24);
const _: () = assert!(size_of::<mptcp_pm_entry>() == 136);
const _: () = assert!(size_of::<tcp_event_entry>() == 96);
const _: () = assert!(size_of::<IpTuple>() == 38);
const _: () = assert!(size_of::<hook_seq_key>() == 40);
const _: () = assert!(size_of::<FilterIp>() == 16);

// The hook tags of sock records in tcbee-trace mirror enum tcbee_onchg_hook
mod onchg_hooks {
    use super::*;
    use tcbee_trace::onchange::Hook;

    const _: () = assert!(Hook::Ingress.tag() == ONCHG_HOOK_INGRESS);
    const _: () = assert!(Hook::Timer.tag() == ONCHG_HOOK_TIMER);
    const _: () = assert!(Hook::Egress.tag() == ONCHG_HOOK_EGRESS);
    const _: () = assert!(Hook::State.tag() == ONCHG_HOOK_STATE);
    const _: () = assert!(Hook::CaState.tag() == ONCHG_HOOK_CA_STATE);
    const _: () = assert!(Hook::Retransmit.tag() == ONCHG_HOOK_RETRANSMIT);
    const _: () = assert!(Hook::Restart.tag() == ONCHG_HOOK_RESTART);
    const _: () = assert!(Hook::Rcvbuf.tag() == ONCHG_HOOK_RCVBUF);
}

// The watchable socket fields in tcbee-trace mirror enum tcbee_sock_field (bpf/onchange.h)
mod sock_fields {
    use super::*;
    use tcbee_trace::onchange::SockField as F;

    macro_rules! same {
        ($($rust:ident = $c:ident),* $(,)?) => {
            $(const _: () = assert!(F::$rust as u32 == $c);)*
            const _: () = assert!(F::ALL.len() as u32 == SF_COUNT);
        };
    }

    same!(
        PacingRate = SF_pacing_rate,
        MaxPacingRate = SF_max_pacing_rate,
        Backoff = SF_backoff,
        Rto = SF_rto,
        RcvMss = SF_rcv_mss,
        SndCwnd = SF_snd_cwnd,
        BytesAcked = SF_bytes_acked,
        SndSsthresh = SF_snd_ssthresh,
        TotalRetrans = SF_total_retrans,
        Probes = SF_probes,
        Lost = SF_lost,
        SackedOut = SF_sacked_out,
        Retrans = SF_retrans,
        RcvSsthresh = SF_rcv_ssthresh,
        Rttvar = SF_rttvar,
        Advmss = SF_advmss,
        Reordering = SF_reordering,
        RcvRtt = SF_rcv_rtt,
        RcvSpace = SF_rcv_space,
        BytesReceived = SF_bytes_received,
        SegsOut = SF_segs_out,
        SegsIn = SF_segs_in,
    );
}
