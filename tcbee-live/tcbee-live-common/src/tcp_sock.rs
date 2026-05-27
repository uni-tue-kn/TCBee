// Minimal hand-written bindings — replaces the 65k-line aya-tool generated file.
// Only structs and fields accessed by the eBPF probes are kept.
// All gaps are filled with _pad_* byte arrays to preserve exact kernel field offsets
// (verified with `pahole` against the running kernel's BTF).

// ---- in6_addr (used inside sock_common) ------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
pub union in6_addr__bindgen_ty_1 {
    pub u6_addr8: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub in6_u: in6_addr__bindgen_ty_1,
}

// ---- sock_common (size: 136) ------------------------------------------------
// Accessed fields and their byte offsets (from pahole):
//   skc_addrpair   @ 0   (u64)
//   skc_portpair   @ 12  (u32)
//   skc_family     @ 16  (u16)
//   skc_v6_daddr   @ 56  (in6_addr, 16 bytes)
//   skc_v6_rcv_saddr @ 72 (in6_addr, 16 bytes)

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_common__bindgen_anon_1__bindgen_anon_1 {
    pub skc_daddr: u32,
    pub skc_rcv_saddr: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union sock_common__bindgen_anon_1 {
    pub skc_addrpair: u64,
    pub __bindgen_anon_1: sock_common__bindgen_anon_1__bindgen_anon_1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union sock_common__bindgen_anon_3 {
    pub skc_portpair: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_common {
    pub __bindgen_anon_1: sock_common__bindgen_anon_1, //  0..8
    pub _pad_8: [u8; 4],                               //  8..12  (skc_hash)
    pub __bindgen_anon_3: sock_common__bindgen_anon_3, // 12..16
    pub skc_family: u16,                               // 16..18
    pub _pad_18: [u8; 38],                             // 18..56
    pub skc_v6_daddr: in6_addr,                        // 56..72
    pub skc_v6_rcv_saddr: in6_addr,                    // 72..88
    pub _pad_88: [u8; 48],                             // 88..136
}

// ---- sock (size: 808) -------------------------------------------------------
// Accessed fields:
//   __sk_common       @ 0    (sock_common, 136 bytes)
//   sk_pacing_rate    @ 488  (u64)
//   sk_max_pacing_rate @ 520 (u64)

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock {
    pub __sk_common: sock_common,    //   0..136
    pub _pad_136: [u8; 352],         // 136..488
    pub sk_pacing_rate: u64,         // 488..496
    pub _pad_496: [u8; 24],          // 496..520
    pub sk_max_pacing_rate: u64,     // 520..528
    pub _pad_528: [u8; 280],         // 528..808
}

// ---- inet_connection_sock (size: 1440) -------------------------------------
// Accessed fields:
//   icsk_rto      @ 1224 (u32)
//   icsk_backoff  @ 1291 (u8)
//   icsk_ack      @ 1296 (struct, size 16; rcv_mss at inner offset 14)

#[repr(C)]
#[derive(Copy, Clone)]
pub struct icsk_ack_t {
    pub _pad: [u8; 14], //  0..14
    pub rcv_mss: u16,   // 14..16
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inet_connection_sock {
    pub _pad_0: [u8; 1224],   //    0..1224
    pub icsk_rto: u32,        // 1224..1228
    pub _pad_1228: [u8; 63],  // 1228..1291
    pub icsk_backoff: u8,     // 1291..1292
    pub _pad_1292: [u8; 4],   // 1292..1296
    pub icsk_ack: icsk_ack_t, // 1296..1312
    pub _pad_1312: [u8; 24],  // 1312..1336
    pub icsk_ca_priv: [u64; 13], // 1336..1440 (congestion control private data)
}

// ---- tcp_sock sub-structs --------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
pub struct tcp_sock_rcv_rtt_est {
    pub rtt_us: u32,    //  0..4
    pub _pad: [u8; 12], //  4..16
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct tcp_sock_rcvq_space {
    pub space: u32,     //  0..4
    pub _pad: [u8; 12], //  4..16
}

// ---- tcp_sock (size: 2368) -------------------------------------------------
// All accessed field offsets verified with pahole against running kernel BTF.

#[repr(C)]
#[derive(Copy, Clone)]
pub struct tcp_sock {
    pub inet_conn: inet_connection_sock, //    0..1440
    pub _pad_1440: [u8; 4],              // 1440..1444
    pub rcv_ssthresh: u32,               // 1444..1448
    pub reordering: u32,                 // 1448..1452
    pub _pad_1452: [u8; 40],             // 1452..1492
    pub snd_cwnd: u32,                   // 1492..1496
    pub _pad_1496: [u8; 8],              // 1496..1504
    pub sacked_out: u32,                 // 1504..1508
    pub _pad_1508: [u8; 16],             // 1508..1524
    pub rttvar_us: u32,                  // 1524..1528
    pub retrans_out: u32,                // 1528..1532
    pub advmss: u16,                     // 1532..1534
    pub _pad_1534: [u8; 2],              // 1534..1536
    pub lost: u32,                       // 1536..1540
    pub snd_ssthresh: u32,               // 1540..1544
    pub _pad_1544: [u8; 56],             // 1544..1600
    pub segs_out: u32,                   // 1600..1604  (64-byte aligned in kernel)
    pub _pad_1604: [u8; 204],            // 1604..1808
    pub bytes_received: u64,             // 1808..1816
    pub segs_in: u32,                    // 1816..1820
    pub _pad_1820: [u8; 60],             // 1820..1880
    pub bytes_acked: u64,                // 1880..1888
    pub rcv_rtt_est: tcp_sock_rcv_rtt_est, // 1888..1904
    pub rcvq_space: tcp_sock_rcvq_space,   // 1904..1920
    pub _pad_1920: [u8; 53],             // 1920..1973
    pub keepalive_probes: u8,            // 1973..1974
    pub _pad_1974: [u8; 282],            // 1974..2256
    pub total_retrans: u32,              // 2256..2260
    pub _pad_2260: [u8; 108],            // 2260..2368
}

// ---- sk_buff (size: 232) ---------------------------------------------------
// Only data_len @ 116 is accessed.

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sk_buff {
    pub _pad_0: [u8; 116],   //   0..116
    pub data_len: u32,        // 116..120
    pub _pad_120: [u8; 112],  // 120..232
}

// ---- FlowKey (BPF map key identifying a TCP connection) --------------------
// Socket-local perspective: src = local side, dst = remote side.
// For AF_INET sockets, src_v6/dst_v6 hold IPv4-mapped addresses (::ffff:x.x.x.x).

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct FlowKey {
    pub src_v6: [u8; 16], // local address
    pub dst_v6: [u8; 16], // remote address
    pub src_port: u16,    // local port
    pub dst_port: u16,    // remote port
    pub family: u16,      // AF_INET=2, AF_INET6=10
    pub _pad: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

// ---- Debug ring-buffer type -----------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DebugMsg {
    pub msg: [u8; 64],
    pub key: FlowKey, // valid only when has_key != 0
    pub has_key: u8,
}

// ---- Trace entry types (output ring-buffer structs) -----------------------

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct cwnd_trace_entry {
    // Stream info
    pub time: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16usize],
    pub dst_v6: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    // Data
    pub snd_cwnd: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct sock_trace_entry {
    pub time: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16usize],
    pub dst_v6: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    // SOCK Stats
    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    // INET_CONN Stats
    pub backoff: u8,
    pub rto: u32,
    // INET_CONN -> icsk_ack
    pub ato: u32,
    pub rcv_mss: u16,
    // TCP_SOCK Stats
    pub snd_cwnd: u32,
    pub bytes_acked: u64,
    pub snd_ssthresh: u32,
    pub total_retrans: u32,
    pub probes: u8,
    pub lost: u32,
    pub sacked_out: u32,
    pub retrans: u32,
    pub rcv_ssthresh: u32,
    pub rttvar: u32,
    pub advmss: u16,
    pub reordering: u32,
    pub rcv_rtt: u32,
    pub rcv_space: u32,
    pub bytes_received: u64,
    pub segs_out: u32,
    pub segs_in: u32,
    // TCP_SOCK -> tcp_options_received
    pub snd_wscale: u16,
    pub rcv_wscale: u16,
}
