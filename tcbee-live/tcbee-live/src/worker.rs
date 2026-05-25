use std::{
    collections::HashSet,
    mem::size_of,
    sync::mpsc::{Receiver, SyncSender},
    time::Duration,
};

use aya::{
    maps::{HashMap as BpfHashMap, MapData, RingBuf},
    Ebpf,
};
use log::{debug, error, info, warn};
use tcbee_live_common::tcp_sock::{cwnd_trace_entry, DebugMsg, FlowKey};
use tokio::io::unix::AsyncFd;

use crate::types::{flow_key_from_entry, CwndEvent, FilterCmd};

/// Outer entry point — logs any error so it is never silently swallowed.
pub async fn run_ebpf_worker(
    ebpf: Ebpf,
    event_tx: SyncSender<CwndEvent>,
    disc_tx: SyncSender<FlowKey>,
    filter_rx: Receiver<FilterCmd>,
    ctx: egui::Context,
    select_ports: std::collections::HashSet<u16>,
) {
    if let Err(e) = worker_inner(ebpf, event_tx, disc_tx, filter_rx, ctx, select_ports).await {
        error!("eBPF worker exited with error: {e:#}");
    }
}

async fn worker_inner(
    mut ebpf: Ebpf,
    event_tx: SyncSender<CwndEvent>,
    disc_tx: SyncSender<FlowKey>,
    filter_rx: Receiver<FilterCmd>,
    ctx: egui::Context,
    select_ports: std::collections::HashSet<u16>,
) -> anyhow::Result<()> {
    info!("Worker: taking BPF maps");

    let known_flows_data = ebpf
        .take_map("KNOWN_FLOWS")
        .ok_or_else(|| anyhow::anyhow!("KNOWN_FLOWS map not found in eBPF object"))?;
    info!("Worker: got KNOWN_FLOWS");

    let flow_filter_data = ebpf
        .take_map("FLOW_FILTER")
        .ok_or_else(|| anyhow::anyhow!("FLOW_FILTER map not found in eBPF object"))?;
    info!("Worker: got FLOW_FILTER");

    let send_rb_data = ebpf
        .take_map("TCP_SEND_CWND_EVENTS")
        .ok_or_else(|| anyhow::anyhow!("TCP_SEND_CWND_EVENTS map not found in eBPF object"))?;
    info!("Worker: got TCP_SEND_CWND_EVENTS");

    let recv_rb_data = ebpf
        .take_map("TCP_RECEIVE_CWND_EVENTS")
        .ok_or_else(|| anyhow::anyhow!("TCP_RECEIVE_CWND_EVENTS map not found in eBPF object"))?;
    info!("Worker: got TCP_RECEIVE_CWND_EVENTS");

    let debug_rb_data = ebpf
        .take_map("DEBUG_EVENTS")
        .ok_or_else(|| anyhow::anyhow!("DEBUG_EVENTS map not found in eBPF object"))?;
    info!("Worker: got DEBUG_EVENTS");

    let known_flows: BpfHashMap<MapData, FlowKey, u8> =
        BpfHashMap::try_from(known_flows_data)?;
    let mut flow_filter: BpfHashMap<MapData, FlowKey, u8> =
        BpfHashMap::try_from(flow_filter_data)?;
    let send_rb: RingBuf<MapData> = RingBuf::try_from(send_rb_data)?;
    let recv_rb: RingBuf<MapData> = RingBuf::try_from(recv_rb_data)?;
    let debug_rb: RingBuf<MapData> = RingBuf::try_from(debug_rb_data)?;

    let mut send_afd = AsyncFd::new(send_rb)?;
    let mut recv_afd = AsyncFd::new(recv_rb)?;
    let mut debug_afd = AsyncFd::new(debug_rb)?;

    info!("Worker: all maps acquired, entering event loop");

    let mut local_known: HashSet<FlowKey> = HashSet::new();
    let mut discovery_interval = tokio::time::interval(Duration::from_millis(500));
    let mut poll_count: u64 = 0;

    loop {
        // Apply pending filter changes (non-blocking drain).
        while let Ok(cmd) = filter_rx.try_recv() {
            match cmd {
                FilterCmd::Add(key) => {
                    info!("Filter: adding flow {}:{} → {}:{}", key.src_port, key.dst_port,
                        format_addr(&key.dst_v6, key.family), key.dst_port);
                    if let Err(e) = flow_filter.insert(key, 1u8, 0) {
                        warn!("Filter: failed to insert into FLOW_FILTER: {e}");
                    }
                }
                FilterCmd::Remove(key) => {
                    info!("Filter: removing flow src_port={} dst_port={}", key.src_port, key.dst_port);
                    if let Err(e) = flow_filter.remove(&key) {
                        warn!("Filter: failed to remove from FLOW_FILTER: {e}");
                    }
                }
            }
        }

        tokio::select! {
            Ok(mut guard) = send_afd.readable_mut() => {
                let n = drain_ring_buf(guard.get_inner_mut(), &event_tx);
                if n > 0 { debug!("Ring buf send: drained {n} cwnd events"); }
                guard.clear_ready();
                ctx.request_repaint_after(Duration::from_millis(33));
            }
            Ok(mut guard) = recv_afd.readable_mut() => {
                let n = drain_ring_buf(guard.get_inner_mut(), &event_tx);
                if n > 0 { debug!("Ring buf recv: drained {n} cwnd events"); }
                guard.clear_ready();
                ctx.request_repaint_after(Duration::from_millis(33));
            }
            Ok(mut guard) = debug_afd.readable_mut() => {
                drain_debug_ring_buf(guard.get_inner_mut());
                guard.clear_ready();
            }
            _ = discovery_interval.tick() => {
                poll_count += 1;
                let mut new_count = 0;
                for item in known_flows.iter() {
                    match item {
                        Ok((key, _)) => {
                            if local_known.insert(key) {
                                new_count += 1;
                                info!("Discovery: new flow {}:{} → {}:{}",
                                    format_addr(&key.src_v6, key.family), key.src_port,
                                    format_addr(&key.dst_v6, key.family), key.dst_port);
                                // Auto-select: insert directly into FLOW_FILTER without
                                // waiting for the GUI round-trip (~500ms+ too slow for
                                // short-lived flows).
                                if select_ports.contains(&key.src_port)
                                    || select_ports.contains(&key.dst_port) {
                                    info!("Auto-filter: adding flow {}:{} → {}:{}",
                                        format_addr(&key.src_v6, key.family), key.src_port,
                                        format_addr(&key.dst_v6, key.family), key.dst_port);
                                    if let Err(e) = flow_filter.insert(key, 1u8, 0) {
                                        warn!("Auto-filter: failed to insert into FLOW_FILTER: {e}");
                                    }
                                }
                                let _ = disc_tx.try_send(key);
                            }
                        }
                        Err(e) => warn!("Discovery: error reading KNOWN_FLOWS entry: {e}"),
                    }
                }
                // Log a heartbeat every 10 polls (~5 s) so we know the worker is alive.
                if poll_count % 10 == 0 {
                    info!("Worker: alive, known flows = {}", local_known.len());
                }
                if new_count > 0 || poll_count <= 3 {
                    debug!("Discovery poll #{poll_count}: total known = {}, new = {new_count}",
                        local_known.len());
                }
                ctx.request_repaint_after(Duration::from_millis(33));
            }
        }
    }
}

fn drain_ring_buf(ring: &mut RingBuf<MapData>, tx: &SyncSender<CwndEvent>) -> usize {
    let mut count = 0;
    while let Some(item) = ring.next() {
        if item.len() == size_of::<cwnd_trace_entry>() {
            let entry: cwnd_trace_entry =
                unsafe { std::ptr::read_unaligned(item.as_ptr() as *const cwnd_trace_entry) };
            let _ = tx.try_send(CwndEvent {
                key: flow_key_from_entry(&entry),
                time_ns: entry.time,
                snd_cwnd: entry.snd_cwnd,
            });
            count += 1;
        } else {
            warn!("Ring buf: unexpected item size {} (expected {})", item.len(), size_of::<cwnd_trace_entry>());
        }
    }
    count
}

fn drain_debug_ring_buf(ring: &mut RingBuf<MapData>) {
    while let Some(item) = ring.next() {
        if item.len() == size_of::<DebugMsg>() {
            let entry: DebugMsg =
                unsafe { std::ptr::read_unaligned(item.as_ptr() as *const DebugMsg) };
            let len = entry.msg.iter().position(|&b| b == 0).unwrap_or(64);
            if let Ok(s) = std::str::from_utf8(&entry.msg[..len]) {
                if entry.has_key != 0 {
                    let k = &entry.key;
                    let src = format_addr(&k.src_v6, k.family);
                    let dst = format_addr(&k.dst_v6, k.family);
                    info!("[eBPF dbg] {s} | {src}:{} -> {dst}:{}", k.src_port, k.dst_port);
                } else {
                    info!("[eBPF dbg] {s}");
                }
            }
        }
    }
}

fn format_addr(v6: &[u8; 16], family: u16) -> String {
    if family == 2 {
        format!("{}.{}.{}.{}", v6[12], v6[13], v6[14], v6[15])
    } else {
        std::net::Ipv6Addr::from(*v6).to_string()
    }
}
