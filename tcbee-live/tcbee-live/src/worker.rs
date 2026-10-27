use std::{
    collections::HashSet,
    sync::mpsc::{Receiver, SyncSender, TryRecvError},
    time::{Duration, Instant},
};

use anyhow::bail;
use libbpf_rs::{MapCore, MapFlags, MapHandle, RingBuffer, RingBufferBuilder};
use log::{debug, error, info, warn};

use crate::bpf::{self, FlowKey, LiveMaps};
use crate::types::{CwndEvent, FilterCmd, format_flow};

/// How often the worker reads the EVENTS ring buffer. The probes submit without
/// a wakeup, so this sets the latency of the plot (the GUI keeps one point per 50 ms).
const CONSUME_INTERVAL: Duration = Duration::from_millis(33);
/// How often KNOWN_FLOWS is scanned for new flows
const DISCOVERY_INTERVAL: Duration = Duration::from_millis(500);
/// Most events read per consume, about one full EVENTS ring (8 MiB of 64-byte
/// records), so a flow that sends faster than the worker reads cannot keep it
/// in one consume forever
const MAX_EVENTS_PER_CONSUME: usize = 1 << 17;

/// The BPF maps the worker reads and writes
pub struct WorkerMaps {
    known_flows: MapHandle,
    flow_filter: MapHandle,
    /// Reads EVENTS; its callback forwards the events to the GUI
    events: RingBuffer<'static>,
}

impl WorkerMaps {
    pub fn new(maps: &LiveMaps<'_>, event_tx: SyncSender<CwndEvent>) -> anyhow::Result<Self> {
        let mut events = RingBufferBuilder::new();
        events.add(&maps.EVENTS, move |data: &[u8]| {
            match bpf::parse_event(data) {
                Some(event) => {
                    let _ = event_tx.try_send(event);
                }
                None => warn!("Ring buf: unexpected item size {}", data.len()),
            }
            0
        })?;
        Ok(Self {
            known_flows: MapHandle::try_from(&maps.KNOWN_FLOWS)?,
            flow_filter: MapHandle::try_from(&maps.FLOW_FILTER)?,
            events: events.build()?,
        })
    }
}

/// Outer entry point — logs any error so it is never silently swallowed.
pub fn run_ebpf_worker(
    maps: WorkerMaps,
    disc_tx: SyncSender<FlowKey>,
    filter_rx: Receiver<FilterCmd>,
    ctx: egui::Context,
    select_ports: HashSet<u16>,
) {
    match worker_inner(maps, disc_tx, filter_rx, ctx, select_ports) {
        Ok(()) => info!("eBPF worker stopped"),
        Err(e) => error!("eBPF worker exited with error: {e:#}"),
    }
}

fn worker_inner(
    maps: WorkerMaps,
    disc_tx: SyncSender<FlowKey>,
    filter_rx: Receiver<FilterCmd>,
    ctx: egui::Context,
    select_ports: HashSet<u16>,
) -> anyhow::Result<()> {
    info!("Worker: entering event loop");

    let mut local_known: HashSet<FlowKey> = HashSet::new();
    let mut next_discovery = Instant::now();
    let mut poll_count: u64 = 0;

    loop {
        // Apply pending filter changes (non-blocking drain). The GUI is gone once
        // the channel disconnects.
        loop {
            match filter_rx.try_recv() {
                Ok(FilterCmd::Add(key)) => {
                    info!("Filter: adding flow {}", format_flow(&key));
                    select_flow(&maps.flow_filter, &key, "Filter");
                }
                Ok(FilterCmd::Remove(key)) => {
                    info!("Filter: removing flow {}", format_flow(&key));
                    if let Err(e) = maps.flow_filter.delete(key.as_bytes()) {
                        warn!("Filter: failed to remove from FLOW_FILTER: {e}");
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        let consumed = maps.events.consume_raw_n(MAX_EVENTS_PER_CONSUME);
        if consumed < 0 {
            bail!(
                "reading the EVENTS ring buffer: {}",
                std::io::Error::from_raw_os_error(-consumed)
            );
        }
        let mut repaint = consumed > 0;

        if Instant::now() >= next_discovery {
            next_discovery = Instant::now() + DISCOVERY_INTERVAL;
            poll_count += 1;
            let mut new_count = 0;
            for bytes in maps.known_flows.keys() {
                let Some(key) = FlowKey::from_bytes(&bytes) else {
                    warn!("Discovery: KNOWN_FLOWS key of {} bytes", bytes.len());
                    continue;
                };
                if local_known.contains(&key) {
                    continue;
                }
                // A flow the GUI has no room for yet is offered again on the next poll:
                // the GUI drops the events of flows it does not know.
                if disc_tx.try_send(key).is_err() {
                    continue;
                }
                local_known.insert(key);
                new_count += 1;
                info!("Discovery: new flow {}", format_flow(&key));
                // Auto-select: insert directly into FLOW_FILTER without waiting for
                // the GUI round-trip (~500ms+ too slow for short-lived flows).
                if select_ports.contains(&key.src_port) || select_ports.contains(&key.dst_port) {
                    select_flow(&maps.flow_filter, &key, "Auto-filter");
                }
            }
            repaint |= new_count > 0;
            // Log a heartbeat every 10 polls (~5 s) so we know the worker is alive.
            if poll_count.is_multiple_of(10) {
                info!("Worker: alive, known flows = {}", local_known.len());
            }
            if new_count > 0 || poll_count <= 3 {
                debug!(
                    "Discovery poll #{poll_count}: total known = {}, new = {new_count}",
                    local_known.len()
                );
            }
        }

        if repaint {
            ctx.request_repaint();
        }
        std::thread::sleep(CONSUME_INTERVAL);
    }
}

fn select_flow(flow_filter: &MapHandle, key: &FlowKey, log_prefix: &str) {
    if let Err(e) = flow_filter.update(key.as_bytes(), &[1], MapFlags::ANY) {
        warn!("{log_prefix}: failed to insert into FLOW_FILTER: {e}");
    }
}
