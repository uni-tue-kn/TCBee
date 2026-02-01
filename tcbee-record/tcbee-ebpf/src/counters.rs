use aya_ebpf::{macros::map, maps::PerCpuArray};

static NUM_CPUS: u32 = 32;

// Total number of events
#[map(name = "EVENTS_DROPPED")]
static mut EVENTS_DROPPED: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0); //TODO: set CPU count
#[map(name = "EVENTS_HANDLED")]
static mut EVENTS_HANDLED: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);

// Header tracing
#[map(name = "INGRESS_EVENTS")]
static mut INGRESS_EVENTS: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);
#[map(name = "EGRESS_EVENTS")]
static mut EGRESS_EVENTS: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);

// Tracepoints
#[map(name = "TRACEPOINT_EVENTS")]
static mut TRACEPOINT_EVENTS: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);

// Kernel tracing
#[map(name = "SEND_TCP_SOCK")]
static mut SEND_TCP_SOCK: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);
#[map(name = "RECV_TCP_SOCK")]
static mut RECV_TCP_SOCK: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);

#[map(name = "SENT_TCP_BYTES")]
static mut SENT_TCP_BYTES: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);
#[map(name = "RECEIVED_TCP_BYTES")]
static mut RECEIVED_TCP_BYTES: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);

// Algorithm Counters
#[map(name = "CUBIC_EVENTS_COUNTER")]
static mut CUBIC_EVENTS_COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);
#[map(name = "BBR_EVENTS_COUNTER")]
static mut BBR_EVENTS_COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);

#[inline(always)]
pub fn try_count_tracpoint() -> Result<(), ()> {
    unsafe {
        let counter = TRACEPOINT_EVENTS.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}

#[inline(always)]
pub fn try_count_cubic_event() -> Result<(), ()> {
    unsafe {
        let counter = CUBIC_EVENTS_COUNTER.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}

#[inline(always)]
pub fn try_count_bbr_event() -> Result<(), ()> {
    unsafe {
        let counter = BBR_EVENTS_COUNTER.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}

#[inline(always)]
pub fn try_sent_tcp_bytes(add: u32) -> Result<(), ()> {
    unsafe {
        let counter = SENT_TCP_BYTES.get_ptr_mut(0).ok_or(())?;
        *counter += add;
    }
    Ok(())
}

#[inline(always)]
pub fn try_received_tcp_bytes(add: u32) -> Result<(), ()> {
    unsafe {
        let counter = RECEIVED_TCP_BYTES.get_ptr_mut(0).ok_or(())?;
        *counter += add;
    }
    Ok(())
}

#[inline(always)]
pub fn try_send_tcp_sock() -> Result<(), ()> {
    unsafe {
        let counter = SEND_TCP_SOCK.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}

#[inline(always)]
pub fn try_recv_tcp_sock() -> Result<(), ()> {
    unsafe {
        let counter = RECV_TCP_SOCK.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}

#[inline(always)]
pub fn try_dropped_counter() -> Result<(), ()> {
    unsafe {
        let counter = EVENTS_DROPPED.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}

#[inline(always)]
pub fn try_handled_counter() -> Result<(), ()> {
    unsafe {
        let counter = EVENTS_HANDLED.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}

#[inline(always)]
pub fn try_ingress_counter() -> Result<(), ()> {
    unsafe {
        let counter = INGRESS_EVENTS.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}

#[inline(always)]
pub fn try_egress_counter() -> Result<(), ()> {
    unsafe {
        let counter = EGRESS_EVENTS.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    Ok(())
}
