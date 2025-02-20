use aya_ebpf::{macros::map, maps::PerCpuArray};

static NUM_CPUS: u32 = 32;

#[map(name = "EVENTS_DROPPED")]
static mut EVENTS_DROPPED: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0); //TODO: set CPU count
#[map(name = "EVENTS_HANDLED")]
static mut EVENTS_HANDLED: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);
#[map(name = "INGRESS_EVENTS")]
static mut INGRESS_EVENTS: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);
#[map(name = "EGRESS_EVENTS")]
static mut EGRESS_EVENTS: PerCpuArray<u32> = PerCpuArray::with_max_entries(NUM_CPUS, 0);


#[inline(always)] 
pub fn try_dropped_counter() -> Result<(), ()> {
    unsafe {
        let counter = EVENTS_DROPPED
            .get_ptr_mut(0)
            .ok_or(())? ;
            *counter += 1;
        }
    Ok(())
}

#[inline(always)] 
pub fn try_handled_counter() -> Result<(), ()> {
    unsafe {
        let counter = EVENTS_HANDLED
            .get_ptr_mut(0)
            .ok_or(())? ;
            *counter += 1;
        }
    Ok(())
}

#[inline(always)] 
pub fn try_ingress_counter() -> Result<(), ()> {
    unsafe {
        let counter = INGRESS_EVENTS
            .get_ptr_mut(0)
            .ok_or(())? ;
            *counter += 1;
        }
    Ok(())
}

#[inline(always)] 
pub fn try_egress_counter() -> Result<(), ()> {
    unsafe {
        let counter = EGRESS_EVENTS
            .get_ptr_mut(0)
            .ok_or(())? ;
            *counter += 1;
        }
    Ok(())
}