#[cfg(feature = "ebpf")]
#[inline(always)]
pub unsafe fn read_kernel<T>(src: *const T) -> Result<T, u32> {
    // Use aya helper directly here (common gets this only in ebpf builds)
    unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(src).map_err(|_| 1u32) }
}

#[cfg(not(feature = "ebpf"))]
#[inline(always)]
pub fn read_kernel<T>(_src: *const T) -> Result<T, u32> {
    // Not used in userspace; only here so the derive compiles.
    unreachable!("read_kernel is only available in eBPF builds")
}
