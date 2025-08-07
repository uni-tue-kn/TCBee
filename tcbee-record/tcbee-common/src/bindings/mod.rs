pub mod tcp_bad_csum;
pub mod tcp_probe;
pub mod tcp_retransmit_synack;
pub mod tcp_header;
pub mod eth_header;
pub mod ip4_header;
pub mod ip6_header;
pub mod flow;
pub mod tcp_sock;

#[cfg(feature = "user")]
use aya::Pod;
use tcp_bad_csum::tcp_bad_csum_entry;
use tcp_probe::tcp_probe_entry;
use tcp_retransmit_synack::tcp_retransmit_synack_entry;
use tcp_sock::sock_trace_entry;

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::core::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::core::marker::PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::core::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::core::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::core::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
pub type __u64 = ::aya_ebpf::cty::c_ulonglong;
pub type __u16 = ::aya_ebpf::cty::c_ushort;
pub type __u8 = ::aya_ebpf::cty::c_uchar;
pub type __u32 = ::aya_ebpf::cty::c_uint;


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct trace_entry {
    pub type_: ::aya_ebpf::cty::c_ushort,
    pub flags: ::aya_ebpf::cty::c_uchar,
    pub preempt_count: ::aya_ebpf::cty::c_uchar,
    pub pid: ::aya_ebpf::cty::c_int,
}

pub trait EBPFTracePointType {
    const QUEUE_NAME: &'static str;
    const NAME: &'static str;
    const CATEGORY: &'static str;
}

impl EBPFTracePointType for tcp_retransmit_synack_entry {
    const QUEUE_NAME: &'static str = "TCP_RETRANSMIT_SYNACK_QUEUE";
    const NAME: &'static str = "tcp_retransmit_synack";
    const CATEGORY: &'static str = "tcp";
}

impl EBPFTracePointType for tcp_probe_entry {
    const QUEUE_NAME: &'static str = "TCP_PROBE_QUEUE";
    const NAME: &'static str = "tcp_probe";
    const CATEGORY: &'static str = "tcp";
}

impl EBPFTracePointType for tcp_bad_csum_entry {
    const QUEUE_NAME: &'static str = "TCP_BAD_CSUM_QUEUE";
    const NAME: &'static str = "tcp_bad_csum";
    const CATEGORY: &'static str = "tcp";
}

impl EBPFTracePointType for sock_trace_entry {
    const QUEUE_NAME: &'static str = "TCP_SOCK";
    const NAME: &'static str = "tcp_sock";
    const CATEGORY: &'static str = "tcp";
}
#[cfg(feature = "user")]
// Needed to be able to parse as queue entry from eBPF queue
unsafe impl Pod for tcp_probe_entry {}
#[cfg(feature = "user")]
unsafe impl Pod for tcp_retransmit_synack_entry {}
#[cfg(feature = "user")]
unsafe impl Pod for tcp_bad_csum_entry {}
#[cfg(feature = "user")]
unsafe impl Pod for sock_trace_entry {}