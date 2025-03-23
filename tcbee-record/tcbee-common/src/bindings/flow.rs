#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct IpTuple {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
}

#[cfg(feature = "user")]
unsafe impl Pod for IpTuple {}
