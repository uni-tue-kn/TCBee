#[cfg(feature = "user")]
use aya::Pod;

pub const FILTER_MODE_NONE: u32 = 0;
pub const FILTER_MODE_SINGLE_PORT: u32 = 1;
pub const FILTER_MODE_MAPS: u32 = 2;

pub const FILTER_ANY_PORT: u32 = 1 << 0;
pub const FILTER_SRC_PORT: u32 = 1 << 1;
pub const FILTER_DST_PORT: u32 = 1 << 2;
pub const FILTER_ANY_IP: u32 = 1 << 3;
pub const FILTER_SRC_IP: u32 = 1 << 4;
pub const FILTER_DST_IP: u32 = 1 << 5;

pub const FILTER_PORT_BITS: u32 = FILTER_ANY_PORT | FILTER_SRC_PORT | FILTER_DST_PORT;
pub const FILTER_IP_BITS: u32 = FILTER_ANY_IP | FILTER_SRC_IP | FILTER_DST_IP;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct FilterIp {
    pub addr: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl Pod for FilterIp {}
