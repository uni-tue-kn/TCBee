#[cfg(feature = "user")]
use aya::Pod;

pub use crate::records::IpTuple;

#[cfg(feature = "user")]
unsafe impl Pod for IpTuple {}

