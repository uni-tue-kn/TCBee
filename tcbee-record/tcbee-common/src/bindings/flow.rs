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

impl IpTuple {
    /// Returns a canonical form with the lexicographically smaller (ip, port) pair as src,
    /// so both directions of a TCP connection map to the same hash-map key.
    #[inline(always)]
    pub fn canonical(self) -> Self {
        let swap =
            self.src_ip > self.dst_ip || (self.src_ip == self.dst_ip && self.sport > self.dport);
        if swap {
            IpTuple {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                sport: self.dport,
                dport: self.sport,
                protocol: self.protocol,
            }
        } else {
            self
        }
    }
}
