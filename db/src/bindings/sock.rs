use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ts_storage::{DataValue, IpTuple};

use crate::{db_writer::DBOperation, flow_tracker::{EventIndexer, AF_INET}, reader::FromBuffer};

use arrayref::array_ref;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct sock_trace_entry {
    pub time: u64,
    pub addr_v4: u64,
    pub src_v6: [u8; 16],
    pub dst_v6: [u8; 16],
    pub ports: u32,
    pub family: u16,
    pub snd_cwnd: u32,
    pub padding: [u8; 4], // TODO: this is somehow added when writing the header to file, find reason and fix!
    pub div: u32,
}

impl FromBuffer for sock_trace_entry {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        unsafe { *(buf.as_ptr() as *const sock_trace_entry) }

    }
}

impl EventIndexer for sock_trace_entry {
    fn get_field(&self, index: usize) -> Option<DataValue> {
        match index {
            _ => None, // TODO: better error handling
        }
    }
    fn get_default_field(&self, index: usize) -> DataValue {
        match index {
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_field_name(&self, index: usize) -> &str {
        match index {
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_ip_tuple(&self) -> IpTuple {
        let src: IpAddr;
        let dst: IpAddr;

        //print!("Family: {}",self.family);


        if self.family == AF_INET {
            // TODO: check offsets
            let mut bytes = self.addr_v4.to_be_bytes();

            let mut srcbytes = array_ref![bytes,0,4].clone();
            let mut dstbytes = array_ref![bytes,4,4].clone();
            //srcbytes.reverse();

            srcbytes.reverse();
            dstbytes.reverse();
            src = IpAddr::V4(Ipv4Addr::from(srcbytes));
            dst = IpAddr::V4(Ipv4Addr::from(dstbytes));
        } else {
            src = IpAddr::V6(Ipv6Addr::from(self.src_v6));
            dst = IpAddr::V6(Ipv6Addr::from(self.dst_v6));
        }

        let port_bytes = self.ports.to_be_bytes();

        let srcbytes = array_ref![port_bytes,0,2].clone();
        let dstbytes = array_ref![port_bytes,2,2].clone();

        let sport = u16::from_le_bytes(srcbytes);
        let dport = u16::from_le_bytes(dstbytes);

        IpTuple {
            src: src,
            dst: dst,
            sport: sport as i64,
            dport: dport as i64,
            l4proto: 6,
        }
    }
    fn get_max_index(&self) -> usize {
        0
    }
    fn get_timestamp(&self) -> f64 {
        self.time as f64
    }
    fn as_db_op(self) -> DBOperation {
        DBOperation::Socket(self)
    }
}
