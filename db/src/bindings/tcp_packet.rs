use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ts_storage::{DataValue, IpTuple};

use crate::{db_writer::DBOperation, flow_tracker::EventIndexer, reader::FromBuffer};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpPacket {
    pub time: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub saddr_v6: [u8; 16usize],
    pub daddr_v6: [u8; 16usize],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub flag_urg: bool,
    pub flag_ack: bool,
    pub flag_psh: bool,
    pub flag_rst: bool,
    pub flag_syn: bool,
    pub flag_fin: bool,
    pub checksum: u16,
    pub div: u32,
}

impl FromBuffer for TcpPacket {
    fn from_buffer(buf: &Vec<u8>) -> Self {
        unsafe { *(buf.as_ptr() as *const TcpPacket) }

    }
}

impl EventIndexer for TcpPacket {
    fn get_field(&self, index: usize) -> Option<DataValue> {
        match index {
            0 => if self.seq > 0 {Some(DataValue::Int(self.seq as i64))} else {None},
            1 => if self.ack > 0 {Some(DataValue::Int(self.ack as i64))} else {None},
            2 => if self.window > 0 {Some(DataValue::Int(self.window as i64))} else {None},
            // Only add Flags when true to save space
            // TODO: 
            3 => if self.flag_urg { Some(DataValue::Boolean(true)) } else {None},
            4 => if self.flag_ack { Some(DataValue::Boolean(true)) } else {None},
            5 => if self.flag_psh { Some(DataValue::Boolean(true)) } else {None},
            6 => if self.flag_rst { Some(DataValue::Boolean(true)) } else {None},
            7 => if self.flag_syn { Some(DataValue::Boolean(true)) } else {None},
            8 => if self.flag_fin { Some(DataValue::Boolean(true)) } else {None},
            9 => if self.checksum > 0 {Some(DataValue::Int(self.checksum as i64))} else {None},
            _ => None, // TODO: better error handling
        }
    }
    fn get_default_field(&self, index: usize) -> DataValue {
        match index {
            0 => DataValue::Int(0),
            1 => DataValue::Int(0),
            2 => DataValue::Int(0),
            3 => DataValue::Boolean(false),
            4 => DataValue::Boolean(false),
            5 => DataValue::Boolean(false),
            6 => DataValue::Boolean(false),
            7 => DataValue::Boolean(false),
            8 => DataValue::Boolean(false),
            9 => DataValue::Int(0),
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_field_name(&self, index: usize) -> &str {
        match index {
            0 => "SEQ_NUM",
            1 => "ACK_NUM",
            2 => "WINDOW",
            3 => "FLAG_URG",
            4 => "FLAG_ACK",
            5 => "FLAG_PSH",
            6 => "FLAG_RST",
            7 => "FLAG_SYN",
            8 => "FLAG_FIN",
            9 => "CHECKSUM",
            _ => panic!("Tried to access out of bounds index!"), // TODO: better error handling
        }
    }
    fn get_ip_tuple(&self) -> IpTuple {
        let src: IpAddr;
        let dst: IpAddr;

        if self.saddr != 0 && self.daddr != 0 {
            src = IpAddr::V4(Ipv4Addr::from(self.saddr));
            dst = IpAddr::V4(Ipv4Addr::from(self.daddr));
        } else {
            src = IpAddr::V6(Ipv6Addr::from(self.saddr_v6));
            dst = IpAddr::V6(Ipv6Addr::from(self.daddr_v6));
        }
        IpTuple {
            src: src,
            dst: dst,
            sport: self.sport as i64,
            dport: self.dport as i64,
            l4proto: 6,
        }
    }
    fn get_max_index(&self) -> usize {
        9
    }
    fn get_timestamp(&self) -> f64 {
        self.time as f64
    }
    fn as_db_op(self) -> DBOperation {
        DBOperation::Packet(self)
    }
}
