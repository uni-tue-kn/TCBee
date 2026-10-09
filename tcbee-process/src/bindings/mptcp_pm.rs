use tcbee_common::records::mptcp_pm_entry;
use ts_storage::IpTuple;

use crate::{
    event::event_schema,
    ip::{flow_tuple, kernel_addr_pair, AF_INET},
};

event_schema! {
    mptcp_pm_entry => "mptcp_pm", 111 {
        event: U8,
        token: U32,
        remote_token: U32,
        subflow_id: U32,
        error: I64,
        local_id: U8,
        remote_id: U8,
        backup: U8,
        addr_id: U8,
        addr_family: U16,
        addr_port: U16,
    }
    {
        fn flow_key(&self) -> IpTuple {
            let (src, dst) = kernel_addr_pair(
                self.family == AF_INET,
                self.addr_v4,
                self.src_v6,
                self.dst_v6,
            );
            flow_tuple(src, dst, self.sport, self.dport)
        }
        fn conn_key(&self) -> u32 {
            self.token
        }
    }
}
