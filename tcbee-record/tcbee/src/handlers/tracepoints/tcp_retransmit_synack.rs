
use tcbee_common::bindings::tcp_retransmit_synack::tcp_retransmit_synack_entry;

use crate::handlers::{BufferHandler, BufferHandlerImpl};

impl BufferHandlerImpl<tcp_retransmit_synack_entry>
    for BufferHandler<tcp_retransmit_synack_entry>
{
    fn handle_event(&self, event: tcp_retransmit_synack_entry) -> Option<tcp_retransmit_synack_entry> {
        Some(event)
    }
}
