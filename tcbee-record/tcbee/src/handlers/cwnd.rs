use tcbee_common::bindings::tcp_sock::cwnd_trace_entry;

use crate::handlers::{BufferHandler, BufferHandlerImpl};

// The first four bytes of an address contains IP version and ports, so remove them
// IpAddr determines IPv4 and IPv6 based on array length, so these functions shorten them as needed
// TODO: could be moved to a single function as the first byte contains the AF_INET type ?

impl BufferHandlerImpl<cwnd_trace_entry> for BufferHandler<cwnd_trace_entry> {
    fn handle_event(&self, event: cwnd_trace_entry) -> Option<cwnd_trace_entry> {
        // TODO: FILTER!

        Some(event)
    }
}
