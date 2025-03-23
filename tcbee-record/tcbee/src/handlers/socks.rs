use tcbee_common::bindings::tcp_sock::sock_trace_entry;

use crate::handlers::{BufferHandler, BufferHandlerImpl};

// The first four bytes of an address contains IP version and ports, so remove them
// IpAddr determines IPv4 and IPv6 based on array length, so these functions shorten them as needed
// TODO: could be moved to a single function as the first byte contains the AF_INET type ?

impl BufferHandlerImpl<sock_trace_entry> for BufferHandler<sock_trace_entry> {
    fn handle_event(&self, event: sock_trace_entry) -> Option<sock_trace_entry> {
        // TODO: FILTER!

        Some(event)
    }
}
