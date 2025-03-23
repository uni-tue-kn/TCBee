use tcbee_common::bindings::tcp_header::tcp_packet_trace;

use crate::handlers::{BufferHandler, BufferHandlerImpl};

// The first four bytes of an address contains IP version and ports, so remove them
// IpAddr determines IPv4 and IPv6 based on array length, so these functions shorten them as needed
// TODO: could be moved to a single function as the first byte contains the AF_INET type ?

impl BufferHandlerImpl<tcp_packet_trace> for BufferHandler<tcp_packet_trace> {
    fn handle_event(&self, event: tcp_packet_trace) -> Option<tcp_packet_trace> {
        // TODO: FILTER!

        Some(event)
    }
}
