use tcbee_common::bindings::tcp_bad_csum::tcp_bad_csum_entry;

use crate::handlers::{BufferHandler, BufferHandlerImpl};

// The first four bytes of an address contains IP version and ports, so remove them
// IpAddr determines IPv4 and IPv6 based on array length, so these functions shorten them as needed
// TODO: could be moved to a single function as the first byte contains the AF_INET type ?

impl BufferHandlerImpl<tcp_bad_csum_entry> for BufferHandler<tcp_bad_csum_entry> {
    fn handle_event(&self, event: tcp_bad_csum_entry) -> Option<tcp_bad_csum_entry>{
        println!("DEBUG: {event:?}");
        Some(event)
    }
}