use std::{convert::Infallible, net::IpAddr};

use tcbee_common::bindings::tcp_probe::tcp_probe_entry;

use crate::{config::AF_INET, handlers::{BufferHandler, BufferHandlerImpl}};

// The first four bytes of an address contains IP version and ports, so remove them
// IpAddr determines IPv4 and IPv6 based on array length, so these functions shorten them as needed
// TODO: could be moved to a single function as the first byte contains the AF_INET type ?
fn shorten_to_ipv6(arg: [u8; 28]) -> [u8; 16] {
    std::array::from_fn(|i| arg[i + 4])
}
fn shorten_to_ipv4(arg: [u8; 28]) -> [u8; 4] {
    std::array::from_fn(|i| arg[i + 4])
}

impl BufferHandlerImpl<tcp_probe_entry> for BufferHandler<tcp_probe_entry> {
    fn handle_event(&self, event: tcp_probe_entry) -> Option<tcp_probe_entry>{
        Some(event)
    }
}