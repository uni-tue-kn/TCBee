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
        // TODO: new kernel has family field
        let ip_version = event.family;
        // Get first two bytes that determine IP version
        //let ip_version = ((event.daddr[0] as u16) << 8) | event.daddr[1] as u16;

        let mut src: String;
        let mut dst: String;
        let mut src_raw: Result<IpAddr, Infallible>;
        let mut dst_raw: Result<IpAddr, Infallible>;

        // IPv4 Socket
        if ip_version == AF_INET {
            src_raw = IpAddr::try_from(shorten_to_ipv4(event.saddr));
            dst_raw = IpAddr::try_from(shorten_to_ipv4(event.daddr));
            // TODO:  if ip_version == AF_INET6
        } else {
            src_raw = IpAddr::try_from(shorten_to_ipv6(event.saddr));
            dst_raw = IpAddr::try_from(shorten_to_ipv6(event.daddr));
        }

        if src_raw.is_err() {
            src = "ERROR".to_owned();
        } else {
            src = src_raw.unwrap().to_string();
        }

        if dst_raw.is_err() {
            dst = "ERROR".to_owned();
        } else {
            dst = dst_raw.unwrap().to_string();
        }

        let sport = event.sport;
        let dport = event.dport;

        // TODO: filter needed!
        //if dport != 58080 && sport != 58080 {
        //    return async {}
        //}

        let len = event.data_len;

        /*
        if ip_version == AF_INET {
            info!(
                "New IPv4 Packet {}:{} - {}:{}. {} bytes",
                src, sport, dst, dport, len
            );
        } else {
            info!(
                "New IPv6 Packet [{}]:{} - [{}]:{} {} bytes",
               src, sport, dst, dport, len
            );
        }
         */
        
        Some(event)
    }
}