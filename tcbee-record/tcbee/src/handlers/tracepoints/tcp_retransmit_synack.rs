use std::{convert::Infallible, net::IpAddr};

use tcbee_common::bindings::tcp_retransmit_synack::tcp_retransmit_synack_entry;

use crate::{config::AF_INET, handlers::{BufferHandler, BufferHandlerImpl}};

impl BufferHandlerImpl<tcp_retransmit_synack_entry>
    for BufferHandler<tcp_retransmit_synack_entry>
{
    fn handle_event(&self, event: tcp_retransmit_synack_entry) -> Option<tcp_retransmit_synack_entry> {
        // TODO: new kernel has family field
        let ip_version = event.family;
        // Get first two bytes that determine IP version
        //let ip_version = ((event.saddr[0] as u16) << 8) | event.saddr[1] as u16;

        let mut src: String;
        let mut dst: String;
        let mut  src_raw: Result<IpAddr, Infallible>;
        let mut  dst_raw: Result<IpAddr, Infallible>;

        // IPv4 Socket
        if ip_version == AF_INET {
            src_raw = IpAddr::try_from(event.saddr);
            dst_raw = IpAddr::try_from(event.daddr);
            // TODO:  if ip_version == AF_INET6
        } else {
            src_raw = IpAddr::try_from(event.saddr);
            dst_raw = IpAddr::try_from(event.daddr);
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

        //println!("{:?}",event.saddr);
        /*
        if ip_version == AF_INET {
            println!(
                "New IPv4 RETRANS Packet {}:{} - {}:{}.",
                src, sport, dst, dport
            );
        } else {
            println!(
                "New IPv6 RETRANS Packet [{}]:{} - [{}]:{}",
                src, sport, dst, dport
            );
        }
        */
        Some(event)
    }
}
