use std::net::IpAddr;

use anyhow::anyhow;
use tcbee_common::{filter::*, stats::RINGBUFS};

#[derive(Default, Debug, Clone)]
pub struct FilterConfig {
    pub single_port: u16,
    pub any_ports: Vec<u16>,
    pub src_ports: Vec<u16>,
    pub dst_ports: Vec<u16>,
    pub any_ips: Vec<[u8; 16]>,
    pub src_ips: Vec<[u8; 16]>,
    pub dst_ips: Vec<[u8; 16]>,
}

impl FilterConfig {
    pub fn mode(&self) -> u32 {
        if self.rule_flags() != 0 {
            FILTER_MODE_MAPS
        } else if self.single_port != 0 {
            FILTER_MODE_SINGLE_PORT
        } else {
            FILTER_MODE_NONE
        }
    }

    pub fn rule_flags(&self) -> u32 {
        let mut flags = 0;
        if !self.any_ports.is_empty() {
            flags |= FILTER_ANY_PORT;
        }
        if !self.src_ports.is_empty() {
            flags |= FILTER_SRC_PORT;
        }
        if !self.dst_ports.is_empty() {
            flags |= FILTER_DST_PORT;
        }
        if !self.any_ips.is_empty() {
            flags |= FILTER_ANY_IP;
        }
        if !self.src_ips.is_empty() {
            flags |= FILTER_SRC_IP;
        }
        if !self.dst_ips.is_empty() {
            flags |= FILTER_DST_IP;
        }
        flags
    }
}

pub fn ip_to_filter_addr(ip: IpAddr) -> [u8; 16] {
    let mut addr = [0u8; 16];
    match ip {
        IpAddr::V4(ip) => addr[..4].copy_from_slice(&ip.octets()),
        IpAddr::V6(ip) => addr = ip.octets(),
    }
    addr
}

/// Largest ring buffer the kernel accepts is just below 2 GiB, use the largest power of two
const MAX_RINGBUF_SIZE: u64 = 1 << 30;
const PAGE_SIZE: u64 = 4096;

fn parse_size(arg: &str) -> anyhow::Result<u64> {
    let arg = arg.trim();
    let (number, factor) = match arg.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&arg[..arg.len() - 1], 1 << 10),
        Some('M') => (&arg[..arg.len() - 1], 1 << 20),
        Some('G') => (&arg[..arg.len() - 1], 1 << 30),
        _ => (arg, 1),
    };
    let size = number
        .trim()
        .parse::<u64>()
        .map_err(|err| anyhow!("Invalid ring buffer size '{}': {}", arg, err))?
        .checked_mul(factor)
        .ok_or_else(|| anyhow!("Ring buffer size '{}' is too large", arg))?;
    if size == 0 || size > MAX_RINGBUF_SIZE {
        return Err(anyhow!(
            "Ring buffer size '{}' must be between 1 and {} bytes",
            arg,
            MAX_RINGBUF_SIZE
        ));
    }
    // The kernel requires a power of two multiple of the page size
    Ok(size.next_power_of_two().max(PAGE_SIZE))
}

/// Parses `--ringbuf-size`: a size for all ring buffers, `group=size` pairs, or both, e.g.
/// `64M` or `tcp4=256M,sock=1G`. Groups are the ones in `tcbee_common::stats::RINGBUFS`,
/// a full map name selects a single ring buffer. Returns (map name, bytes) pairs.
pub fn parse_ringbuf_sizes(arg: &str) -> anyhow::Result<Vec<(&'static str, u32)>> {
    let mut sizes: Vec<(&'static str, u32)> = Vec::new();
    let mut set = |selector: Option<&str>, size: u64| -> anyhow::Result<()> {
        let mut matched = false;
        for (name, group) in RINGBUFS {
            let selected = match selector {
                None => true,
                Some(sel) => sel == group || sel.eq_ignore_ascii_case(name),
            };
            if selected {
                matched = true;
                sizes.retain(|(n, _)| *n != name);
                sizes.push((name, size as u32));
            }
        }
        if !matched {
            let mut groups: Vec<&str> = RINGBUFS.iter().map(|(_, group)| *group).collect();
            groups.dedup();
            return Err(anyhow!(
                "Unknown ring buffer '{}', use one of: {}",
                selector.unwrap_or_default(),
                groups.join(", ")
            ));
        }
        Ok(())
    };

    // Apply the size for all buffers first so that groups override it
    let items: Vec<&str> = arg.split(',').map(str::trim).filter(|i| !i.is_empty()).collect();
    for item in items.iter().filter(|i| !i.contains('=')) {
        set(None, parse_size(item)?)?;
    }
    for item in items.iter().filter(|i| i.contains('=')) {
        let (selector, size) = item.split_once('=').unwrap();
        set(Some(selector.trim()), parse_size(size)?)?;
    }
    Ok(sizes)
}

#[derive(Default, Debug)]
pub struct EbpfRunnerConfig {
    pub iface: String,
    pub do_tui: bool,
    pub update_period: u128,
    pub observation_window: f64,
    pub filter: FilterConfig,
    pub headers: bool,
    pub tracepoints: bool,
    pub kernel: bool,
    pub cwnd: bool,
    pub metrics: bool,
    pub algorithms: bool,
    pub dir: String,
    pub ringbuf_sizes: Vec<(&'static str, u32)>,
}

#[derive(Default)]
pub struct GraphConfig {
    pub events: bool,
    pub packets: bool,
    pub kernel: bool,
    pub cubic: bool,
    pub bbr: bool,
    pub tracepoints: bool,
}

pub struct EbpfWatcherConfig {
    pub graphs: GraphConfig,
    pub packets: bool,
    pub stats: bool,
    pub calls: bool,
    pub flows: bool,
    pub cwnd: bool,
    pub algorithms: bool,
    pub metrics: bool,
    pub observation_window: Option<f64>,
    pub dir: String,
}

impl EbpfRunnerConfig {
    pub fn new() -> EbpfRunnerConfig {
        EbpfRunnerConfig::default()
    }

    pub fn interface(mut self, iface: String) -> EbpfRunnerConfig {
        self.iface = iface;
        self
    }

    pub fn tui(mut self, set: bool) -> EbpfRunnerConfig {
        self.do_tui = set;
        self
    }

    pub fn update_period(mut self, update_period: u128) -> EbpfRunnerConfig {
        self.update_period = update_period;
        self
    }

    pub fn observation_window(mut self, observation_window: f64) -> EbpfRunnerConfig {
        self.observation_window = observation_window;
        self
    }

    pub fn filter(mut self, filter: FilterConfig) -> EbpfRunnerConfig {
        self.filter = filter;
        self
    }

    pub fn headers(mut self, set: bool) -> EbpfRunnerConfig {
        self.headers = set;
        self
    }

    pub fn tracepoints(mut self, set: bool) -> EbpfRunnerConfig {
        self.tracepoints = set;
        self
    }

    pub fn kernel(mut self, set: bool) -> EbpfRunnerConfig {
        self.kernel = set;
        self
    }

    pub fn cwnd(mut self, set: bool) -> EbpfRunnerConfig {
        self.cwnd = set;
        self
    }

    pub fn dir(mut self, set: String) -> EbpfRunnerConfig {
        self.dir = set;
        self
    }

    pub fn metrics(mut self, set: bool) -> EbpfRunnerConfig {
        self.metrics = set;
        self
    }

    pub fn algorithms(mut self, set: bool) -> EbpfRunnerConfig {
        self.algorithms = set;
        self
    }

    pub fn ringbuf_sizes(mut self, sizes: Vec<(&'static str, u32)>) -> EbpfRunnerConfig {
        self.ringbuf_sizes = sizes;
        self
    }

    pub fn watcher_config(&self) -> EbpfWatcherConfig {
        EbpfWatcherConfig {
            graphs: GraphConfig::default(),
            packets: self.headers,
            stats: true,
            calls: self.kernel,
            flows: true,
            cwnd: self.cwnd,
            algorithms: self.algorithms,
            metrics: self.metrics,
            observation_window: (self.observation_window > 0.0).then_some(self.observation_window),
            dir: self.dir.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ringbuf_size_for_all_and_per_group() {
        let sizes = parse_ringbuf_sizes("1M,tcp4=3M,TCP_RECV_SOCK_EVENTS=5000").unwrap();
        let get = |name: &str| sizes.iter().find(|(n, _)| *n == name).unwrap().1;
        assert_eq!(sizes.len(), RINGBUFS.len());
        assert_eq!(get("TCP4_PACKETS_EGRESS"), 4 << 20);
        assert_eq!(get("TCP4_PACKETS_INGRESS"), 4 << 20);
        assert_eq!(get("TCP6_PACKETS_EGRESS"), 1 << 20);
        assert_eq!(get("TCP_RECV_SOCK_EVENTS"), 8192);
        assert_eq!(get("TCP_SEND_SOCK_EVENTS"), 1 << 20);
    }

    #[test]
    fn ringbuf_size_rejects_invalid() {
        assert!(parse_ringbuf_sizes("").unwrap().is_empty());
        assert_eq!(parse_ringbuf_sizes("1").unwrap()[0].1, 4096);
        assert!(parse_ringbuf_sizes("0").is_err());
        assert!(parse_ringbuf_sizes("2G").is_err());
        assert!(parse_ringbuf_sizes("foo=1M").is_err());
        assert!(parse_ringbuf_sizes("tcp4=1X").is_err());
    }
}
