use std::net::IpAddr;

use tcbee_common::filter::*;

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
