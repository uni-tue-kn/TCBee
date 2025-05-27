#[derive(Default, Debug)]
pub struct EbpfRunnerConfig {
    pub iface: String,
    pub do_tui: bool,
    pub update_period: u128,
    pub port: u16,
    pub headers: bool,
    pub tracepoints: bool,
    pub kernel: bool,
}

pub struct EbpfWatcherConfig {
    pub packets: bool,
    pub stats: bool,
    pub calls: bool,
    pub flows: bool
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

    pub fn filter_port(mut self, port: u16) -> EbpfRunnerConfig {
        self.port = port;
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

    pub fn watcher_config(&self) -> EbpfWatcherConfig {
        EbpfWatcherConfig { packets: self.headers, stats: true, calls: self.kernel, flows: true }
    }
}