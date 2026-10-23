use std::net::IpAddr;

use anyhow::anyhow;

use crate::writer::PollMode;
use tcbee_common::{filter::*, stats::RINGBUFS};
use tcbee_trace::{
    onchange::{
        Hook, HookSet, Manifest, Sampling, SockField, SourceMeta, WatchSet, MANIFEST_VERSION,
    },
    TraceFile,
};

/// On-change mode of the sock (-k) and cwnd (-w) probes: a record only when a watched field
/// or the socket state changed
#[derive(Debug, Clone, Copy)]
pub struct OnChange {
    /// Socket fields the sock probes compare; the cwnd probes compare snd_cwnd
    pub watch: WatchSet,
    /// Write every sock run anyway, with the decision as a reason code in `ato`
    pub shadow: bool,
    /// Kernel hooks the on-change programs run at
    pub hooks: HookSet,
}

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

/// max_entries is a u32 and has to be a power of two, so 2 GiB is the largest size
const MAX_RINGBUF_SIZE: u64 = 1 << 31;
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
        for ringbuf in &RINGBUFS {
            let (name, group) = (ringbuf.map, ringbuf.group);
            let selected = match selector {
                None => true,
                Some(sel) => sel.eq_ignore_ascii_case(group) || sel.eq_ignore_ascii_case(name),
            };
            if selected {
                matched = true;
                sizes.retain(|(n, _)| *n != name);
                sizes.push((name, size as u32));
            }
        }
        if !matched {
            let mut groups: Vec<&str> = RINGBUFS.iter().map(|ringbuf| ringbuf.group).collect();
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
    let items: Vec<&str> = arg
        .split(',')
        .map(str::trim)
        .filter(|i| !i.is_empty())
        .collect();
    for item in items.iter().filter(|i| !i.contains('=')) {
        set(None, parse_size(item)?)?;
    }
    for item in items.iter().filter(|i| i.contains('=')) {
        let (selector, size) = item.split_once('=').unwrap();
        set(Some(selector.trim()), parse_size(size)?)?;
    }
    Ok(sizes)
}

/// What `-m` records about MPTCP
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct MptcpModes {
    /// Tag the sock and cwnd records of a subflow with the token of its connection
    pub tag: bool,
    /// Record path manager and lifecycle events
    pub pm: bool,
}

impl MptcpModes {
    const NAMES: &'static str = "tag, pm";

    /// The modes of a plain `-m`: path manager events, and tagging if sock or cwnd records are
    /// recorded
    pub fn default_for(tagged_records: bool) -> MptcpModes {
        MptcpModes {
            tag: tagged_records,
            pm: true,
        }
    }

    /// Parses `--mptcp-modes`, a comma separated list of modes
    pub fn parse(arg: &str) -> anyhow::Result<MptcpModes> {
        let mut modes = MptcpModes::default();
        for mode in arg.split(',').map(str::trim).filter(|m| !m.is_empty()) {
            match mode {
                "tag" => modes.tag = true,
                "pm" => modes.pm = true,
                other => {
                    return Err(anyhow!(
                        "Unknown MPTCP mode '{}', use {}",
                        other,
                        MptcpModes::NAMES
                    ))
                }
            }
        }
        Ok(modes)
    }
}

/// The tracepoints `-t` records, by their `--tp` names. `-t` alone records all but the
/// opt-in ones.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct TracepointSet(u16);

impl TracepointSet {
    /// Every name with whether a plain `-t` records it. Each `-e` event is a TCP event hook
    /// (`TCP_EVENT_HOOKS`), the others are programs of their own.
    pub const NAMES: [(&'static str, bool); 11] = [
        ("probe", true),
        ("synack", true),
        ("bad_csum", true),
        ("retransmit", true),
        ("rst_sent", true),
        ("rst_received", true),
        ("state", true),
        ("ca_state", true),
        ("rto", true),
        ("destroy", true),
        ("drops", false),
    ];
    /// What `-e` used to record
    pub const EVENTS: [&'static str; 7] = [
        "retransmit",
        "rst_sent",
        "rst_received",
        "state",
        "ca_state",
        "rto",
        "destroy",
    ];

    fn bit(name: &str) -> Option<u16> {
        Self::NAMES
            .iter()
            .position(|(n, _)| *n == name)
            .map(|i| 1 << i)
    }

    /// What a plain `-t` records
    pub fn default_set() -> TracepointSet {
        TracepointSet(
            Self::NAMES
                .iter()
                .enumerate()
                .filter(|(_, (_, default))| *default)
                .fold(0, |bits, (i, _)| bits | 1 << i),
        )
    }

    pub fn all() -> TracepointSet {
        TracepointSet((1 << Self::NAMES.len()) - 1)
    }

    /// The set of these names, which must be in `NAMES`
    pub fn of(names: &[&str]) -> TracepointSet {
        TracepointSet(
            names
                .iter()
                .map(|n| Self::bit(n).expect(n))
                .fold(0, |a, b| a | b),
        )
    }

    pub fn union(self, other: TracepointSet) -> TracepointSet {
        TracepointSet(self.0 | other.0)
    }

    pub fn contains(self, name: &str) -> bool {
        Self::bit(name).is_some_and(|bit| self.0 & bit != 0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether any of these names is in the set
    pub fn any(self, names: &[&str]) -> bool {
        names.iter().any(|n| self.contains(n))
    }

    /// Parses `--tp`, a comma-separated list of names, `all` and `default`. A list in which
    /// every item starts with `+` or `-` changes the default set, otherwise it is the set.
    pub fn parse(arg: &str) -> anyhow::Result<TracepointSet> {
        let items: Vec<&str> = arg
            .split(',')
            .map(str::trim)
            .filter(|i| !i.is_empty())
            .collect();
        if items.is_empty() {
            return Err(anyhow!("--tp needs at least one tracepoint name"));
        }
        let relative = items.iter().all(|i| i.starts_with(['+', '-']));
        let mut set = if relative {
            TracepointSet::default_set()
        } else {
            TracepointSet::default()
        };
        for item in items {
            let (remove, name) = match item.split_at(item.starts_with(['+', '-']) as usize) {
                ("-", name) => (true, name),
                (_, name) => (false, name),
            };
            let bits = match name {
                "all" => TracepointSet::all().0,
                "default" => TracepointSet::default_set().0,
                name => Self::bit(name).ok_or_else(|| {
                    let names: Vec<_> = Self::NAMES.iter().map(|(n, _)| *n).collect();
                    anyhow!(
                        "Unknown tracepoint '{}', use all, default or {}",
                        name,
                        names.join(", ")
                    )
                })?,
            };
            set.0 = if remove { set.0 & !bits } else { set.0 | bits };
        }
        Ok(set)
    }
}

/// The tracepoints of `-t`, `--tp` and the old flags `-e` and `--drops`, which add the TCP
/// events and the drops to them
pub fn tracepoint_set(
    tracepoints: bool,
    tp: &str,
    events: bool,
    drops: bool,
) -> anyhow::Result<TracepointSet> {
    let mut set = if !tp.is_empty() {
        TracepointSet::parse(tp)?
    } else if tracepoints {
        TracepointSet::default_set()
    } else {
        TracepointSet::default()
    };
    if events || drops {
        set = set.union(TracepointSet::of(&TracepointSet::EVENTS));
    }
    if drops {
        set = set.union(TracepointSet::of(&["drops"]));
    }
    Ok(set)
}

/// `--no-timer-hook` switches off the write timer program of -k; on-change mode picks its
/// hooks with `--on-change-hooks` instead
pub fn check_no_timer_hook(
    no_timer_hook: bool,
    kernel: bool,
    on_change: bool,
) -> anyhow::Result<()> {
    if !no_timer_hook {
        return Ok(());
    }
    if !kernel {
        return Err(anyhow!("--no-timer-hook needs -k"));
    }
    if on_change {
        return Err(anyhow!(
            "--no-timer-hook is for the default mode, use --on-change-hooks with --on-change"
        ));
    }
    Ok(())
}

/// The hooks of `-k` without on-change: `--sock-hooks` (default egress, ingress-entry and
/// timer), less the timer with `--no-timer-hook`
pub fn full_sock_hooks(spec: &str, no_timer_hook: bool) -> anyhow::Result<HookSet> {
    let hooks = if spec.is_empty() {
        HookSet::FULL_DEFAULT
    } else {
        HookSet::parse_changes(spec, HookSet::FULL_DEFAULT)
            .map_err(|e| anyhow!("--sock-hooks: {}", e))?
    };
    if hooks.contains(Hook::Ingress) {
        return Err(anyhow!("--sock-hooks: ingress needs --on-change"));
    }
    if no_timer_hook {
        if hooks == HookSet::parse("timer").unwrap() {
            return Err(anyhow!("--no-timer-hook leaves -k without hooks"));
        }
        return Ok(hooks.without(Hook::Timer));
    }
    Ok(hooks)
}

/// `--on-change FIELDS`, `--on-change-hooks HOOKS` (or `--sock-hooks`) and
/// `--on-change-shadow`, None in the default mode. An empty `hooks` is the default set
/// (ingress and timer).
pub fn parse_on_change(
    fields: &str,
    hooks: &str,
    shadow: bool,
    kernel: bool,
    cwnd: bool,
) -> anyhow::Result<Option<OnChange>> {
    if fields.is_empty() {
        if shadow {
            return Err(anyhow!("--on-change-shadow needs --on-change"));
        }
        if !hooks.is_empty() {
            return Err(anyhow!("--on-change-hooks needs --on-change"));
        }
        return Ok(None);
    }
    if !kernel && !cwnd {
        return Err(anyhow!("--on-change needs -k or -w"));
    }
    if shadow && !kernel {
        return Err(anyhow!("--on-change-shadow needs -k"));
    }
    let watch = WatchSet::parse(fields).map_err(|e| anyhow!("--on-change: {}", e))?;
    let hooks = if hooks.is_empty() {
        HookSet::DEFAULT
    } else {
        HookSet::parse_changes(hooks, HookSet::DEFAULT)
            .map_err(|e| anyhow!("--on-change-hooks: {}", e))?
    };
    if let Some(hook) = hooks.hooks().find(|h| !Hook::ON_CHANGE.contains(h)) {
        return Err(anyhow!(
            "--on-change compares at ingress, timer and egress only, not at {}",
            hook.name()
        ));
    }
    let per_packet: Vec<&str> = watch
        .fields()
        .filter(|f| f.changes_per_packet())
        .map(SockField::name)
        .collect();
    if kernel && !per_packet.is_empty() {
        eprintln!(
            "Warning: {} change on almost every packet, on-change mode will write nearly every run",
            per_packet.join(", ")
        );
    }
    Ok(Some(OnChange {
        watch,
        shadow,
        hooks,
    }))
}

/// What the on-change files in the recording directory hold, for tcbee-process: per probe,
/// the send file if egress is hooked and the receive file if ingress or timer is
fn on_change_sources(
    hooks: HookSet,
    (send_file, receive_file): (TraceFile, TraceFile),
    fields: Vec<String>,
    shadow: bool,
) -> Vec<SourceMeta> {
    let source = |file: TraceFile, file_hooks: Vec<Hook>| SourceMeta {
        file: file.filename().into(),
        sampling: Sampling::OnChange {
            fields: fields.clone(),
        },
        shadow,
        recv_hook: "fexit/tcp_rcv_established".into(),
        hooks: file_hooks
            .iter()
            .flat_map(|h| h.kernel_hooks())
            .map(|k| k.to_string())
            .collect(),
    };
    let mut sources = Vec::new();
    if hooks.send() {
        sources.push(source(send_file, vec![Hook::Egress]));
    }
    if hooks.receive() {
        let receive = hooks.hooks().filter(|h| *h != Hook::Egress).collect();
        sources.push(source(receive_file, receive));
    }
    sources
}

/// The manifest of an on-change recording: the on-change files of the sock (`kernel`) and cwnd
/// probes
pub fn on_change_manifest(on_change: OnChange, kernel: bool, cwnd: bool) -> Manifest {
    let mut sources = Vec::new();
    if kernel {
        let fields = on_change.watch.fields().map(|f| f.name().into()).collect();
        sources.extend(on_change_sources(
            on_change.hooks,
            (TraceFile::SendSockOc, TraceFile::RecvSockOc),
            fields,
            on_change.shadow,
        ));
    }
    if cwnd {
        sources.extend(on_change_sources(
            on_change.hooks,
            (TraceFile::SendCwndOc, TraceFile::RecvCwndOc),
            vec!["snd_cwnd".into()],
            false,
        ));
    }
    Manifest {
        format_version: MANIFEST_VERSION,
        sources,
    }
}

#[derive(Default, Debug)]
pub struct EbpfRunnerConfig {
    pub iface: String,
    pub do_tui: bool,
    pub update_period: u128,
    pub observation_window: f64,
    pub filter: FilterConfig,
    pub headers: bool,
    pub tracepoints: TracepointSet,
    pub kernel: bool,
    pub cwnd: bool,
    pub metrics: bool,
    pub metadata: bool,
    pub algorithms: bool,
    pub mptcp: MptcpModes,
    pub dir: String,
    pub ringbuf_sizes: Vec<(&'static str, u32)>,
    pub poll_mode: PollMode,
    pub writer_cpus: Vec<usize>,
    pub on_change: Option<OnChange>,
    /// The hooks of -k without on-change, see `full_sock_hooks`
    pub sock_hooks: HookSet,
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

    pub fn tracepoints(mut self, set: TracepointSet) -> EbpfRunnerConfig {
        self.tracepoints = set;
        self
    }

    pub fn kernel(mut self, set: bool) -> EbpfRunnerConfig {
        self.kernel = set;
        self
    }

    pub fn sock_hooks(mut self, hooks: HookSet) -> EbpfRunnerConfig {
        self.sock_hooks = hooks;
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

    pub fn metadata(mut self, set: bool) -> EbpfRunnerConfig {
        self.metadata = set;
        self
    }

    pub fn algorithms(mut self, set: bool) -> EbpfRunnerConfig {
        self.algorithms = set;
        self
    }

    pub fn mptcp(mut self, modes: MptcpModes) -> EbpfRunnerConfig {
        self.mptcp = modes;
        self
    }

    pub fn writer_cpus(mut self, cpus: Vec<usize>) -> EbpfRunnerConfig {
        self.writer_cpus = cpus;
        self
    }

    pub fn on_change(mut self, on_change: Option<OnChange>) -> EbpfRunnerConfig {
        self.on_change = on_change;
        self
    }

    pub fn poll_mode(mut self, mode: PollMode) -> EbpfRunnerConfig {
        self.poll_mode = mode;
        self
    }

    pub fn ringbuf_sizes(mut self, sizes: Vec<(&'static str, u32)>) -> EbpfRunnerConfig {
        self.ringbuf_sizes = sizes;
        self
    }

    /// Size of each CPU's ring buffer `rb`: from `--ringbuf-size` or the default
    pub fn ringbuf_size(&self, rb: u32) -> u32 {
        let ringbuf = &RINGBUFS[rb as usize];
        self.ringbuf_sizes
            .iter()
            .find(|(name, _)| *name == ringbuf.map)
            .map_or(ringbuf.size_per_cpu, |(_, size)| *size)
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
    fn sock_hooks_without_on_change() {
        assert_eq!(full_sock_hooks("", false).unwrap(), HookSet::FULL_DEFAULT);
        assert_eq!(
            full_sock_hooks("", true).unwrap(),
            HookSet::parse("egress,ingress-entry").unwrap()
        );
        assert_eq!(
            full_sock_hooks("-egress", false).unwrap(),
            HookSet::parse("ingress-entry,timer").unwrap()
        );
        assert!(full_sock_hooks("timer", true).is_err());
        assert!(full_sock_hooks("ingress", false).is_err());
        assert!(full_sock_hooks("rx", false).is_err());
    }

    #[test]
    fn on_change_takes_its_own_hooks_only() {
        assert!(parse_on_change("cc", "ingress-entry", false, true, false).is_err());
        let oc = parse_on_change("cc", "+egress", false, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(oc.hooks, HookSet::parse("ingress,timer,egress").unwrap());
    }

    #[test]
    fn tracepoint_lists() {
        let default = TracepointSet::default_set();
        assert!(default.contains("probe") && default.contains("destroy"));
        assert!(!default.contains("drops"));
        assert_eq!(TracepointSet::parse("default").unwrap(), default);
        assert_eq!(
            TracepointSet::parse("probe, rto").unwrap(),
            TracepointSet::of(&["probe", "rto"])
        );
        let changed = TracepointSet::parse("+drops,-probe").unwrap();
        assert!(changed.contains("drops") && !changed.contains("probe"));
        assert!(changed.contains("state"));
        assert_eq!(
            TracepointSet::parse("all,-drops").unwrap(),
            TracepointSet::parse("default").unwrap()
        );
        assert!(TracepointSet::parse("probe,cwnd").is_err());
        assert!(TracepointSet::parse(" , ").is_err());
    }

    /// -e and --drops record what they did before -t had the TCP events
    #[test]
    fn old_event_flags() {
        let events = TracepointSet::of(&TracepointSet::EVENTS);
        assert_eq!(tracepoint_set(false, "", true, false).unwrap(), events);
        assert_eq!(
            tracepoint_set(false, "", false, true).unwrap(),
            events.union(TracepointSet::of(&["drops"]))
        );
        assert_eq!(
            tracepoint_set(true, "", false, false).unwrap(),
            TracepointSet::default_set()
        );
        assert_eq!(
            tracepoint_set(false, "probe", false, false).unwrap(),
            TracepointSet::of(&["probe"])
        );
        assert!(tracepoint_set(false, "", false, false).unwrap().is_empty());
    }

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
    fn no_timer_hook_only_for_the_default_sock_probe() {
        assert!(check_no_timer_hook(false, false, false).is_ok());
        assert!(check_no_timer_hook(true, true, false).is_ok());
        assert!(check_no_timer_hook(true, false, false).is_err());
        assert!(check_no_timer_hook(true, true, true).is_err());
    }

    #[test]
    fn mptcp_modes() {
        let tag = MptcpModes {
            tag: true,
            pm: false,
        };
        assert_eq!(MptcpModes::parse(" tag, ").unwrap(), tag);
        assert_eq!(
            MptcpModes::parse("pm,tag").unwrap(),
            MptcpModes::default_for(true)
        );
        assert_eq!(MptcpModes::parse("").unwrap(), MptcpModes::default());
        assert!(MptcpModes::parse("tag,foo").is_err());
    }

    #[test]
    fn ringbuf_size_rejects_invalid() {
        assert!(parse_ringbuf_sizes("").unwrap().is_empty());
        assert_eq!(parse_ringbuf_sizes("1").unwrap()[0].1, 4096);
        assert!(parse_ringbuf_sizes("0").is_err());
        assert_eq!(parse_ringbuf_sizes("TCP4=2G").unwrap()[0].1, 1 << 31);
        assert!(parse_ringbuf_sizes("3G").is_err());
        assert!(parse_ringbuf_sizes("foo=1M").is_err());
        assert!(parse_ringbuf_sizes("tcp4=1X").is_err());
    }

    #[test]
    fn on_change_options() {
        assert!(parse_on_change("", "", false, true, true)
            .unwrap()
            .is_none());
        let oc = parse_on_change("cc", "", true, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(oc.watch, WatchSet::CC);
        assert!(oc.shadow);
        assert_eq!(oc.hooks, HookSet::DEFAULT);
        let oc = parse_on_change("cc", "ingress", false, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(oc.hooks, HookSet::parse("ingress").unwrap());
        assert!(parse_on_change("", "", true, true, false).is_err());
        assert!(parse_on_change("", "egress", false, true, false).is_err());
        assert!(parse_on_change("cc", "", false, false, false).is_err());
        assert!(parse_on_change("cc", "", true, false, true).is_err());
        assert!(parse_on_change("cc", "tx", false, true, false).is_err());
        assert!(parse_on_change("cwnd", "", false, true, false).is_err());
        assert!(parse_on_change("pacing_rate/16", "", false, true, false).is_err());
    }

    fn files(m: &Manifest) -> Vec<&str> {
        m.sources.iter().map(|s| s.file.as_str()).collect()
    }

    #[test]
    fn manifest_lists_the_enabled_on_change_files() {
        let mut oc = OnChange {
            watch: WatchSet::parse("snd_cwnd,total_retrans").unwrap(),
            shadow: false,
            hooks: HookSet::parse("ingress,timer,egress").unwrap(),
        };
        let m = on_change_manifest(oc, true, true);
        assert_eq!(
            files(&m),
            [
                "send_sock_oc.tcp",
                "recv_sock_oc.tcp",
                "send_cwnd_oc.tcp",
                "recv_cwnd_oc.tcp"
            ]
        );
        assert_eq!(
            m.sources[0].sampling,
            Sampling::OnChange {
                fields: vec!["snd_cwnd".into(), "total_retrans".into()]
            }
        );
        assert_eq!(m.sources[0].hooks, ["fentry/__tcp_transmit_skb"]);
        assert_eq!(
            m.sources[1].hooks,
            [
                "fexit/tcp_rcv_established",
                "fexit/tcp_rcv_state_process",
                "fexit/tcp_write_timer_handler"
            ]
        );
        assert_eq!(on_change_manifest(oc, false, true).sources.len(), 2);

        // The default hooks write no send files
        oc.hooks = HookSet::DEFAULT;
        let m = on_change_manifest(oc, true, true);
        assert_eq!(files(&m), ["recv_sock_oc.tcp", "recv_cwnd_oc.tcp"]);
        oc.hooks = HookSet::parse("egress").unwrap();
        let m = on_change_manifest(oc, true, false);
        assert_eq!(files(&m), ["send_sock_oc.tcp"]);
    }
}
