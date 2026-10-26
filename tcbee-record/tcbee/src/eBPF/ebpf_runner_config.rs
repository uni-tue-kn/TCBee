use std::net::IpAddr;

use anyhow::anyhow;

use crate::{
    eBPF::probes::{
        headers::HeadersAt,
        tracepoints::{Tracepoint, TracepointSet},
    },
    writer::PollMode,
};
use tcbee_common::{filter::*, stats::RINGBUFS};
use tcbee_trace::{
    onchange::{Manifest, Sampling, SockField, SourceMeta, WatchSet, MANIFEST_VERSION},
    sock_hooks::{Hook, HookSet},
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

/// The filter map keys of an address. A dual-stack socket (AF_INET6) talks to an IPv4 peer with
/// v4-mapped addresses, which the socket programs take as they are, so an IPv4 address also
/// matches in its v4-mapped form (`::ffff:a.b.c.d`). Only the keys change, the programs and their
/// code stay the same.
pub fn ip_filter_keys(ip: IpAddr) -> Vec<[u8; 16]> {
    match ip {
        IpAddr::V4(v4) => vec![ip_to_filter_addr(ip), v4.to_ipv6_mapped().octets()],
        IpAddr::V6(_) => vec![ip_to_filter_addr(ip)],
    }
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
        TracepointSet::DEFAULT
    } else {
        TracepointSet::EMPTY
    };
    if events || drops {
        set = set.union(TracepointSet::EVENTS);
    }
    if drops {
        set = set.union(TracepointSet::of(&[Tracepoint::Drops]));
    }
    Ok(set)
}

/// `--no-timer-hook` switches off the write timer program of -k; on-change mode picks its
/// hooks with `--on-change-hooks` instead
fn check_no_timer_hook(no_timer_hook: bool, kernel: bool, on_change: bool) -> anyhow::Result<()> {
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

/// The hooks of `-k` without on-change: `--sock-hooks` (default the write timer and the
/// socket events), less the timer with `--no-timer-hook`
fn full_sock_hooks(spec: &str, no_timer_hook: bool) -> anyhow::Result<HookSet> {
    let hooks = if spec.is_empty() {
        HookSet::FULL_DEFAULT
    } else {
        HookSet::parse(spec, HookSet::FULL_DEFAULT).map_err(|e| anyhow!("--sock-hooks: {}", e))?
    };
    if no_timer_hook {
        if hooks == HookSet::of(&[Hook::Timer]) {
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
        HookSet::ON_CHANGE_DEFAULT
    } else {
        HookSet::parse_on_change(hooks).map_err(|e| anyhow!("--on-change-hooks: {}", e))?
    };
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

/// The flags that pick the hooks of the sock (-k) and cwnd (-w) probes, as given; empty
/// strings for flags that are not given
#[derive(Debug, Default, Clone, Copy)]
pub struct HookFlags<'a> {
    pub kernel: bool,
    pub cwnd: bool,
    pub sock_hooks: &'a str,
    pub on_change: &'a str,
    pub on_change_hooks: &'a str,
    pub on_change_shadow: bool,
    pub no_timer_hook: bool,
}

impl HookFlags<'_> {
    /// On-change mode, or else the hooks of -k in full mode (None without -k). With
    /// --on-change, `--sock-hooks` names the compared hooks like `--on-change-hooks`, but only
    /// with -k: the cwnd probe of -w ignores `--sock-hooks` in full mode, so with -w alone it
    /// is refused rather than picking the cwnd hooks in on-change mode only.
    pub fn resolve(&self) -> anyhow::Result<(Option<OnChange>, Option<HookSet>)> {
        let sock_hooks = !self.sock_hooks.is_empty();
        if sock_hooks && !self.on_change_hooks.is_empty() {
            return Err(anyhow!(
                "--sock-hooks and --on-change-hooks name the same hooks, give one"
            ));
        }
        if sock_hooks && !self.kernel {
            return Err(anyhow!(
                "--sock-hooks needs -k; with --on-change and -w alone use --on-change-hooks"
            ));
        }
        let on_change_hooks = if sock_hooks && !self.on_change.is_empty() {
            self.sock_hooks
        } else {
            self.on_change_hooks
        };
        let on_change = parse_on_change(
            self.on_change,
            on_change_hooks,
            self.on_change_shadow,
            self.kernel,
            self.cwnd,
        )?;
        check_no_timer_hook(self.no_timer_hook, self.kernel, on_change.is_some())?;
        let full = if self.kernel && on_change.is_none() {
            Some(full_sock_hooks(self.sock_hooks, self.no_timer_hook)?)
        } else {
            None
        };
        Ok((on_change, full))
    }
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

#[derive(Debug)]
pub struct EbpfRunnerConfig {
    pub iface: String,
    pub do_tui: bool,
    pub update_period: u128,
    pub observation_window: f64,
    pub filter: FilterConfig,
    pub headers: bool,
    pub headers_at: HeadersAt,
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
    /// The hooks of -k in full mode, None without -k or in on-change mode (`HookFlags`)
    pub sock_hooks: Option<HookSet>,
    /// Record the process that opens each connection (`flow_owners.tcp`), along with
    /// whatever else records; never a reason to record on its own
    pub owners: bool,
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
    /// The packet rates come from the driver hooks (only they record)
    pub driver_packets: bool,
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
    /// Records nothing until a probe is switched on
    pub fn new() -> EbpfRunnerConfig {
        EbpfRunnerConfig {
            iface: String::new(),
            do_tui: false,
            update_period: 0,
            observation_window: 0.0,
            filter: FilterConfig::default(),
            headers: false,
            headers_at: HeadersAt::default(),
            tracepoints: TracepointSet::EMPTY,
            kernel: false,
            cwnd: false,
            metrics: false,
            metadata: false,
            algorithms: false,
            mptcp: MptcpModes::default(),
            dir: String::new(),
            ringbuf_sizes: Vec::new(),
            poll_mode: PollMode::default(),
            writer_cpus: Vec::new(),
            on_change: None,
            sock_hooks: None,
            owners: false,
        }
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

    pub fn headers_at(mut self, at: HeadersAt) -> EbpfRunnerConfig {
        self.headers_at = at;
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

    pub fn sock_hooks(mut self, hooks: Option<HookSet>) -> EbpfRunnerConfig {
        self.sock_hooks = hooks;
        self
    }

    /// Whether -k records at `hook` in full mode
    pub fn sock_hooked(&self, hook: Hook) -> bool {
        self.sock_hooks.is_some_and(|hooks| hooks.contains(hook))
    }

    pub fn owners(mut self, set: bool) -> EbpfRunnerConfig {
        self.owners = set;
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
            driver_packets: self.headers && self.headers_at.driver && !self.headers_at.tc,
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

    /// `all` in an on-change list names the hooks on-change mode can use
    #[test]
    fn on_change_lists_know_only_their_hooks() {
        let oc = parse_on_change("cc", "all", false, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(oc.hooks, HookSet::of(&Hook::ON_CHANGE));
        let err = parse_on_change("cc", "state", false, true, false).unwrap_err();
        assert!(!err.to_string().contains("ingress-entry"), "{err}");
    }

    #[test]
    fn sock_hooks_without_on_change() {
        assert_eq!(full_sock_hooks("", false).unwrap(), HookSet::FULL_DEFAULT);
        assert_eq!(
            full_sock_hooks("", true).unwrap(),
            HookSet::FULL_DEFAULT.without(Hook::Timer)
        );
        let sender = full_sock_hooks("+ingress", false).unwrap();
        assert!(sender.contains(Hook::Ingress) && sender.contains(Hook::State));
        assert_eq!(
            full_sock_hooks("egress,ingress-entry,timer", true).unwrap(),
            HookSet::of(&[Hook::Egress, Hook::IngressEntry])
        );
        assert!(full_sock_hooks("timer", true).is_err());
        assert_eq!(
            full_sock_hooks("ingress,timer", false).unwrap(),
            HookSet::ON_CHANGE_DEFAULT
        );
        assert!(full_sock_hooks("rx", false).is_err());
        assert_eq!(
            full_sock_hooks("timer,+ca_state", false).unwrap(),
            HookSet::of(&[Hook::Timer, Hook::CaState])
        );
        assert!(full_sock_hooks("-all", false).is_err());
    }

    #[test]
    fn on_change_takes_its_own_hooks_only() {
        assert!(parse_on_change("cc", "ingress-entry", false, true, false).is_err());
        let oc = parse_on_change("cc", "+egress", false, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(
            oc.hooks,
            HookSet::of(&[Hook::Ingress, Hook::Timer, Hook::Egress])
        );
    }

    /// -e and --drops record what they did before -t had the TCP events
    #[test]
    fn old_event_flags() {
        let events = TracepointSet::EVENTS;
        assert_eq!(tracepoint_set(false, "", true, false).unwrap(), events);
        assert_eq!(
            tracepoint_set(false, "", false, true).unwrap(),
            events.union(TracepointSet::of(&[Tracepoint::Drops]))
        );
        assert_eq!(
            tracepoint_set(true, "", false, false).unwrap(),
            TracepointSet::DEFAULT
        );
        assert_eq!(
            tracepoint_set(false, "probe", false, false).unwrap(),
            TracepointSet::of(&[Tracepoint::Probe])
        );
        assert!(tracepoint_set(false, "", false, false).unwrap().is_empty());
    }

    #[test]
    fn ipv4_filter_addresses_also_match_v4_mapped() {
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(
            ip_filter_keys(v4),
            [ip_to_filter_addr(v4), ip_to_filter_addr(mapped)]
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(ip_filter_keys(v6), [ip_to_filter_addr(v6)]);
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

    fn k() -> HookFlags<'static> {
        HookFlags {
            kernel: true,
            ..HookFlags::default()
        }
    }

    #[test]
    fn hook_flags_of_the_full_mode() {
        let (on_change, full) = k().resolve().unwrap();
        assert!(on_change.is_none());
        assert_eq!(full, Some(HookSet::FULL_DEFAULT));
        let flags = HookFlags {
            sock_hooks: "+ingress",
            ..k()
        };
        assert!(flags.resolve().unwrap().1.unwrap().contains(Hook::Ingress));
        let flags = HookFlags {
            no_timer_hook: true,
            ..k()
        };
        let full = flags.resolve().unwrap().1;
        assert_eq!(full, Some(HookSet::FULL_DEFAULT.without(Hook::Timer)));
        let flags = HookFlags {
            sock_hooks: "egress,timer",
            no_timer_hook: true,
            ..k()
        };
        let full = flags.resolve().unwrap().1;
        assert_eq!(full, Some(HookSet::of(&[Hook::Egress])));
    }

    #[test]
    fn hook_flags_without_k() {
        let w = HookFlags {
            cwnd: true,
            ..HookFlags::default()
        };
        let (on_change, full) = w.resolve().unwrap();
        assert!(on_change.is_none() && full.is_none());
        for flags in [
            HookFlags {
                sock_hooks: "egress",
                ..w
            },
            HookFlags {
                no_timer_hook: true,
                ..w
            },
            // -w with on-change takes its hooks from --on-change-hooks only
            HookFlags {
                sock_hooks: "egress",
                on_change: "cc",
                ..w
            },
        ] {
            assert!(flags.resolve().is_err(), "{flags:?}");
        }
        let flags = HookFlags {
            on_change: "cc",
            on_change_hooks: "+egress",
            ..w
        };
        let (on_change, full) = flags.resolve().unwrap();
        assert!(on_change.unwrap().hooks.contains(Hook::Egress) && full.is_none());
    }

    #[test]
    fn hook_flags_with_on_change() {
        let flags = HookFlags {
            on_change: "cc",
            ..k()
        };
        let (on_change, full) = flags.resolve().unwrap();
        assert_eq!(on_change.unwrap().hooks, HookSet::ON_CHANGE_DEFAULT);
        assert!(full.is_none());
        // --sock-hooks names the compared hooks like --on-change-hooks
        for hooks in [("+egress", ""), ("", "+egress")] {
            let flags = HookFlags {
                sock_hooks: hooks.0,
                on_change_hooks: hooks.1,
                ..flags
            };
            let (on_change, full) = flags.resolve().unwrap();
            assert_eq!(
                on_change.unwrap().hooks,
                HookSet::of(&[Hook::Ingress, Hook::Timer, Hook::Egress])
            );
            assert!(full.is_none());
        }
        for bad in [
            HookFlags {
                sock_hooks: "egress",
                on_change_hooks: "egress",
                ..flags
            },
            HookFlags {
                no_timer_hook: true,
                ..flags
            },
            HookFlags {
                sock_hooks: "state",
                ..flags
            },
            HookFlags {
                on_change_hooks: "egress",
                ..k()
            },
            HookFlags {
                sock_hooks: "egress",
                on_change_hooks: "egress",
                ..k()
            },
        ] {
            assert!(bad.resolve().is_err(), "{bad:?}");
        }
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
        assert_eq!(oc.hooks, HookSet::ON_CHANGE_DEFAULT);
        let oc = parse_on_change("cc", "ingress", false, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(oc.hooks, HookSet::of(&[Hook::Ingress]));
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
            hooks: HookSet::of(&[Hook::Ingress, Hook::Timer, Hook::Egress]),
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
        oc.hooks = HookSet::ON_CHANGE_DEFAULT;
        let m = on_change_manifest(oc, true, true);
        assert_eq!(files(&m), ["recv_sock_oc.tcp", "recv_cwnd_oc.tcp"]);
        oc.hooks = HookSet::of(&[Hook::Egress]);
        let m = on_change_manifest(oc, true, false);
        assert_eq!(files(&m), ["send_sock_oc.tcp"]);
    }
}
