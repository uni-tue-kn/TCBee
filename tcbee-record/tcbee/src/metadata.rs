//! Run metadata (`--metadata`): the host, kernel, network settings and recorder options of a
//! recording, plus clock and counter samples at start and stop. Written as JSON into the trace
//! directory once the probes are attached and again at stop, so a crash still leaves the start.
//!
//! Every value is collected best effort: something that cannot be read is left out or null
//! and the recording goes on.

use std::{
    collections::BTreeMap,
    ffi::CStr,
    fs,
    io::{self, Write},
    mem,
    path::Path,
    process::Command,
};

use log::warn;
use serde::Serialize;

use crate::metrics::RingCounters;

/// Version of the file layout, increased when a field changes meaning
const FORMAT: u32 = 1;

/// Sysctls that change how TCP behaves, relative to /proc/sys
const SYSCTLS: [&str; 15] = [
    "net/ipv4/tcp_congestion_control",
    "net/ipv4/tcp_available_congestion_control",
    "net/ipv4/tcp_rmem",
    "net/ipv4/tcp_wmem",
    "net/ipv4/tcp_ecn",
    "net/ipv4/tcp_sack",
    "net/ipv4/tcp_timestamps",
    "net/ipv4/tcp_window_scaling",
    "net/ipv4/tcp_mtu_probing",
    "net/ipv4/tcp_no_metrics_save",
    "net/ipv4/tcp_notsent_lowat",
    "net/core/rmem_max",
    "net/core/wmem_max",
    "net/core/default_qdisc",
    "net/core/netdev_max_backlog",
];

/// Clock samples taken per measurement; the one with the shortest bracket is kept
const CLOCK_SAMPLES: usize = 16;

#[derive(Serialize)]
pub struct RunMetadata {
    format: u32,
    host: Host,
    kernel: Kernel,
    recorder: Recorder,
    /// Raw sysctl values keyed by their dotted name, whitespace collapsed
    sysctls: BTreeMap<String, String>,
    interfaces: Vec<Interface>,
    start: Sample,
    stop: Option<Sample>,
}

#[derive(Serialize)]
struct Host {
    hostname: Option<String>,
    /// Changes with every boot. Timestamps of two recordings are only comparable on
    /// CLOCK_MONOTONIC if the boot_id is the same.
    boot_id: Option<String>,
    /// Network namespace of the recorder, e.g. `net:[4026531840]`. Sysctls, interfaces and
    /// counters are the ones of this namespace.
    netns: Option<String>,
    cpus_online: Option<String>,
}

#[derive(Serialize)]
struct Kernel {
    release: Option<String>,
    version: Option<String>,
    machine: Option<String>,
}

/// What the recorder was asked to do and what it attached. The filters are in `argv`.
#[derive(Serialize, Default)]
pub struct Recorder {
    pub argv: Vec<String>,
    /// Probe groups that record, e.g. `headers`, `kernel`
    pub groups: Vec<String>,
    /// Hooks that were requested but are not recorded, with the reason
    pub skipped: Vec<String>,
    pub interface: Option<String>,
    /// Ring buffer bytes per CPU by map name, for the created ring buffers
    pub ringbuf_sizes: BTreeMap<String, u32>,
}

#[derive(Serialize)]
struct Interface {
    name: String,
    mtu: Option<u32>,
    /// Mb/s; None if the driver does not report it (virtual devices, link down)
    speed: Option<u32>,
    operstate: Option<String>,
    offloads: Offloads,
    qdiscs: Option<Vec<Qdisc>>,
}

#[derive(Serialize, Default)]
struct Offloads {
    tso: Option<bool>,
    gso: Option<bool>,
    gro: Option<bool>,
    lro: Option<bool>,
}

#[derive(Serialize, Debug, PartialEq)]
struct Qdisc {
    kind: String,
    handle: Option<String>,
    parent: Option<String>,
}

/// Clocks and counters at one point in time
#[derive(Serialize)]
struct Sample {
    clock: ClockSample,
    ntp: Option<NtpState>,
    /// Tcp from /proc/net/snmp and TcpExt from /proc/net/netstat
    tcp: BTreeMap<String, BTreeMap<String, i64>>,
    /// Drop counters of the described interfaces, in the order of `interfaces`
    interface_drops: Vec<InterfaceDrops>,
    softnet: Option<Softnet>,
    /// The recorder's own event counters, only in the stop sample
    tcbee: Option<Vec<NamedRingCounters>>,
}

/// One reading of all clocks. The offsets map a CLOCK_MONOTONIC timestamp, which is what
/// bpf_ktime_get_ns returns and what the records carry, to the other clocks.
#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
pub struct ClockSample {
    pub monotonic_ns: i64,
    pub realtime_minus_monotonic_ns: i64,
    pub tai_minus_monotonic_ns: i64,
    pub boottime_minus_monotonic_ns: i64,
    /// Time between the two monotonic reads that bracket the others, an upper bound of the
    /// error of the offsets
    pub uncertainty_ns: i64,
}

#[derive(Serialize)]
struct NtpState {
    /// Return value of adjtimex: 0 TIME_OK ... 5 TIME_ERROR (clock not synchronized)
    state: i32,
    synchronized: bool,
    status: i32,
    /// Estimated and maximum error in microseconds
    esterror_us: i64,
    maxerror_us: i64,
    /// TAI-UTC offset in seconds the kernel knows. 0 means CLOCK_TAI equals CLOCK_REALTIME.
    tai_offset_s: i32,
}

#[derive(Serialize)]
struct InterfaceDrops {
    name: String,
    rx_dropped: Option<u64>,
    tx_dropped: Option<u64>,
}

#[derive(Serialize, Debug, PartialEq, Default)]
struct Softnet {
    /// Packets dropped because a CPU's backlog queue was full, summed over all CPUs
    dropped: u64,
    /// Times net_rx_action ran out of budget or time, summed over all CPUs
    time_squeeze: u64,
}

/// The counters of one ring buffer, by its map name
#[derive(Serialize)]
pub struct NamedRingCounters {
    pub name: String,
    #[serde(flatten)]
    pub counters: RingCounters,
}

impl RunMetadata {
    /// Collects everything. `interface` is the `-h` interface; without it all interfaces that
    /// are up are described, except loopback.
    pub fn collect(recorder: Recorder) -> RunMetadata {
        let interfaces = interface_names(recorder.interface.as_deref());
        RunMetadata {
            format: FORMAT,
            host: Host {
                hostname: read_trimmed("/proc/sys/kernel/hostname"),
                boot_id: read_trimmed("/proc/sys/kernel/random/boot_id"),
                netns: fs::read_link("/proc/self/ns/net")
                    .ok()
                    .map(|link| link.to_string_lossy().into_owned()),
                cpus_online: read_trimmed("/sys/devices/system/cpu/online"),
            },
            kernel: Kernel::read(),
            recorder,
            sysctls: SYSCTLS
                .iter()
                .filter_map(|path| {
                    let value = read_trimmed(Path::new("/proc/sys").join(path))?;
                    Some((path.replace('/', "."), collapse_whitespace(&value)))
                })
                .collect(),
            interfaces: interfaces
                .iter()
                .map(|name| Interface::read(name))
                .collect(),
            start: Sample::take(&interfaces, None),
            stop: None,
        }
    }

    /// Adds the stop sample with the recorder's final counters
    pub fn finish(&mut self, tcbee: Option<Vec<NamedRingCounters>>) {
        let names: Vec<String> = self.interfaces.iter().map(|i| i.name.clone()).collect();
        self.stop = Some(Sample::take(&names, tcbee));
    }

    /// Writes the file through a temporary file, so a reader never sees half of it
    pub fn write(&self, path: &Path) -> io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        let mut file = io::BufWriter::new(fs::File::create(&tmp)?);
        serde_json::to_writer_pretty(&mut file, self)?;
        file.flush()?;
        drop(file);
        fs::rename(&tmp, path)
    }
}

impl Interface {
    fn read(name: &str) -> Interface {
        let sys = Path::new("/sys/class/net").join(name);
        Interface {
            name: name.to_string(),
            mtu: read_trimmed(sys.join("mtu")).and_then(|v| v.parse().ok()),
            // Reading speed fails with EINVAL while the link is down
            speed: read_trimmed(sys.join("speed")).and_then(|v| v.parse().ok()),
            operstate: read_trimmed(sys.join("operstate")),
            offloads: Offloads::read(name),
            qdiscs: qdiscs(name),
        }
    }
}

impl Sample {
    fn take(interfaces: &[String], tcbee: Option<Vec<NamedRingCounters>>) -> Sample {
        let mut tcp = BTreeMap::new();
        for file in ["/proc/net/snmp", "/proc/net/netstat"] {
            if let Ok(text) = fs::read_to_string(file) {
                for (group, values) in parse_snmp(&text) {
                    if group == "Tcp" || group == "TcpExt" {
                        tcp.insert(group, values);
                    }
                }
            }
        }
        let interface_drops = interfaces
            .iter()
            .map(|name| {
                let stats = Path::new("/sys/class/net").join(name).join("statistics");
                let counter = |file| read_trimmed(stats.join(file))?.parse().ok();
                InterfaceDrops {
                    name: name.clone(),
                    rx_dropped: counter("rx_dropped"),
                    tx_dropped: counter("tx_dropped"),
                }
            })
            .collect();
        Sample {
            clock: ClockSample::take(),
            ntp: NtpState::read(),
            tcp,
            interface_drops,
            softnet: fs::read_to_string("/proc/net/softnet_stat")
                .ok()
                .map(|text| parse_softnet(&text)),
            tcbee,
        }
    }
}

fn clock_ns(clock: libc::clockid_t) -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // These clocks exist on every kernel tcbee-record supports, the call cannot fail
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

impl ClockSample {
    fn take() -> ClockSample {
        (0..CLOCK_SAMPLES)
            .map(|_| {
                let before = clock_ns(libc::CLOCK_MONOTONIC);
                let realtime = clock_ns(libc::CLOCK_REALTIME);
                let tai = clock_ns(libc::CLOCK_TAI);
                let boottime = clock_ns(libc::CLOCK_BOOTTIME);
                let after = clock_ns(libc::CLOCK_MONOTONIC);
                ClockSample::from_reads(before, realtime, tai, boottime, after)
            })
            .min_by_key(|sample| sample.uncertainty_ns)
            .expect("CLOCK_SAMPLES > 0")
    }

    /// The other clocks are read between two monotonic reads; their midpoint stands for the
    /// monotonic time of all of them
    fn from_reads(before: i64, realtime: i64, tai: i64, boottime: i64, after: i64) -> ClockSample {
        let monotonic = before + (after - before) / 2;
        ClockSample {
            monotonic_ns: monotonic,
            realtime_minus_monotonic_ns: realtime - monotonic,
            tai_minus_monotonic_ns: tai - monotonic,
            boottime_minus_monotonic_ns: boottime - monotonic,
            uncertainty_ns: after - before,
        }
    }
}

impl NtpState {
    fn read() -> Option<NtpState> {
        let mut timex: libc::timex = unsafe { mem::zeroed() };
        // modes = 0 only reads
        let state = unsafe { libc::adjtimex(&mut timex) };
        if state < 0 {
            return None;
        }
        Some(NtpState {
            state,
            synchronized: state != libc::TIME_ERROR && timex.status & libc::STA_UNSYNC == 0,
            status: timex.status,
            esterror_us: timex.esterror,
            maxerror_us: timex.maxerror,
            tai_offset_s: timex.tai,
        })
    }
}

// ethtool commands of the legacy SIOCETHTOOL interface, from include/uapi/linux/ethtool.h
const ETHTOOL_GTSO: u32 = 0x1e;
const ETHTOOL_GFLAGS: u32 = 0x25;
const ETHTOOL_GGSO: u32 = 0x23;
const ETHTOOL_GGRO: u32 = 0x2b;
const ETH_FLAG_LRO: u32 = 1 << 15;

#[repr(C)]
struct EthtoolValue {
    cmd: u32,
    data: u32,
}

/// struct ifreq with the ifr_data member of its union, padded to the size of the union
#[repr(C)]
struct IfreqData {
    name: [libc::c_char; libc::IFNAMSIZ],
    data: *mut libc::c_void,
    _pad: [u8; 24 - mem::size_of::<*mut libc::c_void>()],
}

impl Offloads {
    fn read(name: &str) -> Offloads {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Offloads::default();
        }
        let get = |cmd: u32| -> Option<u32> {
            let mut value = EthtoolValue { cmd, data: 0 };
            let mut ifr = IfreqData {
                name: [0; libc::IFNAMSIZ],
                data: &mut value as *mut EthtoolValue as *mut libc::c_void,
                _pad: [0; 24 - mem::size_of::<*mut libc::c_void>()],
            };
            if name.len() >= libc::IFNAMSIZ {
                return None;
            }
            for (dst, src) in ifr.name.iter_mut().zip(name.bytes()) {
                *dst = src as libc::c_char;
            }
            let ret = unsafe { libc::ioctl(fd, libc::SIOCETHTOOL, &mut ifr) };
            (ret == 0).then_some(value.data)
        };
        let offloads = Offloads {
            tso: get(ETHTOOL_GTSO).map(|v| v != 0),
            gso: get(ETHTOOL_GGSO).map(|v| v != 0),
            gro: get(ETHTOOL_GGRO).map(|v| v != 0),
            lro: get(ETHTOOL_GFLAGS).map(|v| v & ETH_FLAG_LRO != 0),
        };
        unsafe { libc::close(fd) };
        offloads
    }
}

/// The qdiscs of an interface from `tc -j qdisc show`. None if tc is missing or fails.
fn qdiscs(name: &str) -> Option<Vec<Qdisc>> {
    let output = Command::new("tc")
        .args(["-j", "qdisc", "show", "dev", name])
        .output()
        .inspect_err(|err| warn!("Could not run tc for the qdiscs of {}: {}", name, err))
        .ok()?;
    if !output.status.success() {
        warn!(
            "tc qdisc show dev {} failed: {}",
            name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return None;
    }
    parse_tc_qdiscs(&output.stdout)
}

fn parse_tc_qdiscs(json: &[u8]) -> Option<Vec<Qdisc>> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let text = |q: &serde_json::Value, key: &str| q.get(key)?.as_str().map(str::to_string);
    Some(
        value
            .as_array()?
            .iter()
            .filter_map(|q| {
                Some(Qdisc {
                    kind: text(q, "kind")?,
                    handle: text(q, "handle"),
                    // The root qdisc has "root": true and no parent
                    parent: text(q, "parent"),
                })
            })
            .collect(),
    )
}

/// The interfaces to describe: `selected` if given, else all that are up, except loopback
fn interface_names(selected: Option<&str>) -> Vec<String> {
    if let Some(name) = selected {
        return vec![name.to_string()];
    }
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
        .filter(|name| {
            let sys = Path::new("/sys/class/net").join(name);
            let flags = read_trimmed(sys.join("flags"))
                .and_then(|f| u32::from_str_radix(f.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            flags & libc::IFF_UP as u32 != 0 && flags & libc::IFF_LOOPBACK as u32 == 0
        })
        .collect();
    names.sort();
    names
}

/// Parses /proc/net/snmp or /proc/net/netstat: pairs of lines `Group: names...` and
/// `Group: values...`
fn parse_snmp(text: &str) -> BTreeMap<String, BTreeMap<String, i64>> {
    let mut groups = BTreeMap::new();
    let mut lines = text.lines();
    while let (Some(names), Some(values)) = (lines.next(), lines.next()) {
        let (Some((group, names)), Some((value_group, values))) =
            (names.split_once(':'), values.split_once(':'))
        else {
            break;
        };
        if group != value_group {
            break;
        }
        let counters = names
            .split_whitespace()
            .zip(values.split_whitespace())
            .filter_map(|(name, value)| Some((name.to_string(), value.parse().ok()?)))
            .collect();
        groups.insert(group.to_string(), counters);
    }
    groups
}

/// Sums the drop and time squeeze columns (the second and third, hex) of
/// /proc/net/softnet_stat over all CPUs
fn parse_softnet(text: &str) -> Softnet {
    let mut softnet = Softnet::default();
    for line in text.lines() {
        let mut columns = line
            .split_whitespace()
            .map(|c| u64::from_str_radix(c, 16).unwrap_or(0));
        let _processed = columns.next();
        softnet.dropped += columns.next().unwrap_or(0);
        softnet.time_squeeze += columns.next().unwrap_or(0);
    }
    softnet
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Kernel {
    /// From uname; all fields None if it fails
    fn read() -> Kernel {
        let mut uts: libc::utsname = unsafe { mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } != 0 {
            return Kernel {
                release: None,
                version: None,
                machine: None,
            };
        }
        let field = |f: &[libc::c_char]| {
            let text = unsafe { CStr::from_ptr(f.as_ptr()) }.to_string_lossy();
            Some(text.into_owned())
        };
        Kernel {
            release: field(&uts.release),
            version: field(&uts.version),
            machine: field(&uts.machine),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_groups_pair_names_with_values() {
        let text = "Ip: Forwarding DefaultTTL\nIp: 1 64\n\
                    Tcp: RtoAlgorithm ActiveOpens CurrEstab\nTcp: 1 42 -3\n";
        let groups = parse_snmp(text);
        assert_eq!(groups["Ip"]["DefaultTTL"], 64);
        assert_eq!(groups["Tcp"]["ActiveOpens"], 42);
        assert_eq!(groups["Tcp"]["CurrEstab"], -3);
    }

    #[test]
    fn snmp_stops_at_mismatched_groups() {
        let groups = parse_snmp("Tcp: A B\nUdp: 1 2\nTcp: A\nTcp: 1\n");
        assert!(groups.is_empty());
    }

    #[test]
    fn softnet_sums_hex_columns() {
        let text = "0000a000 00000002 0000000f 00000000\n00000001 00000010 00000001 00000000\n";
        assert_eq!(
            parse_softnet(text),
            Softnet {
                dropped: 0x12,
                time_squeeze: 0x10
            }
        );
    }

    #[test]
    fn tc_qdiscs_keep_kind_handle_parent() {
        let json = br#"[{"kind":"mq","handle":"0:","root":true,"options":{}},
                        {"kind":"fq_codel","handle":"0:","parent":":1","options":{"limit":10240}}]"#;
        assert_eq!(
            parse_tc_qdiscs(json).unwrap(),
            vec![
                Qdisc {
                    kind: "mq".into(),
                    handle: Some("0:".into()),
                    parent: None
                },
                Qdisc {
                    kind: "fq_codel".into(),
                    handle: Some("0:".into()),
                    parent: Some(":1".into())
                },
            ]
        );
        assert!(parse_tc_qdiscs(b"not json").is_none());
    }

    #[test]
    fn clock_offsets_use_the_bracket_midpoint() {
        let sample = ClockSample::from_reads(1000, 5_000_000, 5_000_037, 1100, 1010);
        assert_eq!(sample.monotonic_ns, 1005);
        assert_eq!(sample.realtime_minus_monotonic_ns, 5_000_000 - 1005);
        assert_eq!(sample.tai_minus_monotonic_ns, 5_000_037 - 1005);
        assert_eq!(sample.boottime_minus_monotonic_ns, 95);
        assert_eq!(sample.uncertainty_ns, 10);
    }

    #[test]
    fn clock_sample_is_consistent() {
        let sample = ClockSample::take();
        assert!(sample.uncertainty_ns >= 0);
        assert!(sample.realtime_minus_monotonic_ns > 0);
        assert!(sample.boottime_minus_monotonic_ns >= 0);
    }

    #[test]
    fn ifreq_has_the_kernel_size() {
        assert_eq!(mem::size_of::<IfreqData>(), mem::size_of::<libc::ifreq>());
    }

    #[test]
    fn sysctl_whitespace_is_collapsed() {
        assert_eq!(
            collapse_whitespace("4096\t131072\t6291456"),
            "4096 131072 6291456"
        );
    }

    #[test]
    fn written_file_round_trips() {
        let dir = std::env::temp_dir().join(format!("tcbee-meta-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("metadata.json");
        let mut meta = RunMetadata::collect(Recorder {
            argv: vec!["tcbee-record".into(), "-k".into()],
            groups: vec!["kernel".into()],
            ..Recorder::default()
        });
        meta.write(&path).unwrap();
        let start: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(start["format"], FORMAT);
        assert_eq!(start["recorder"]["argv"][1], "-k");
        assert!(start["stop"].is_null());
        meta.finish(Some(vec![]));
        meta.write(&path).unwrap();
        let stop: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            stop["stop"]["clock"]["monotonic_ns"].as_i64().unwrap()
                >= start["start"]["clock"]["monotonic_ns"].as_i64().unwrap()
        );
        assert!(!path.with_extension("json.tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
