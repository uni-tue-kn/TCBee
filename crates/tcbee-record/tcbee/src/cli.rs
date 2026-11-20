//! Command line of tcbee-record: the flags, parsed into [`Args`].

use std::io::Write;

use argparse::{ArgumentParser, Store, StoreOption, StoreTrue};

/// The command line flags, as given (values are checked later in main).
#[derive(Debug, Clone, PartialEq)]
pub struct Args {
    pub iface: String,
    pub headers_at: String,
    pub yes: bool,
    pub dir: String,
    pub quiet: bool,
    pub port: u16,
    pub ports: String,
    pub src_ports: String,
    pub dst_ports: String,
    pub ips: String,
    pub src_ips: String,
    pub dst_ips: String,
    pub update_period: u128,
    pub observation_window: f64,
    pub trace_tracepoints: bool,
    pub trace_kernel: bool,
    pub trace_algorithms: bool,
    pub trace_cwnd: bool,
    pub trace_mptcp: bool,
    pub tp: String,
    pub mptcp_modes: String,
    pub cpus: u16,
    pub metrics: bool,
    pub metadata: bool,
    pub duration: f64,
    pub ringbuf_size: String,
    pub poll: String,
    pub writer_cpus: String,
    pub writer_placement: String,
    pub writer_sink: String,
    pub writer_format: String,
    pub writer_io_cpus: String,
    pub writer_no_prealloc: bool,
    pub writer_max_buffers: Option<usize>,
    pub on_change: String,
    pub on_change_hooks: String,
    pub on_change_shadow: bool,
    pub sock_hooks: String,
    pub sock_fields: String,
    pub no_owners: bool,
    pub no_hook_seq: bool,
    pub owners_no_cmdline: bool,
    pub version: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            iface: String::new(),
            headers_at: String::new(),
            yes: false,
            dir: "/tmp/".to_string(),
            quiet: false,
            port: 0,
            ports: String::new(),
            src_ports: String::new(),
            dst_ports: String::new(),
            ips: String::new(),
            src_ips: String::new(),
            dst_ips: String::new(),
            update_period: 100,
            observation_window: 0.0,
            trace_tracepoints: false,
            trace_kernel: false,
            trace_algorithms: false,
            trace_cwnd: false,
            trace_mptcp: false,
            tp: String::new(),
            mptcp_modes: String::new(),
            cpus: 1,
            metrics: false,
            metadata: false,
            duration: 0.0,
            ringbuf_size: String::new(),
            poll: "busy".to_string(),
            writer_cpus: String::new(),
            writer_placement: "balanced".to_string(),
            writer_sink: "mmap".to_string(),
            writer_format: "records".to_string(),
            writer_io_cpus: String::new(),
            writer_no_prealloc: false,
            writer_max_buffers: None,
            on_change: String::new(),
            on_change_hooks: String::new(),
            on_change_shadow: false,
            sock_hooks: String::new(),
            sock_fields: String::new(),
            no_owners: false,
            no_hook_seq: false,
            owners_no_cmdline: false,
            version: false,
        }
    }
}

/// Parses the command line (`argv[0]` is the program name). `Err` carries the exit code:
/// 0 after the help, 2 for a bad command line.
pub fn parse_args(
    argv: Vec<String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Args, i32> {
    let mut args = Args::default();
    {
        let mut argparser = ArgumentParser::new();
        argparser.set_description(
            "TCBee: A High-Performance and Extensible Tool For TCP Connection Analysis Using eBPF",
        );
        argparser.refer(&mut args.iface).add_option(
            &["-H", "--headers"],
            Store,
            "Record the TCP headers of received and sent packets on the specified interface, at TC by default, see --headers-at.",
        );
        argparser.refer(&mut args.headers_at).add_option(
            &["--headers-at"],
            Store,
            "Where -H records the headers: tc (default) = TC ingress and egress, the packets as the stack sees them (after GRO, before GSO); driver = native XDP for received packets, before GRO, and net_dev_start_xmit for sent ones, after the qdisc and software GSO (tcp*_driver_*.tcp). driver needs a NIC driver with native XDP and LRO and rx-gro-hw off. tc,driver records both, into separate files, to compare a packet at the two hooks (qdisc and pacing delay); it asks for confirmation.",
        );
        argparser.refer(&mut args.yes).add_option(
            &["--yes"],
            StoreTrue,
            "Do not ask for confirmation (--headers-at tc,driver), for scripts.",
        );
        argparser.refer(&mut args.dir).add_option(
            &["-o", "--output"],
            Store,
            "Directory to store recording results in. Defaults to /tmp/",
        );
        argparser.refer(&mut args.port).add_option(
            &["--port"],
            Store,
            "Fast single-port filter for a remote or local port. Other filter flags switch to the map-backed filter.",
        );
        argparser.refer(&mut args.ports).add_option(
            &["--ports"],
            Store,
            "Comma-separated remote or local ports to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut args.src_ports).add_option(
            &["--src-ports"],
            Store,
            "Comma-separated source ports to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut args.dst_ports).add_option(
            &["--dst-ports"],
            Store,
            "Comma-separated destination ports to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut args.ips).add_option(
            &["--ips"],
            Store,
            "Comma-separated remote or local IPv4/IPv6 addresses to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut args.src_ips).add_option(
            &["--src-ips"],
            Store,
            "Comma-separated source IPv4/IPv6 addresses to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut args.dst_ips).add_option(
            &["--dst-ips"],
            Store,
            "Comma-separated destination IPv4/IPv6 addresses to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut args.update_period).add_option(
            &["--tui-update-ms"],
            Store,
            "Miliseconds between each TUI update. Default is 100ms, higher values may help with tearing.",
        );
        argparser.refer(&mut args.observation_window).add_option(
            &["--tui-observation-window-s"],
            Store,
            "Time window of the TUI charts at the start, in seconds, rounded up to 10 s, 30 s, 1, 2, 5, 10 or 30 min (less with --tui-update-ms below 50). 0 starts with the whole recording. In the TUI, w switches between the window and the whole recording, + and - change the window. Default is 0.",
        );
        argparser.refer(&mut args.cpus).add_option(
            &["-c", "--cpus"],
            Store,
            "Number of CPUs to run TCBee on. One CPU should always be enough as the probes seem to be the bottleneck, will run at 100% load due to polling from eBPF maps.",
        );
        argparser.refer(&mut args.quiet).add_option(
            &["-q", "--quiet"],
            StoreTrue,
            "Disable terminal UI. Will still display some information.",
        );
        argparser.refer(&mut args.trace_cwnd).add_option(
            &["-w", "--cwnd"],
            StoreTrue,
            "Record send_cwnd from kernel function calls only. Testing mode for performance evaluation.",
        );
        argparser.refer(&mut args.trace_tracepoints).add_option(
            &["-t", "--tracepoints"],
            StoreTrue,
            "Record the TCP tracepoints: tcp_probe (main TCP metrics at every received segment), SYN-ACK retransmissions, bad checksums, and as TCP events (tcp_events.tcp) retransmissions, RSTs sent and received, state and congestion state changes, retransmission timeouts and destroyed sockets. See --tp.",
        );
        argparser.refer(&mut args.tp).add_option(
            &["--tp"],
            Store,
            "Tracepoints to record, comma-separated; implies -t. Names: probe, synack, bad_csum, retransmit, rst_sent, rst_received, state, ca_state, rto, destroy, and drops (kfree_skb: packets of TCP flows the kernel drops, with the reason; not in the default). 'all' and 'default' name the sets. +name and -name items add to or remove from the plain names, or from the default set in a list without plain names, e.g. +drops,-probe or all,-probe. _ and - are the same in names.",
        );
        argparser.refer(&mut args.trace_kernel).add_option(
            &["-k", "--kernel"],
            StoreTrue,
            "Record the socket (all TCP metrics) at the hooks of --sock-hooks: by default after every run of the write timer and at TCP events (state and congestion state changes, retransmissions, cwnd restarts, receive buffer growth), none per packet. Add +ingress for the state after every received segment.",
        );
        argparser.refer(&mut args.metrics).add_option(
            &["--metrics"],
            StoreTrue,
            "Write per ring buffer event counters, records written and per program recursion misses to metrics.json in the recording directory after shutdown.",
        );
        argparser.refer(&mut args.metadata).add_option(
            &["--metadata"],
            StoreTrue,
            "Write run metadata to metadata.json in the recording directory: host, kernel, TCP sysctls, interfaces with offloads and qdiscs, the command line, clock offsets and drop counters at start and stop.",
        );
        argparser.refer(&mut args.duration).add_option(
            &["--duration"],
            Store,
            "Stop recording after this many seconds. Use 0 to record until stopped. Default is 0.",
        );
        argparser.refer(&mut args.poll).add_option(
            &["--poll"],
            Store,
            "How writer threads wait for records: 'busy' polls the rings and sleeps when they are idle (50 µs per thread per file; with --writer-cpus spins, then sleeps 1 µs growing to 100 µs), 'wait' blocks until the kernel signals new records. Default is busy.",
        );
        argparser.refer(&mut args.writer_cpus).add_option(
            &["--writer-cpus"],
            Store,
            "Comma-separated CPU ids for the writer threads: one thread per CPU drains the rings it gets by hook, each pair of per-packet hooks (ingress and egress) on a CPU of its own where possible and the rare hooks' rings together. Without, one unpinned thread runs per output file.",
        );
        argparser.refer(&mut args.writer_placement).add_option(
            &["--writer-placement"],
            Store,
            "Where file helpers run on the --writer-cpus: 'balanced' runs file growth on the least loaded writer CPU, 'round-robin' on the writer CPUs without a writer thread (all if none is free). Writer threads do not move. Default is balanced.",
        );
        argparser.refer(&mut args.writer_sink).add_option(
            &["--writer-sink"],
            Store,
            "How writers write the trace files: 'mmap' maps them, 'direct' copies records into large buffers that I/O threads write with O_DIRECT, 'uring' submits those writes to an io_uring, 'buffered' writes the buffers through the page cache and pushes them to the disk at once, 'sync' writes two 256 KiB buffers itself through the page cache, without I/O threads, and pushes the pages to the disk every 8 MiB. The file bytes are the same. Default is mmap.",
        );
        argparser.refer(&mut args.writer_format).add_option(
            &["--writer-format"],
            Store,
            "How records get into the trace files: 'records' hands each record to the writer, which packs it and appends a delimiter, 'raw' copies the ring buffers' committed bytes in spans of up to 64 KiB, each record with its ring buffer header and padding. tcbee-process reads both. Default is records.",
        );
        argparser.refer(&mut args.writer_io_cpus).add_option(
            &["--writer-io-cpus"],
            Store,
            "Comma-separated CPU ids for the I/O threads (or io_uring workers) of the direct, uring and buffered sinks. By default they run on the --writer-cpus like the file growth helpers.",
        );
        argparser.refer(&mut args.writer_no_prealloc).add_option(
            &["--writer-no-prealloc"],
            StoreTrue,
            "With the direct and uring sinks, do not allocate the trace files ahead of the writes. Allocating takes the file's lock and, on tmpfs, zeroes the memory, which the writes then wait for.",
        );
        argparser.refer(&mut args.writer_max_buffers).add_option(
            &["--writer-max-buffers"],
            StoreOption,
            "With the direct and buffered sinks, how many 2 MiB buffers a trace file may hold while the disk is slow, instead of the writer waiting for it. Default 256 (512 MiB); quiet files keep 8.",
        );
        argparser.refer(&mut args.ringbuf_size).add_option(
            &["--ringbuf-size"],
            Store,
            "Size of each CPU's ring buffer in bytes (K, M, G suffixes), rounded up to a power of two. Every probe output has one ring buffer per CPU. Either one size for all buffers, per group as tcp4=64M,sock=32M, or both. Groups: tcp4, tcp6, sock, sock_timer, sock_event, cwnd, tcp_probe, synack, bad_csum, cubic, bbr, reno, mptcp_pm, tcp_events, owners.",
        );
        argparser.refer(&mut args.on_change).add_option(
            &["--on-change"],
            Store,
            "Write sock (-k) and cwnd (-w) records only when a watched field or the socket state changed, into *_oc.tcp files with a manifest.json. 'cc' watches snd_cwnd, snd_ssthresh, total_retrans, backoff, rto, reordering and rcv_mss, 'rcv' (for a receiver) rcv_mss, rcv_space, rcv_ssthresh and rcv_rtt; or give a comma-separated list of sock_trace_entry fields. The cwnd probe watches snd_cwnd. Each probe compares with the last record of the connection, whichever hook wrote it.",
        );
        argparser.refer(&mut args.on_change_hooks).add_option(
            &["--on-change-hooks"],
            Store,
            "With --on-change: comma-separated kernel hooks to compare at. ingress = after each received segment (fexit/tcp_rcv_established and tcp_rcv_state_process), timer = after each retransmission, loss probe, RACK reordering or zero window probe timer (fexit/tcp_write_timer_handler), both into the recv_*_oc.tcp files; egress = before each transmitted segment (fentry/__tcp_transmit_skb), into send_*_oc.tcp, one probe run per segment. Default: ingress,timer. The list works as in --tp, e.g. +egress. In sock records, bits 8-15 of ato tell the hook (1 ingress, 2 timer, 3 egress).",
        );
        argparser.refer(&mut args.on_change_shadow).add_option(
            &["--on-change-shadow"],
            StoreTrue,
            "With --on-change and -k: write every sock run anyway, with the decision as a reason code in bits 0-7 of the ato field (1 suppressed, 2 changed, 3 first or after a drop, 4 state change, 5 no socket storage).",
        );
        argparser.refer(&mut args.sock_hooks).add_option(
            &["--sock-hooks"],
            Store,
            "Comma-separated kernel hooks at which -k records the socket. Per packet: ingress = after each received segment (fexit/tcp_rcv_established and tcp_rcv_state_process, ingress_sock.tcp), egress = before each transmitted segment (fentry/__tcp_transmit_skb, send_sock.tcp), ingress-entry = before each received segment in ESTABLISHED (fentry/tcp_rcv_established, recv_sock.tcp). Not per packet: timer = after each write timer run (fexit/tcp_write_timer_handler, timer_sock.tcp); state, ca-state, retransmit, restart, rcvbuf = at TCP state and congestion state changes, retransmissions, cwnd restarts after idle and receive buffer growth (event_sock.tcp). Default: the ones not per packet. The list works as in --tp (all, default, +name, -name), e.g. +ingress on a sender. With --on-change and -k it is the same as --on-change-hooks (with -w alone, use --on-change-hooks).",
        );
        argparser.refer(&mut args.sock_fields).add_option(
            &["--sock-fields"],
            Store,
            "With -k at the hooks egress, ingress-entry and timer (give them with --sock-hooks): record only these groups of socket fields, into *_sock_sel.tcp files with a manifest.json. Smaller records let more of them through the writer and the disk without loss. Groups: pacing, icsk, cwnd, cc (the rest of the congestion and loss state), rcv, rtt, delivery, chrono, seq, sndbuf. The header, ato and conn_id are always recorded. The list works as in --tp, e.g. cwnd,rtt or all,-chrono.",
        );
        argparser.refer(&mut args.no_hook_seq).add_option(
            &["--no-hook-seq"],
            StoreTrue,
            "Disable per-flow hook sequence numbers (enabled by default). Records carry hook_seq=0: exact cross-CPU hook ordering and gap-based loss accounting are unavailable. Aggregate drop counters remain. TCP event hooks retain tuple membership filtering. Writes metadata.json to identify this mode.",
        );
        argparser.refer(&mut args.no_owners).add_option(
            &["--no-owners"],
            StoreTrue,
            "Do not record the process that opens each connection. By default every recording writes flow_owners.tcp, one record per connect and accept with the process id, uid, name and cgroup, and flow_owners.json with the connections that existed at the start and their processes (as netstat -p finds them), and the command lines of the processes. The filter flags apply to both. Process names and command lines end up in the recording, and command lines may hold secrets (tokens, passwords in URLs); --owners-no-cmdline leaves them out. The pids are those of the host's pid namespace.",
        );
        argparser.refer(&mut args.owners_no_cmdline).add_option(
            &["--owners-no-cmdline"],
            StoreTrue,
            "Record the owners without the command lines of their processes: process id, uid, name (15 characters) and cgroup only, nothing read from /proc/<pid>/cmdline. For recordings that are shared.",
        );
        argparser.refer(&mut args.trace_algorithms).add_option(
            &["-a", "--algorithms"],
            StoreTrue,
            "Record the internals of the congestion control algorithms: CUBIC and BBR state, and Reno's congestion avoidance (also where DCTCP and others reuse it).",
        );
        argparser.refer(&mut args.trace_mptcp).add_option(
            &["-m", "--mptcp"],
            StoreTrue,
            "Record MPTCP: path manager and connection lifecycle events, stale subflows, sent MP_PRIO, data-level reinjections and the fallback to TCP in the handshake, and with -k or -w the token of its MPTCP connection in the records of each subflow.",
        );
        argparser.refer(&mut args.mptcp_modes).add_option(
            &["--mptcp-modes"],
            Store,
            "What -m records, comma-separated: tag (needs -k or -w), pm. Implies -m. Default is pm, plus tag with -k or -w.",
        );

        argparser.refer(&mut args.version).add_option(
            &["-V", "--version"],
            StoreTrue,
            "Print the version and exit.",
        );

        // Without any argument there is nothing to record, so show what can be recorded
        if argv.len() <= 1 {
            // A closed pipe (| head) is no error
            let _ = argparser.print_help("tcbee-record", out);
            return Err(0);
        }
        argparser.parse(argv, out, err)?;
    }
    if args.version {
        let _ = writeln!(out, "{}", version_string());
        return Err(0);
    }
    Ok(args)
}

/// `tcbee-record <version> (<git sha>)`; the sha is set by the CI and release builds.
pub fn version_string() -> String {
    format!(
        "tcbee-record {} ({})",
        env!("CARGO_PKG_VERSION"),
        option_env!("TCBEE_GIT_SHA").unwrap_or("unknown")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> (Result<Args, i32>, String, String) {
        let argv = std::iter::once("tcbee-record")
            .chain(argv.iter().copied())
            .map(String::from)
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = parse_args(argv, &mut out, &mut err);
        (
            result,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn no_arguments_print_the_help() {
        let (result, out, _) = parse(&[]);
        assert_eq!(result, Err(0));
        assert!(out.contains("--sock-hooks"), "{out}");
    }

    #[test]
    fn flags_land_in_their_fields() {
        let (result, _, _) = parse(&["-k", "--ports", "5201,5202", "--duration", "2.5"]);
        let args = result.unwrap();
        assert!(args.trace_kernel);
        assert_eq!(args.ports, "5201,5202");
        assert_eq!(args.duration, 2.5);
        assert_eq!(args.dir, "/tmp/");
    }

    #[test]
    fn unknown_flags_are_rejected() {
        let (result, _, err) = parse(&["--no-such-flag"]);
        assert_eq!(result, Err(2));
        assert!(err.contains("--no-such-flag"), "{err}");
    }

    #[test]
    fn renamed_flags_parse() {
        let (result, _, _) = parse(&["-H", "eth0", "-o", "/data", "--port", "443", "-m"]);
        let args = result.unwrap();
        assert_eq!(args.iface, "eth0");
        assert_eq!(args.dir, "/data");
        assert_eq!(args.port, 443);
        assert!(args.trace_mptcp);
    }

    #[test]
    fn removed_flags_are_rejected() {
        for flag in [
            &["-h", "eth0"][..],
            &["-d", "/data"],
            &["--dir", "/data"],
            &["-p", "443"],
            &["-e"],
            &["--events"],
            &["--drops"],
            &["--no-timer-hook"],
            &["-M"],
        ] {
            let (result, _, _) = parse(flag);
            assert!(result.is_err(), "{flag:?}");
        }
    }

    #[test]
    fn help_lists_h_once() {
        let (result, out, _) = parse(&["--help"]);
        assert_eq!(result, Err(0));
        assert_eq!(out.matches("-h,").count(), 1, "{out}");
        assert!(out.contains("-H,--headers"), "{out}");
    }

    #[test]
    fn version_is_printed() {
        let (result, out, _) = parse(&["-V"]);
        assert_eq!(result, Err(0));
        assert_eq!(out.trim(), version_string());
        assert!(out.starts_with(&format!("tcbee-record {} (", env!("CARGO_PKG_VERSION"))));
    }
}
