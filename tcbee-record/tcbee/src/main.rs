// Crate components
mod config;
mod eBPF;
mod metadata;
mod metrics;
mod stats;
mod viz;
mod writer;
use std::net::IpAddr;

use anyhow::anyhow;
use eBPF::ebpf_runner::EbpfRunner;
use eBPF::ebpf_runner_config::{
    check_no_timer_hook, ip_to_filter_addr, on_change_manifest, parse_on_change,
    parse_ringbuf_sizes, tracepoint_set, EbpfRunnerConfig, FilterConfig, MptcpModes,
};
use tcbee_trace::TCBeeTrace;
use writer::PollMode;

// Error handling
use log::info;

// Async Libraries
use std::time::Duration;
use tokio::{
    runtime::Builder,
    signal::unix::{signal, SignalKind},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

// Commandline arguments
use argparse::{ArgumentParser, Store, StoreTrue};

fn parse_csv<T>(arg: &str, name: &str) -> anyhow::Result<Vec<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    if arg.trim().is_empty() {
        return Ok(Vec::new());
    }

    arg.split(',')
        .map(|value| {
            value
                .trim()
                .parse::<T>()
                .map_err(|err| anyhow!("Invalid {} '{}': {}", name, value, err))
        })
        .collect()
}

fn parse_ip_csv(arg: &str, name: &str) -> anyhow::Result<Vec<[u8; 16]>> {
    parse_csv::<IpAddr>(arg, name).map(|ips| ips.into_iter().map(ip_to_filter_addr).collect())
}

fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let mut iface: String = String::new();
    let mut dir: String = "/tmp/".to_string();
    let mut quiet: bool = false;
    let mut port: u16 = 0;
    let mut ports: String = String::new();
    let mut src_ports: String = String::new();
    let mut dst_ports: String = String::new();
    let mut ips: String = String::new();
    let mut src_ips: String = String::new();
    let mut dst_ips: String = String::new();
    let mut update_period: u128 = 100;
    let mut observation_window: f64 = 0.0;
    let mut trace_tracepoints: bool = false;
    let mut trace_kernel: bool = false;
    let mut trace_algorithms: bool = false;
    let mut trace_cwnd: bool = false;
    let mut trace_mptcp: bool = false;
    let mut trace_events: bool = false;
    let mut trace_drops: bool = false;
    let mut tp: String = String::new();
    let mut mptcp_modes: String = String::new();
    let mut cpus: u16 = 1;
    let mut metrics: bool = false;
    let mut metadata: bool = false;
    let mut duration: f64 = 0.0;
    let mut ringbuf_size: String = String::new();
    let mut poll: String = "busy".to_string();
    let mut writer_cpus: String = String::new();
    let mut on_change: String = String::new();
    let mut on_change_hooks: String = String::new();
    let mut on_change_shadow: bool = false;
    let mut no_timer_hook: bool = false;

    {
        let mut argparser = ArgumentParser::new();
        argparser.set_description(
            "TCBee: A High-Performance and Extensible Tool For TCP Connection Analysis Using eBPF",
        );
        argparser.refer(&mut iface).add_option(
            &["-h", "--headers"],
            Store,
            "Record TCP headers of incoming and outgoing packets on the specified interface.",
        );
        argparser.refer(&mut dir).add_option(
            &["-d", "--dir"],
            Store,
            "Directory to store recording results in. Defaults to /tmp/",
        );
        argparser.refer(&mut port).add_option(
            &["-p", "--port"],
            Store,
            "Fast single-port filter for remote or local port.",
        );
        argparser.refer(&mut ports).add_option(
            &["--ports"],
            Store,
            "Comma-separated remote or local ports to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut src_ports).add_option(
            &["--src-ports"],
            Store,
            "Comma-separated source ports to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut dst_ports).add_option(
            &["--dst-ports"],
            Store,
            "Comma-separated destination ports to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut ips).add_option(
            &["--ips"],
            Store,
            "Comma-separated remote or local IPv4/IPv6 addresses to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut src_ips).add_option(
            &["--src-ips"],
            Store,
            "Comma-separated source IPv4/IPv6 addresses to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut dst_ips).add_option(
            &["--dst-ips"],
            Store,
            "Comma-separated destination IPv4/IPv6 addresses to record. Enables map-backed filtering.",
        );
        argparser.refer(&mut update_period).add_option(
            &["--tui-update-ms"],
            Store,
            "Miliseconds between each TUI update. Default is 100ms, higher values may help with tearing.",
        );
        argparser.refer(&mut observation_window).add_option(
            &["--tui-observation-window-s"],
            Store,
            "Sliding TUI graph observation window in seconds. Use 0 for the full recording. Default is 0.",
        );
        argparser.refer(&mut cpus).add_option(
            &["-c", "--cpus"],
            Store,
            "Number of CPUs to run TCBee on. One CPU should always be enough as the probes seem to be the bottleneck, will run at 100% load due to polling from eBPF maps.",
        );
        argparser.refer(&mut quiet).add_option(
            &["-q", "--quiet"],
            StoreTrue,
            "Disable terminal UI. Will still display some information.",
        );
        argparser.refer(&mut trace_cwnd).add_option(
            &["-w", "--cwnd"],
            StoreTrue,
            "Record send_cwnd from kernel function calls only. Testing mode for performance evaluation.",
        );
        // --headers now takes the interface name as its argument
        argparser.refer(&mut trace_tracepoints).add_option(
            &["-t", "--tracepoints"],
            StoreTrue,
            "Record the TCP tracepoints: tcp_probe (main TCP metrics at every received segment), SYN-ACK retransmissions, bad checksums, and as TCP events (tcp_events.tcp) retransmissions, RSTs sent and received, state and congestion state changes, retransmission timeouts and destroyed sockets. See --tp.",
        );
        argparser.refer(&mut tp).add_option(
            &["--tp"],
            Store,
            "Tracepoints to record, comma-separated; implies -t. Names: probe, synack, bad_csum, retransmit, rst_sent, rst_received, state, ca_state, rto, destroy, and drops (kfree_skb: packets of TCP flows the kernel drops, with the reason; not in the default). 'all' and 'default' name the sets. A list of only +name and -name items changes the default set, e.g. +drops,-probe.",
        );
        argparser.refer(&mut trace_kernel).add_option(
            &["-k", "--kernel"],
            StoreTrue,
            "Record the socket (all TCP metrics) at every transmitted (__tcp_transmit_skb) and received (tcp_rcv_established) segment, and after every run of the write timer (tcp_write_timer_handler, see --no-timer-hook).",
        );
        argparser.refer(&mut metrics).add_option(
            &["--metrics"],
            StoreTrue,
            "Write per ring buffer event counters, records written and per program recursion misses to metrics.json in the recording directory after shutdown.",
        );
        argparser.refer(&mut metadata).add_option(
            &["--metadata"],
            StoreTrue,
            "Write run metadata to metadata.json in the recording directory: host, kernel, TCP sysctls, interfaces with offloads and qdiscs, the command line, clock offsets and drop counters at start and stop.",
        );
        argparser.refer(&mut duration).add_option(
            &["--duration"],
            Store,
            "Stop recording after this many seconds. Use 0 to record until stopped. Default is 0.",
        );
        argparser.refer(&mut poll).add_option(
            &["--poll"],
            Store,
            "How writer threads wait for records: 'busy' polls the rings and sleeps 50 µs when a poll returns fewer than 256 records, 'wait' blocks until the kernel signals new records. Default is busy.",
        );
        argparser.refer(&mut writer_cpus).add_option(
            &["--writer-cpus"],
            Store,
            "Comma-separated CPU ids to pin the writer threads to, assigned round-robin. One thread runs per output file.",
        );
        argparser.refer(&mut ringbuf_size).add_option(
            &["--ringbuf-size"],
            Store,
            "Size of each CPU's ring buffer in bytes (K, M, G suffixes), rounded up to a power of two. Every probe output has one ring buffer per CPU. Either one size for all buffers, per group as tcp4=64M,sock=32M, or both. Groups: tcp4, tcp6, sock, sock_timer, cwnd, tcp_probe, synack, bad_csum, cubic, bbr, mptcp_pm, tcp_events.",
        );
        argparser.refer(&mut on_change).add_option(
            &["--on-change"],
            Store,
            "Write sock (-k) and cwnd (-w) records only when a watched field or the socket state changed, into *_oc.tcp files with a manifest.json. 'cc' watches snd_cwnd, snd_ssthresh, total_retrans, backoff, rto, reordering and rcv_mss, 'rcv' (for a receiver) rcv_mss, rcv_space, rcv_ssthresh and rcv_rtt; or give a comma-separated list of sock_trace_entry fields. The cwnd probe watches snd_cwnd. Each probe compares with the last record of the connection, whichever hook wrote it.",
        );
        argparser.refer(&mut on_change_hooks).add_option(
            &["--on-change-hooks"],
            Store,
            "With --on-change: comma-separated kernel hooks to compare at. ingress = after each received segment (fexit/tcp_rcv_established and tcp_rcv_state_process), timer = after each retransmission, loss probe, RACK reordering or zero window probe timer (fexit/tcp_write_timer_handler), both into the recv_*_oc.tcp files; egress = before each transmitted segment (fentry/__tcp_transmit_skb), into send_*_oc.tcp, one probe run per segment. Default: ingress,timer. In sock records, bits 8-15 of ato tell the hook (1 ingress, 2 timer, 3 egress).",
        );
        argparser.refer(&mut on_change_shadow).add_option(
            &["--on-change-shadow"],
            StoreTrue,
            "With --on-change and -k: write every sock run anyway, with the decision as a reason code in bits 0-7 of the ato field (1 suppressed, 2 changed, 3 first or after a drop, 4 state change, 5 no socket storage).",
        );
        argparser.refer(&mut no_timer_hook).add_option(
            &["--no-timer-hook"],
            StoreTrue,
            "With -k: do not record the socket after each run of the write timer (timer_sock.tcp).",
        );
        argparser.refer(&mut trace_algorithms).add_option(
            &["-a", "--algorithms"],
            StoreTrue,
            "Record behaviour of congestion algorithms: Cubic and BBR.",
        );
        argparser.refer(&mut trace_events).add_option(
            &["-e", "--events"],
            StoreTrue,
            "Record only the TCP events of -t. Kept for old command lines.",
        );
        argparser.refer(&mut trace_drops).add_option(
            &["--drops"],
            StoreTrue,
            "Record the TCP events of -t and the packets of TCP flows that the kernel drops (kfree_skb). Kept for old command lines, use --tp +drops.",
        );
        argparser.refer(&mut trace_mptcp).add_option(
            &["-m", "-M", "--mptcp"],
            StoreTrue,
            "Record MPTCP: path manager and connection lifecycle events, stale subflows, sent MP_PRIO, data-level reinjections and the fallback to TCP in the handshake, and with -k or -w the token of its MPTCP connection in the records of each subflow.",
        );
        argparser.refer(&mut mptcp_modes).add_option(
            &["--mptcp-modes"],
            Store,
            "What -m records, comma-separated: tag (needs -k or -w), pm. Implies -m. Default is pm, plus tag with -k or -w.",
        );

        // Will try to parse arguments or exit program on error!
        argparser.parse_args_or_exit();
    }

    let trace_headers = !iface.is_empty();
    let tracepoints = tracepoint_set(trace_tracepoints, &tp, trace_events, trace_drops)?;
    let filter = FilterConfig {
        single_port: port,
        any_ports: parse_csv(&ports, "port")?,
        src_ports: parse_csv(&src_ports, "source port")?,
        dst_ports: parse_csv(&dst_ports, "destination port")?,
        any_ips: parse_ip_csv(&ips, "IP address")?,
        src_ips: parse_ip_csv(&src_ips, "source IP address")?,
        dst_ips: parse_ip_csv(&dst_ips, "destination IP address")?,
    };

    let ringbuf_sizes = parse_ringbuf_sizes(&ringbuf_size)?;
    let writer_cpus: Vec<usize> = parse_csv(&writer_cpus, "CPU id")?;
    if let Some(cpu) = writer_cpus
        .iter()
        .find(|cpu| **cpu >= libc::CPU_SETSIZE as usize)
    {
        return Err(anyhow!("Invalid writer CPU id {}", cpu));
    }
    let poll_mode = match poll.as_str() {
        "busy" => PollMode::Busy,
        "wait" => PollMode::Wait,
        other => return Err(anyhow!("Unknown --poll mode '{}', use busy or wait", other)),
    };

    let mptcp = if !mptcp_modes.is_empty() {
        MptcpModes::parse(&mptcp_modes)?
    } else if trace_mptcp {
        MptcpModes::default_for(trace_kernel || trace_cwnd)
    } else {
        MptcpModes::default()
    };
    if mptcp.tag && !trace_kernel && !trace_cwnd {
        return Err(anyhow!(
            "MPTCP tagging needs -k or -w, it tags their records"
        ));
    }

    let duration = Duration::try_from_secs_f64(duration)
        .map_err(|_| anyhow!("--duration must be a non-negative number of seconds"))?;

    if !trace_headers
        && tracepoints.is_empty()
        && !trace_kernel
        && !trace_cwnd
        && !trace_algorithms
        && !mptcp.pm
    {
        return Err(anyhow!("No metrics to trace selected, stopping!"));
    }
    let on_change = parse_on_change(
        &on_change,
        &on_change_hooks,
        on_change_shadow,
        trace_kernel,
        trace_cwnd,
    )?;
    check_no_timer_hook(no_timer_hook, trace_kernel, on_change.is_some())?;

    // Create a timestamped recording directory inside the requested base dir
    let trace = TCBeeTrace::create(&dir)
        .map_err(|e| anyhow!("Failed to create trace directory in {}: {}", dir, e))?;
    let trace_dir = trace.dir().to_string_lossy().into_owned();

    // Greet user if running without TUI
    if quiet {
        println!("Running TCBee without terminal UI, Ctrl+c to stop recording!");
        println!("Recording to: {}", trace_dir);
        println!("------------------------------------------------------------");
    }

    // Cancellation token to signal stopping to child threads
    let token = CancellationToken::new();

    let config = EbpfRunnerConfig::new()
        .filter(filter)
        .tui(!quiet)
        .update_period(update_period)
        .observation_window(observation_window)
        .headers(trace_headers)
        .tracepoints(tracepoints)
        .kernel(trace_kernel)
        .interface(iface)
        .cwnd(trace_cwnd)
        .metrics(metrics)
        .metadata(metadata)
        .algorithms(trace_algorithms)
        .mptcp(mptcp)
        .ringbuf_sizes(ringbuf_sizes)
        .poll_mode(poll_mode)
        .writer_cpus(writer_cpus.clone())
        .on_change(on_change)
        .no_timer_hook(no_timer_hook)
        .dir(trace_dir);

    // Main thread that strats all probes/tracepoints
    // If these calls fail, stop program!
    let mut runner = EbpfRunner::new(token.clone(), config);

    let runtime = Builder::new_multi_thread()
        .worker_threads(cpus as usize)
        .thread_name("TCBee")
        .on_thread_start(move || avoid_cpus(&writer_cpus))
        .enable_all()
        .build()?;

    runtime.block_on(async {
        // Install the handlers before starting so that a signal during startup still
        // stops the recorder cleanly instead of killing it
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        // The manifest only once the probes run, so a failed start leaves no on-change
        // directory without trace files
        let starting_result = runner.run().await.and_then(|()| {
            if let Some(on_change) = on_change {
                on_change_manifest(on_change, trace_kernel, trace_cwnd)
                    .write(trace.dir())
                    .map_err(|e| format!("Failed to write the on-change manifest: {e}"))?;
            }
            Ok(())
        });

        if let Err(err) = starting_result {
            // On start failure, wait until everythin has stopped
            let err = anyhow!("Failed to start eBPF runner {}", err);
            runner.stop().await;
            Err(err)
        } else {
            // Runner was created and correctly initialized
            // Stop on SIGINT (ctrl+c in quiet mode, the TUI handles keys itself), SIGTERM,
            // after --duration or when the TUI cancels the token
            let timeout = async {
                if duration.is_zero() {
                    std::future::pending().await
                } else {
                    sleep(duration).await
                }
            };
            tokio::select! {
                _ = token.cancelled() => {}
                _ = sigterm.recv() => {}
                _ = sigint.recv() => {}
                _ = timeout => {}
            }
            token.cancel();

            info!("Stopping eBPF runner and threads!");

            // waits for all child threads to finish
            runner.stop().await;

            info!("Stopped gracefully!");
            Ok(())
        }
    })
}

/// Keeps the calling thread off the CPUs the writer threads are pinned to, so that the
/// control and UI threads don't take time from a busy writer. Does nothing if no
/// writer CPUs are set or they cover every CPU.
fn avoid_cpus(writer_cpus: &[usize]) {
    if writer_cpus.is_empty() {
        return;
    }
    unsafe {
        let mut current: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut current) != 0 {
            return;
        }
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        let mut any = false;
        for cpu in 0..libc::CPU_SETSIZE as usize {
            if libc::CPU_ISSET(cpu, &current) && !writer_cpus.contains(&cpu) {
                libc::CPU_SET(cpu, &mut set);
                any = true;
            }
        }
        if any {
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        }
    }
}
