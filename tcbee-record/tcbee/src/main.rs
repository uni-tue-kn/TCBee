// Crate components
mod config;
mod eBPF;
mod metadata;
mod metrics;
mod stats;
mod viz;
mod writer;
use std::{
    io::{self, BufRead, IsTerminal, Write},
    net::IpAddr,
};

use anyhow::anyhow;
use eBPF::ebpf_runner::EbpfRunner;
use eBPF::ebpf_runner_config::{
    ip_to_filter_addr, on_change_manifest, parse_ringbuf_sizes, tracepoint_set, EbpfRunnerConfig,
    FilterConfig, HookFlags, MptcpModes,
};
use eBPF::probes::headers::{check_offloads, HeadersAt};
use metadata::Offloads;
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
    let mut headers_at: String = String::new();
    let mut yes: bool = false;
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
    let mut sock_hooks: String = String::new();

    {
        let mut argparser = ArgumentParser::new();
        argparser.set_description(
            "TCBee: A High-Performance and Extensible Tool For TCP Connection Analysis Using eBPF",
        );
        argparser.refer(&mut iface).add_option(
            &["-h", "--headers"],
            Store,
            "Record the TCP headers of received and sent packets on the specified interface, at TC by default, see --headers-at.",
        );
        argparser.refer(&mut headers_at).add_option(
            &["--headers-at"],
            Store,
            "Where -h records the headers: tc (default) = TC ingress and egress, the packets as the stack sees them (after GRO, before GSO); driver = native XDP for received packets, before GRO, and net_dev_start_xmit for sent ones, after the qdisc and software GSO (tcp*_driver_*.tcp). driver needs a NIC driver with native XDP and LRO and rx-gro-hw off. tc,driver records both, into separate files, to compare a packet at the two hooks (qdisc and pacing delay); it asks for confirmation.",
        );
        argparser.refer(&mut yes).add_option(
            &["--yes"],
            StoreTrue,
            "Do not ask for confirmation (--headers-at tc,driver), for scripts.",
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
            "Tracepoints to record, comma-separated; implies -t. Names: probe, synack, bad_csum, retransmit, rst_sent, rst_received, state, ca_state, rto, destroy, and drops (kfree_skb: packets of TCP flows the kernel drops, with the reason; not in the default). 'all' and 'default' name the sets. +name and -name items add to or remove from the plain names, or from the default set in a list without plain names, e.g. +drops,-probe or all,-probe. _ and - are the same in names.",
        );
        argparser.refer(&mut trace_kernel).add_option(
            &["-k", "--kernel"],
            StoreTrue,
            "Record the socket (all TCP metrics) at the hooks of --sock-hooks: by default after every run of the write timer and at TCP events (state and congestion state changes, retransmissions, cwnd restarts, receive buffer growth), none per packet. Add +ingress for the state after every received segment.",
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
            "Size of each CPU's ring buffer in bytes (K, M, G suffixes), rounded up to a power of two. Every probe output has one ring buffer per CPU. Either one size for all buffers, per group as tcp4=64M,sock=32M, or both. Groups: tcp4, tcp6, sock, sock_timer, sock_event, cwnd, tcp_probe, synack, bad_csum, cubic, bbr, reno, mptcp_pm, tcp_events, owners.",
        );
        argparser.refer(&mut on_change).add_option(
            &["--on-change"],
            Store,
            "Write sock (-k) and cwnd (-w) records only when a watched field or the socket state changed, into *_oc.tcp files with a manifest.json. 'cc' watches snd_cwnd, snd_ssthresh, total_retrans, backoff, rto, reordering and rcv_mss, 'rcv' (for a receiver) rcv_mss, rcv_space, rcv_ssthresh and rcv_rtt; or give a comma-separated list of sock_trace_entry fields. The cwnd probe watches snd_cwnd. Each probe compares with the last record of the connection, whichever hook wrote it.",
        );
        argparser.refer(&mut on_change_hooks).add_option(
            &["--on-change-hooks"],
            Store,
            "With --on-change: comma-separated kernel hooks to compare at. ingress = after each received segment (fexit/tcp_rcv_established and tcp_rcv_state_process), timer = after each retransmission, loss probe, RACK reordering or zero window probe timer (fexit/tcp_write_timer_handler), both into the recv_*_oc.tcp files; egress = before each transmitted segment (fentry/__tcp_transmit_skb), into send_*_oc.tcp, one probe run per segment. Default: ingress,timer. The list works as in --tp, e.g. +egress. In sock records, bits 8-15 of ato tell the hook (1 ingress, 2 timer, 3 egress).",
        );
        argparser.refer(&mut on_change_shadow).add_option(
            &["--on-change-shadow"],
            StoreTrue,
            "With --on-change and -k: write every sock run anyway, with the decision as a reason code in bits 0-7 of the ato field (1 suppressed, 2 changed, 3 first or after a drop, 4 state change, 5 no socket storage).",
        );
        argparser.refer(&mut no_timer_hook).add_option(
            &["--no-timer-hook"],
            StoreTrue,
            "With -k: do not record the socket after each run of the write timer (timer_sock.tcp). Same as --sock-hooks -timer.",
        );
        argparser.refer(&mut sock_hooks).add_option(
            &["--sock-hooks"],
            Store,
            "Comma-separated kernel hooks at which -k records the socket. Per packet: ingress = after each received segment (fexit/tcp_rcv_established and tcp_rcv_state_process, ingress_sock.tcp), egress = before each transmitted segment (fentry/__tcp_transmit_skb, send_sock.tcp), ingress-entry = before each received segment in ESTABLISHED (fentry/tcp_rcv_established, recv_sock.tcp). Not per packet: timer = after each write timer run (fexit/tcp_write_timer_handler, timer_sock.tcp); state, ca-state, retransmit, restart, rcvbuf = at TCP state and congestion state changes, retransmissions, cwnd restarts after idle and receive buffer growth (event_sock.tcp). Default: the ones not per packet. The list works as in --tp (all, default, +name, -name), e.g. +ingress on a sender. With --on-change and -k it is the same as --on-change-hooks (with -w alone, use --on-change-hooks).",
        );
        argparser.refer(&mut trace_algorithms).add_option(
            &["-a", "--algorithms"],
            StoreTrue,
            "Record the internals of the congestion control algorithms: CUBIC and BBR state, and Reno's congestion avoidance (also where DCTCP and others reuse it).",
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
        // Without any argument there is nothing to record, so show what can be recorded
        if std::env::args().len() == 1 {
            // A closed pipe (| head) is no error
            let _ = argparser.print_help("tcbee-record", &mut io::stdout());
            return Ok(());
        }
        argparser.parse_args_or_exit();
    }

    let trace_headers = !iface.is_empty();
    if !headers_at.is_empty() && !trace_headers {
        return Err(anyhow!("--headers-at needs -h"));
    }
    let headers_at = if headers_at.is_empty() {
        HeadersAt::default()
    } else {
        HeadersAt::parse(&headers_at).map_err(|e| anyhow!("--headers-at: {}", e))?
    };
    if headers_at.tc && headers_at.driver && !yes {
        // An offload that rules out the driver hooks stops the start anyway, so before asking
        check_offloads(&iface, headers_at, &Offloads::read(&iface)).map_err(|e| anyhow!(e))?;
        confirm_both_header_hooks(&iface)?;
    }
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
    let chose_sock_hooks = !sock_hooks.is_empty();
    let (on_change, sock_hooks) = HookFlags {
        kernel: trace_kernel,
        cwnd: trace_cwnd,
        sock_hooks: &sock_hooks,
        on_change: &on_change,
        on_change_hooks: &on_change_hooks,
        on_change_shadow,
        no_timer_hook,
    }
    .resolve()?;
    // A hint for plain -k only, not for a list someone chose
    if !chose_sock_hooks && sock_hooks.is_some_and(|hooks| hooks.hooks().all(|h| !h.per_packet())) {
        eprintln!(
            "Note: -k records the socket at timers and TCP events only; on a sender, --sock-hooks +ingress adds the state after every ACK"
        );
    }

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
        .headers_at(headers_at)
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
        .sock_hooks(sock_hooks)
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

/// Asks on the terminal before recording headers at TC and in the driver at once. Without a
/// terminal, or in the background, it refuses: scripts pass --yes.
fn confirm_both_header_hooks(iface: &str) -> anyhow::Result<()> {
    let warning = format!(
        "--headers-at tc,driver records every packet of {iface} at two hooks, each with its own \
         cost per packet, and attaches XDP to {iface}, which makes some drivers reset their \
         rings (a short interruption of the traffic)."
    );
    if !io::stdin().is_terminal() || !in_foreground() {
        return Err(anyhow!("{warning} Pass --yes to record without asking"));
    }
    eprint!("{warning}\nContinue? [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    if confirmed(&answer) {
        Ok(())
    } else {
        Err(anyhow!("Not confirmed, nothing recorded"))
    }
}

/// Whether the process runs in the foreground of its terminal: reading the terminal from the
/// background would stop it (SIGTTIN)
fn in_foreground() -> bool {
    unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) == libc::getpgrp() }
}

/// Whether an answer to a [y/N] question says yes
fn confirmed(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_yes_confirms() {
        for answer in ["y\n", "Y", " yes \n"] {
            assert!(confirmed(answer), "{answer:?}");
        }
        for answer in ["", "\n", "n", "no", "yess", "j"] {
            assert!(!confirmed(answer), "{answer:?}");
        }
    }
}
