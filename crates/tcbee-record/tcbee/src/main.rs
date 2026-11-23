// Crate components
mod cli;
mod config;
mod eBPF;
mod metadata;
mod metrics;
mod owners;
mod placement;
mod pooled;
mod rawring;
mod ring_groups;
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
    ip_filter_keys, on_change_manifest, parse_ringbuf_sizes, parse_sock_fields,
    sock_fields_manifest, tracepoint_set, EbpfRunnerConfig, FilterConfig, HookFlags, MptcpModes,
    FILTER_MAX_ENTRIES,
};
use eBPF::probes::headers::{check_offloads, HeadersAt};
use metadata::Offloads;
use tcbee_trace::TCBeeTrace;
use writer::{Placement, PollMode, SinkConfig, SinkKind, WriterFormat};

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

/// CPU ids for a CPU set
fn parse_cpu_list(arg: &str, name: &str) -> anyhow::Result<Vec<usize>> {
    let cpus: Vec<usize> = parse_csv(arg, name)?;
    if let Some(cpu) = cpus.iter().find(|cpu| **cpu >= libc::CPU_SETSIZE as usize) {
        return Err(anyhow!("Invalid {} {}", name, cpu));
    }
    Ok(cpus)
}

fn parse_ip_csv(arg: &str, name: &str) -> anyhow::Result<Vec<[u8; 16]>> {
    let mut keys: Vec<[u8; 16]> = parse_csv::<IpAddr>(arg, name)?
        .into_iter()
        .flat_map(ip_filter_keys)
        .collect();
    keys.sort_unstable();
    keys.dedup();
    if keys.len() > FILTER_MAX_ENTRIES {
        return Err(anyhow!(
            "Too many {name}es: an IPv4 address takes two of the {FILTER_MAX_ENTRIES} filter \
             entries (also as v4-mapped IPv6), an IPv6 address one"
        ));
    }
    Ok(keys)
}

fn main() -> anyhow::Result<()> {
    let argv = std::env::args().collect();
    let args = match cli::parse_args(argv, &mut io::stdout(), &mut io::stderr()) {
        Ok(args) => args,
        Err(code) => std::process::exit(code),
    };
    let cli::Args {
        iface,
        headers_at,
        yes,
        dir,
        quiet,
        port,
        ports,
        src_ports,
        dst_ports,
        ips,
        src_ips,
        dst_ips,
        update_period,
        observation_window,
        trace_tracepoints,
        trace_kernel,
        trace_algorithms,
        trace_cwnd,
        trace_mptcp,
        tp,
        mptcp_modes,
        cpus,
        metrics,
        metadata,
        duration,
        ringbuf_size,
        poll,
        writer_cpus,
        writer_placement,
        writer_sink,
        writer_format,
        writer_io_cpus,
        writer_no_prealloc,
        writer_max_buffers,
        on_change,
        on_change_hooks,
        on_change_shadow,
        sock_hooks,
        sock_fields,
        no_owners,
        no_hook_seq,
        owners_no_cmdline,
        version: _,
    } = args;

    let trace_headers = !iface.is_empty();
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
    let tracepoints = tracepoint_set(trace_tracepoints, &tp)?;
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
    let writer_cpus = parse_cpu_list(&writer_cpus, "writer CPU id")?;
    let poll_mode = match poll.as_str() {
        "busy" => PollMode::Busy,
        "wait" => PollMode::Wait,
        other => return Err(anyhow!("Unknown --poll mode '{}', use busy or wait", other)),
    };
    let writer_io_cpus = parse_cpu_list(&writer_io_cpus, "writer I/O CPU id")?;
    let Some(kind) = SinkKind::from_name(&writer_sink) else {
        return Err(anyhow!(
            "Unknown --writer-sink '{}', use {}",
            writer_sink,
            SinkKind::names()
        ));
    };
    if matches!(kind, SinkKind::Mmap | SinkKind::Sync) && !writer_io_cpus.is_empty() {
        return Err(anyhow!(
            "--writer-io-cpus needs --writer-sink direct, uring or buffered"
        ));
    }
    let writer_sink = SinkConfig {
        io_cpus: writer_io_cpus,
        preallocate: !writer_no_prealloc,
        max_buffers: writer_max_buffers.unwrap_or(SinkConfig::default().max_buffers),
        ..SinkConfig::of(kind)
    };
    let Some(writer_format) = WriterFormat::from_name(&writer_format) else {
        return Err(anyhow!(
            "Unknown --writer-format '{}', use records or raw",
            writer_format
        ));
    };
    let writer_placement = match writer_placement.as_str() {
        "balanced" => Placement::Balanced,
        "round-robin" => Placement::RoundRobin,
        other => {
            return Err(anyhow!(
                "Unknown --writer-placement '{}', use balanced or round-robin",
                other
            ))
        }
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
    }
    .resolve()?;
    let sock_fields = parse_sock_fields(&sock_fields, sock_hooks, on_change.is_some())?;
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
        .metadata(metadata || no_hook_seq)
        .algorithms(trace_algorithms)
        .mptcp(mptcp)
        .ringbuf_sizes(ringbuf_sizes)
        .poll_mode(poll_mode)
        .writer_cpus(writer_cpus.clone())
        .writer_placement(writer_placement)
        .writer_sink(writer_sink)
        .writer_format(writer_format)
        .on_change(on_change)
        .sock_hooks(sock_hooks)
        .sock_fields(sock_fields.clone())
        .hook_seq(!no_hook_seq)
        .owners(!no_owners)
        .owner_cmdlines(!owners_no_cmdline)
        .dir(trace_dir);

    // Before any record: a field-selected file cannot be read without it
    if let (Some(shape), Some(hooks)) = (&sock_fields, sock_hooks) {
        sock_fields_manifest(shape, hooks)
            .write(trace.dir())
            .map_err(|e| anyhow!("Failed to write the manifest: {e}"))?;
    }

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
