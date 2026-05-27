// Crate components
mod config;
mod eBPF;
mod viz;
mod writer;
use std::net::IpAddr;

use anyhow::anyhow;
use eBPF::ebpf_runner::EbpfRunner;
use eBPF::ebpf_runner_config::{ip_to_filter_addr, EbpfRunnerConfig, FilterConfig};
use tcbee_trace::TCBeeTrace;

// Error handling
use log::info;

// Async Libraries
use tokio::{runtime::Builder, signal::ctrl_c};
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
    let mut cpus: u16 = 1;
    let mut metrics: bool = false;

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
            "Record TCP metrics of tcp_probe kernel tracepoint. Covers main TCP metrics but not all!",
        );
        argparser.refer(&mut trace_kernel).add_option(
            &["-k", "--kernel"],
            StoreTrue,
            "Record TCP metrics from kernel calls to tcp_sendmsg and tcp_recvmsg! Covers all TCP metrics.",
        );
        argparser.refer(&mut metrics).add_option(
            &["-m", "--metrics"],
            StoreTrue,
            "Output a file containing general metrics, such as events handled and events lost. Stored under --dir path as 'metrics.json'",
        );
        argparser.refer(&mut trace_algorithms).add_option(
            &["-a", "--algorithms"],
            StoreTrue,
            "Record behaviour of congestion algorithms: Cubic and BBR.",
        );

        // Will try to parse arguments or exit program on error!
        argparser.parse_args_or_exit();
    }

    let trace_headers = !iface.is_empty();
    let filter = FilterConfig {
        single_port: port,
        any_ports: parse_csv(&ports, "port")?,
        src_ports: parse_csv(&src_ports, "source port")?,
        dst_ports: parse_csv(&dst_ports, "destination port")?,
        any_ips: parse_ip_csv(&ips, "IP address")?,
        src_ips: parse_ip_csv(&src_ips, "source IP address")?,
        dst_ips: parse_ip_csv(&dst_ips, "destination IP address")?,
    };

    if !trace_headers && !trace_tracepoints && !trace_kernel && !trace_cwnd && !trace_algorithms {
        return Err(anyhow!("No metrics to trace selected, stopping!"));
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
        .tracepoints(trace_tracepoints)
        .kernel(trace_kernel)
        .interface(iface)
        .cwnd(trace_cwnd)
        .metrics(metrics)
        .algorithms(trace_algorithms)
        .dir(trace_dir);

    // Main thread that strats all probes/tracepoints
    // If these calls fail, stop program!
    let mut runner = EbpfRunner::new(token.clone(), config);

    let runtime = Builder::new_multi_thread()
        .worker_threads(cpus as usize)
        .thread_name("TCBee")
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let starting_result = runner.run().await;

        if let Err(err) = starting_result {
            // On start failure, wait until everythin has stopped
            let err = anyhow!("Failed to start eBPF runner {}", err);
            runner.stop().await;
            Err(err)
        } else {
            // Runner was created and correctly initialized
            // If quiet mode: wait for ctrl+c to cancel
            // If TUI is used: TUI will cancel the token so wait for that
            if quiet {
                let _ = ctrl_c().await;
                token.cancel();
            } else {
                token.cancelled().await;
            }

            info!("Stopping eBPF runner and threads!");

            // waits for all child threads to finish
            runner.stop().await;

            info!("Stopped gracefully!");
            Ok(())
        }
    })
}
