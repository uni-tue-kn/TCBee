// Crate components
mod config;
mod handlers;
mod eBPF;
mod viz;
use anyhow::anyhow;
use eBPF::ebpf_runner::EbpfRunner;
use eBPF::ebpf_runner_config::EbpfRunnerConfig;

// Error handling
use log::{error, info};
use std::error::Error;

// Async Libraries
use tokio::{runtime::Builder, signal::ctrl_c};
use tokio_util::sync::CancellationToken;

// Commandline arguments
use argparse::{ArgumentParser, Store, StoreTrue};

fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let mut iface: String = String::new();
    let mut outfile: String = String::new();
    let mut quiet: bool = false;
    let mut port: u16 = 0;
    let mut update_period: u128 = 100;
    let mut trace_headers: bool = false;
    let mut trace_tracepoints: bool = false;
    let mut trace_kernel: bool = false;
    let mut cpus: u16 = 1;

    {
        let mut argparser = ArgumentParser::new();
        argparser.set_description(
            "TCBee: A High-Performance and Extensible Tool For TCP Connection Analysis Using eBPF",
        );
        argparser
            .refer(&mut iface)
            .add_argument("interface", Store, "Interface to record packets on!")
            .required();
        argparser.refer(&mut outfile).add_option(
            &["-f", "--file"],
            Store,
            "File to store recording results in.",
        );
        argparser.refer(&mut port).add_option(
            &["-p", "--port"],
            Store,
            "Filter streams for remote or local port.",
        );
        argparser.refer(&mut update_period).add_option(
            &["--tui-update-ms"],
            Store,
            "Miliseconds between each TUI update. Default is 100ms, higher values may help with tearing.",
        );
        argparser.refer(&mut cpus).add_option(
            &["-c", "--cpus"],
            Store,
            "Number of CPUs to run TCBee on. Will run at 100% load due to polling from eBPF maps.",
        );
        argparser.refer(&mut quiet).add_option(
            &["-q", "--quiet"],
            StoreTrue,
            "Disable terminal UI. Will still display some information.",
        );
        argparser.refer(&mut trace_headers).add_option(
            &["-h", "--headers"],
            StoreTrue,
            "Record headers of TCP packets using Tthe XDP and TC hook. Very resource intensive!",
        );
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

        // Will try to parse arguments or exit program on error!
        argparser.parse_args_or_exit();
    }

    if !trace_headers && !trace_tracepoints && !trace_kernel {
        return Err(anyhow!("No metrics to trace selected, stopping!"));
    }

    // Greet user if running without TUI
    if quiet {
        println!("Running TCBee without terminal UI, Ctrl+c to stop recording!");
        println!("------------------------------------------------------------");
    }

    // Cancellation token to signal stopping to child threads
    let token = CancellationToken::new();

    let config = EbpfRunnerConfig::new()
        .filter_port(port)
        .tui(!quiet)
        .update_period(update_period)
        .headers(trace_headers)
        .tracepoints(trace_tracepoints)
        .kernel(trace_kernel)
        .interface(iface);

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

            // Stop runner and wait for all child threads to finish
            runner.stop().await;

            info!("Stopped gracefully!");
            Ok(())
        }
    })
}
