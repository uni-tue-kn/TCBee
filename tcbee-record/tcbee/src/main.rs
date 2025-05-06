// Crate components
mod config;
mod handlers;
mod util;
mod viz;
use util::ebpf_runner::eBPFRunner;

// Error handling
use log::error;
use std::error::Error;

// Async Libraries
use tokio::signal::ctrl_c;
use tokio_util::sync::CancellationToken;

// Commandline arguments
use argparse::{ArgumentParser, Store, StoreTrue};

#[tokio::main(flavor = "multi_thread")]
async fn main()  {
    // Parse command line arguments
    let mut iface: String = String::new();
    let mut outfile: String = String::new();
    let mut quiet: bool = false;
    let mut port: u16 = 0;
    let mut update_period: u128 = 100;
    let mut trace_headers: bool = false;
    let mut trace_tracepoints: bool = false;
    let mut trace_kernel: bool = false;

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
        println!("No metrics to trace selected, stopping! Please select at least one of --headers, --tracepoints, --kernel!");
        return
    }

    // Greet user if running without TUI
    if quiet {
        println!("Running TCBee without terminal UI, Ctrl+c to stop recording!");
        println!("------------------------------------------------------------");
    }

    // Cancellation token to signal stopping to child threads
    let token = CancellationToken::new();
    // For each thread token is cloned an passed
    let passed_token = token.clone();

    // Main thread that strats all probes/tracepoints
    // If these calls fail, stop program!
    let mut runner =
        eBPFRunner::new(iface, passed_token, !quiet, update_period, port,trace_headers,trace_kernel,trace_tracepoints).expect("Failed to create eBPF runner!");
    // Setup and run eBPF threads
    let starting_result = runner.run().await;

    if let Err(err) = starting_result {
        error!("Failed to start eBPF runner {}", err);
        // Ensure that possible started threads are stopped
        runner.stop().await;
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

        println!("Stopping eBPF runner and threads!");

        // Stop runner and wait for all child threads to finish
        runner.stop().await;

        println!("Stopped gracefully!");
    }
}
