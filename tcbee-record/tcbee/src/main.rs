// Crate components
mod config;
mod eBPF;
mod writer;
mod viz;
use anyhow::anyhow;
use eBPF::ebpf_runner::EbpfRunner;
use eBPF::ebpf_runner_config::EbpfRunnerConfig;
use tcbee_trace::TCBeeTrace;

// Error handling
use log::info;

// Async Libraries
use tokio::{runtime::Builder, signal::ctrl_c};
use tokio_util::sync::CancellationToken;

// Commandline arguments
use argparse::{ArgumentParser, Store, StoreTrue};

fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let mut iface: String = String::new();
    let mut dir: String = "/tmp/".to_string();
    let mut quiet: bool = false;
    let mut port: u16 = 0;
    let mut update_period: u128 = 100;
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
        argparser
            .refer(&mut iface)
            .add_option(&["-h", "--headers"], Store, "Record TCP headers of incoming and outgoing packets on the specified interface.");
        argparser.refer(&mut dir).add_option(
            &["-d", "--dir"],
            Store,
            "Directory to store recording results in. Defaults to /tmp/",
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
        .filter_port(port)
        .tui(!quiet)
        .update_period(update_period)
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
