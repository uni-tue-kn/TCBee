mod db_writer;
mod flow_tracker;
mod reader;

mod bindings {
    pub mod ctypes;
    pub mod sock;
    pub mod tcp_packet;
    pub mod tcp_probe;
    pub mod cwnd;
}

use argparse::{ArgumentParser, Store};
use bindings::{sock::sock_trace_entry, cwnd::cwnd_trace_entry, tcp_packet::TcpPacket, tcp_probe::TcpProbe};
use db_writer::{DBOperation, DBWriter};
use flow_tracker::{EventIndexer, EventType, FlowTracker, TsTracker};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{error, info};
use reader::{FileReader, FromBuffer};
use serde::Deserialize;
use tokio::{
    signal::ctrl_c,
    sync::mpsc::{self, Sender},
    task::{self, JoinHandle},
};
use tokio_util::sync::CancellationToken;

use core::num;
use std::{
    collections::HashMap, error::Error, fmt::Debug, io::Read, net::{IpAddr, Ipv4Addr}, path::Path, slice::Windows
};

// Kernel sometimes uses a 28 Byte IP Address struct
// First 4 Bytes are IP Version, Port
// Next 4 Bytes are IPv4 Address (0 if IPv6)
// Next 16 Bytes are IPv6 Address (0 if IPv4)
fn shorten_to_ipv6(arg: [u8; 28]) -> [u8; 16] {
    std::array::from_fn(|i| arg[i + 8])
}
fn shorten_to_ipv4(arg: [u8; 28]) -> [u8; 4] {
    std::array::from_fn(|i| arg[i + 4])
}

pub fn prepend_string(mut src: String, prefix: &str) -> String {
    src.insert_str(0, prefix);
    src
}


async fn start_file_reader<
    'a,
    T: EventIndexer + FromBuffer + Debug + Send + Clone + Deserialize<'a> + 'static,
>(
    path: String,
    tx: Sender<DBOperation>,
    token: CancellationToken,
    bars: &MultiProgress,
) -> Option<JoinHandle<()>> {
    // Add progress bar to multibar
    let mut progress = ProgressBar::new(0).with_message(path.clone());
    progress.set_style(
        ProgressStyle::with_template(
            "{msg} - [{eta_precise}/{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7}",
        )
        .unwrap(),
    );
    progress = bars.add(progress);

    // File does not exist
    if !Path::new(&path).exists() {
        progress.set_message(format!("No Entries: {}!",path));
        progress.finish();
        return None;
    }

    // Initialize reader to db
    // TODO: change to if let
    let reader_res = FileReader::<T>::new(&path, tx.clone(), token, progress).await;
    if reader_res.is_err() {
        panic!(
            "Could not open File at {} ! Error: {}",
            path,
            reader_res.err().unwrap()
        )
    }
    let mut reader = reader_res.unwrap();

    // Start reader
    Some(task::spawn(async move {
        reader.run().await;
    }))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut dir: String = "/tmp/".to_string();
    {
        let mut argparser = ArgumentParser::new();
        argparser.refer(&mut dir).add_option(
            &["-d", "--dir"],
            Store,
            "Directory to read recording results from. Defaults to /tmp/",
        );
        argparser.parse_args_or_exit();
    }

    let progress_bars = MultiProgress::new();

    let status = progress_bars.add(ProgressBar::new(5));
    status.set_style(
        ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
    );

    // Channel to send operations to DB Backend
    let (tx, rx) = mpsc::channel::<DBOperation>(100000);
    let stop_token = CancellationToken::new();

    info!("Starting db backend!");
    println!("Starting readers, initial processing may be slow due to setup of streams!");

    // Create DB Backend handler
    let db_res = DBWriter::new("db.sqlite", rx,status);
    if db_res.is_err() {
        panic!("Could not open Database! Error: {}", db_res.err().unwrap())
    }
    let mut db = db_res.unwrap();

    let _db_thread = task::spawn_blocking(move || {
        let res = db.run();
        if res.is_err() {
            error!(
                "DB Backend stopping on error! Error: {}",
                res.err().unwrap()
            )
        }
    });

    info!("Starting file readers!");

    // Start all tasks
    // TODO: move to config file!
    
    let threads = vec![
        start_file_reader::<TcpPacket>(
            prepend_string("xdp.tcp".to_string(),&dir),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<TcpPacket>(
            prepend_string("tc.tcp".to_string(),&dir),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<TcpProbe>(
            prepend_string("probe.tcp".to_string(),&dir),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<sock_trace_entry>(
            prepend_string("sock_send.tcp".to_string(),&dir),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<sock_trace_entry>(
            prepend_string("sock_recv.tcp".to_string(),&dir),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<cwnd_trace_entry>(
            prepend_string("recv_cwnd.tcp".to_string(),&dir),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<cwnd_trace_entry>(
            prepend_string("send_cwnd.tcp".to_string(),&dir),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
    ];

    // Wait for file threads to finish!
    // TODO add ctrl + c check!
    for t in threads.into_iter().flatten() {
        let _res = t.await;
    }
    // Ensure that all channel tx are dropped to signal db_backend to stop
    drop(tx);

    info!("File readers finished!");

    // Signal stop to db backend
    stop_token.cancel();

    Ok(())
}
