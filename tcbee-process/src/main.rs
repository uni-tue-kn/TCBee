mod db_writer;
mod flow_tracker;
mod reader;

mod bindings {
    pub mod ctypes;
    pub mod sock;
    pub mod tcp_packet;
    pub mod tcp_probe;
}

use bindings::{sock::sock_trace_entry, tcp_packet::TcpPacket, tcp_probe::TcpProbe};
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
    collections::HashMap,
    error::Error,
    fmt::Debug,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    slice::Windows,
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

async fn start_file_reader<
    'a,
    T: EventIndexer + FromBuffer + Debug + Send + Clone + Deserialize<'a> + 'static,
>(
    path: &'static str,
    tx: Sender<DBOperation>,
    token: CancellationToken,
    bars: &MultiProgress,
) -> JoinHandle<()> {
    // Add progress bar to multibar
    let mut progress = ProgressBar::new(0).with_message(path);
    progress.set_style(
        ProgressStyle::with_template(
            "{msg} - [{eta_precise}/{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7}",
        )
        .unwrap(),
    );
    progress = bars.add(progress);

    // Initialize reader to db
    // TODO: change to if let
    let reader_res = FileReader::<T>::new(path, tx.clone(), token, progress).await;
    if reader_res.is_err() {
        panic!(
            "Could not open File at {} ! Error: {}",
            path,
            reader_res.err().unwrap()
        )
    }
    let mut reader = reader_res.unwrap();

    // Start reader
    task::spawn(async move {
        reader.run().await;
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

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
            "/tmp/xdp.tcp",
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<TcpPacket>(
            "/tmp/tc.tcp",
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<TcpProbe>(
            "/tmp/probe.tcp",
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<sock_trace_entry>(
            "/tmp/sock_send.tcp",
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<sock_trace_entry>(
            "/tmp/sock_recv.tcp",
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
    ];

    // Wait for file threads to finish!
    // TODO add ctrl + c check!
    for t in threads {
        let _res = t.await;
    }
    // Ensure that all channel tx are dropped to signal db_backend to stop
    drop(tx);

    info!("File readers finished!");

    // Signal stop to db backend
    stop_token.cancel();

    Ok(())
}
