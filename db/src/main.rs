mod db_writer;
mod flow_tracker;
mod reader;

mod bindings {
    pub mod tcp_packet;
    pub mod tcp_probe;
    pub mod ctypes;
    pub mod sock;
}

use bindings::{sock::sock_trace_entry, tcp_packet::TcpPacket, tcp_probe::TcpProbe};
use db_writer::{DBOperation, DBWriter};
use flow_tracker::{EventIndexer, EventType, FlowTracker, TsTracker};
use log::{error, info};
use reader::{FileReader, FromBuffer};
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

async fn start_file_reader<T: EventIndexer + FromBuffer + Debug + Send + 'static>(
    path: &str,
    tx: Sender<DBOperation>,
    token: CancellationToken,
) -> JoinHandle<()> {
    let reader_res = FileReader::<T>::new(path, tx.clone(), token).await;
    if reader_res.is_err() {
        panic!(
            "Could not open File at {} ! Error: {}",
            path,
            reader_res.err().unwrap()
        )
    }
    let mut reader = reader_res.unwrap();

    task::spawn(async move {
        reader.run().await;
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {

    env_logger::init();

    let file = "db.sqlite".to_string();

    // TODO: load from tcpprobe-common
    let xdp_path = "/tmp/xdp.tcp";
    let tc_path = "/tmp/tc.tcp";
    let probe_path = "/tmp/probe.tcp";

    let a = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 146, 10, 44, 83, 186, 4, 0, 0, 1, 0, 0, 127, 1, 0, 0, 127, 16, 29, 237, 216, 42, 87, 50, 48, 152, 166, 137, 19, 0, 2, 147, 129, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
    let b = [122, 32, 14, 217, 42, 87, 50, 48, 152, 166, 137, 19, 0, 2, 244, 253, 0, 0, 0, 0, 0, 0, 0, 0];
    // Channel to send operations to DB Backend
    let (tx, rx) = mpsc::channel::<DBOperation>(100000);
    let stop_token = CancellationToken::new();

    info!("Starting db backend!");

    // Create DB Backend handler
    let db_res = DBWriter::new("db.sqlite", rx);
    if db_res.is_err() {
        panic!("Could not open Database! Error: {}", db_res.err().unwrap())
    }
    let mut db = db_res.unwrap();

    let db_thread = task::spawn_blocking(move || {
        let res = db.run();
        if res.is_err() {
            error!("DB Backend stopping on error! Error: {}",res.err().unwrap())
        }
    });

    info!("Starting file readers!");

    // Start all tasks
    let threads = vec![
        //start_file_reader::<TcpPacket>("/tmp/xdp.tcp", tx.clone(), stop_token.clone()).await,
        //start_file_reader::<TcpPacket>("/tmp/tc.tcp", tx.clone(), stop_token.clone()).await,
        //start_file_reader::<TcpProbe>("/tmp/probe.tcp", tx.clone(), stop_token.clone()).await,
        start_file_reader::<sock_trace_entry>("/tmp/sock.tcp", tx.clone(), stop_token.clone()).await
    ];

    // Wait for file threads to finish!
    // TODO add ctrl + c check!
    for t in threads {
        
        let res = t.await;
    }
    // Ensure that all channel tx are dropped to signal db_backend to stop
    drop(tx);

    info!("File readers finished!");

    // Signal stop to db backend
    stop_token.cancel();
    
    Ok(())
}
