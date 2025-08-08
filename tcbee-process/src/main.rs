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

use argparse::{ArgumentParser, Store, StoreTrue};
use bindings::{sock::sock_trace_entry, cwnd::cwnd_trace_entry, tcp_packet::TcpPacket, tcp_probe::TcpProbe};
use db_writer::{DBOperation, DBWriter};
use flow_tracker::EventIndexer;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{error, info};
use reader::{FileReader, FromBuffer};
use serde::Deserialize;
use tokio::{
    sync::mpsc::{self, Sender},
    task::{self, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use ts_storage::DBBackend;

use std::{
    error::Error, fmt::Debug, path::Path
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

    let mut source: String = "/tmp/".to_string();
    let mut output: String = "".to_string();
    let mut sqlite: bool = false;
    let mut duckdb: bool = false;

    {
        let mut argparser = ArgumentParser::new();
        argparser.refer(&mut source).add_option(
            &["-s", "--source"],
            Store,
            "Directory to search for TCBee recording *.tcp files!",
        );
        argparser.refer(&mut output).add_option(
            &["-o", "--output"],
            Store,
            "Path for outoput database file",
        );
        argparser.refer(&mut sqlite).add_option(
            &["-q", "--sqlite"],
            StoreTrue,
            "Store result to SQLITE",
        );
        argparser.refer(&mut duckdb).add_option(
            &["-d", "--duckdb"],
            StoreTrue,
            "Store result to DuckDB, better performance",
        );

        argparser.parse_args_or_exit();
    }

    if !sqlite && !duckdb {
        print!("Please select either --sqlite or --duckdb");
        return Ok(());
    }
    if sqlite && duckdb {
        print!("Please select either --sqlite or --duckdb");
        return Ok(());
    }

    if output.is_empty() {
        if sqlite {
            output = "/tmp/db.sqlite".to_string();
        }
        if duckdb {
            output = "/tmp/db.duck".to_string();
        }
    }

    let mut backend = DBBackend::SQLite(output.clone());
    if duckdb {
        backend = DBBackend::DuckDB(output);
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
    let db_res = DBWriter::new(backend, rx,status);
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
            prepend_string("xdp.tcp".to_string(),&source),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<TcpPacket>(
            prepend_string("tc.tcp".to_string(),&source),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<TcpProbe>(
            prepend_string("probe.tcp".to_string(),&source),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<sock_trace_entry>(
            prepend_string("send_sock.tcp".to_string(),&source),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<sock_trace_entry>(
            prepend_string("recv_sock.tcp".to_string(),&source),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<cwnd_trace_entry>(
            prepend_string("recv_cwnd.tcp".to_string(),&source),
            tx.clone(),
            stop_token.clone(),
            &progress_bars,
        )
        .await,
        start_file_reader::<cwnd_trace_entry>(
            prepend_string("send_cwnd.tcp".to_string(),&source),
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
