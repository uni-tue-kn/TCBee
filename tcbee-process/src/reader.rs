use std::fmt::Debug;
use std::os::unix::fs::MetadataExt;
use std::{error::Error, marker::PhantomData};

use log::{debug, info};
use serde::Deserialize;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::mpsc::Sender;
use tokio::task;
use tokio_util::sync::CancellationToken;

use crate::db_writer::as_db_operation;
use crate::{bindings::event_indexer::EventIndexer, db_writer::DBOperation};

use indicatif::ProgressBar;

pub trait FromBuffer {
    const ENTRY_SIZE: usize;
    fn from_buffer(buf: &Vec<u8>) -> Self;
}

pub struct FileReader<T> {
    path: String,
    reader: BufReader<File>,
    to_read: u64,
    tx: Sender<Vec<DBOperation>>,
    token: CancellationToken,
    progress: ProgressBar,
    _marker: PhantomData<T>,
}

impl<'a, T: EventIndexer + Debug + FromBuffer + Deserialize<'a> + Clone> FileReader<T> {
    pub async fn new(
        path: &str,
        tx: Sender<Vec<DBOperation>>,
        token: CancellationToken,
        progress: ProgressBar,
    ) -> Result<FileReader<T>, Box<dyn Error>> {
        let infile = OpenOptions::new().read(true).open(path).await?;

        let to_read = infile.metadata().await?.size();

        let reader = BufReader::new(infile);

        Ok(FileReader {
            path: path.to_string(),
            reader,
            to_read,
            tx,
            token,
            progress,
            _marker: PhantomData,
        })
    }

    // TODO: track file percentage!
    pub async fn run(&mut self) {
        let entry_size = T::ENTRY_SIZE;

        debug!("Entry size: {} bytes for {}", entry_size, self.path);

        let mut buffer = vec![0 as u8; entry_size];

        // Progress bar based on total number of entries
        let num_entries = self.to_read / entry_size as u64;
        self.progress.set_length(num_entries);

        // Read until error is returned
        while let Ok(read) = self.reader.read_exact(&mut buffer).await {
            // Check if end of file is reached
            if read < 1 {
                info!("Reached end of file for {}. Stopping!", self.path);
                self.progress.finish();
                return;
            }

            let event = T::from_buffer(&buffer);

            // Sometimes structs are misaligned, this causes all subsequent reads to fail
            // Have not yet found what could cause this...
            if !event.check_divider() {
                panic!(
                    "Misaligned PACKET: {:?}. Something went horribly wrong during recording!",
                    event
                );
            }

            let db_ops = as_db_operation(event);

            let res = self.tx.send(db_ops).await;
            if res.is_err() {
                info!("Stopping file read {} on channel close!", self.path);
                self.progress.finish();
                return;
            }

            self.progress.inc(1);

            // Allow other threads to run
            task::yield_now().await;
        }

        // Error was thrown, EOF reached!
        info!("Reached end of file for {}. Stopping!", self.path);
        self.progress.finish();
        return;
    }
}
