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

use crate::{db_writer::DBOperation, flow_tracker::EventIndexer};

use indicatif::ProgressBar;

pub trait FromBuffer {
    const ENTRY_SIZE: usize;
    fn from_buffer(buf: &Vec<u8>) -> Self;
}

pub struct FileReader<T> {
    path: String,
    reader: BufReader<File>,
    to_read: u64,
    tx: Sender<DBOperation>,
    token: CancellationToken,
    progress: ProgressBar,
    _marker: PhantomData<T>,
}

impl<'a,T: EventIndexer + Debug + FromBuffer + Deserialize<'a> + Clone> FileReader<T> {
    pub async fn new(
        path: &str,
        tx: Sender<DBOperation>,
        token: CancellationToken,
        progress: ProgressBar
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
        // Get bytes for read struct
        // TODO: I DONT KNOW WHY THIS 4 BYTE MISALIGNMENT HAPPENS, IT JUST DOES
        // FIX THIS!
        let entry_size = T::ENTRY_SIZE;
        //let entry_size = size_of::<T>();
        //let entry_size = 68;

        debug!("Entry size: {} bytes for {}", entry_size, self.path);

        // Buffer for file reads
        let mut buffer = vec![0 as u8; entry_size];

        // Progress bar based on total number of entries
        let num_entries = self.to_read / entry_size as u64;
        // Update length of progress bar with expected number of entries
        self.progress.set_length(num_entries);

        // Read until error is returned
        while let Ok(read) = self.reader.read_exact(&mut buffer).await {
            // Check if end of file is reached
            if read < 1 {
                info!("Reached end of file for {}. Stopping!", self.path);
                self.progress.finish();
                return;
            }


            // Bytes were read, try to parse to struct
            //let event: T = unsafe { std::ptr::read(buffer.as_ptr() as *const _) };
            let event = T::from_buffer(&buffer);
            // TODO: error handling
            //let event: T = bincode::deserialize::<'b,T>(&buf).unwrap();

            let db_op = event.as_db_op();

            let res = self.tx.send(db_op).await;

            // If an error is returned, then channel is closed
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
