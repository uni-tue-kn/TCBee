use std::fmt::Debug;
use std::os::unix::fs::MetadataExt;
use std::{error::Error, marker::PhantomData};

use log::{debug, info};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufRead, AsyncReadExt, BufReader, ReadBuf};
use tokio::sync::mpsc::Sender;
use tokio::task;
use tokio_util::sync::CancellationToken;

use crate::{db_writer::DBOperation, flow_tracker::EventIndexer};

use indicatif::{ProgressBar, ProgressStyle};

pub trait FromBuffer {
    fn from_buffer(buf: &Vec<u8>) -> Self;
}

pub struct FileReader<T> {
    path: String,
    reader: BufReader<File>,
    to_read: u64,
    tx: Sender<DBOperation>,
    token: CancellationToken,
    _marker: PhantomData<T>,
}

impl<T: EventIndexer + Debug + FromBuffer> FileReader<T> {
    pub async fn new(
        path: &str,
        tx: Sender<DBOperation>,
        token: CancellationToken,
    ) -> Result<FileReader<T>, Box<dyn Error>> {
        let infile = OpenOptions::new().read(true).open(path).await?;

        let to_read = infile.metadata().await?.size();

        let reader = BufReader::new(infile);

        Ok(FileReader {
            path: path.to_string(),
            reader: reader,
            to_read: to_read,
            tx: tx,
            token: token,
            _marker: PhantomData,
        })
    }

    // TODO: track file percentage!
    pub async fn run(&mut self) {
        // Get bytes for read struct
        // TODO: I DONT KNOW WHY THIS 4 BYTE MISALIGNMENT HAPPENS, IT JUST DOES
        // FIX THIS!
        let entry_size = core::mem::size_of::<T>() - 4;
        //let entry_size = 68;

        debug!("Entry size: {} bytes for {}", entry_size, self.path);

        // Buffer for file reads
        let mut buffer = vec![0 as u8; entry_size];

        // Progress bar based on total number of entries
        let num_entries = self.to_read / entry_size as u64;
        let progress = ProgressBar::new(num_entries).with_message(self.path.clone());
        progress.set_style(
            ProgressStyle::with_template(
                "{msg} - [{eta_precise}/{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7}",
            )
            .unwrap(),
        );

        // Read until error is returned
        while let Ok(read) = self.reader.read_exact(&mut buffer).await {
            // Check if end of file is reached
            if read < 1 {
                info!("Reached end of file for {}. Stopping!", self.path);
                progress.finish();
                return;
            }

            // Bytes were read, try to parse to struct
            //let event: T = unsafe { std::ptr::read(buffer.as_ptr() as *const _) };
            let event = T::from_buffer(&buffer);

            let db_op = event.as_db_op();

            let res = self.tx.send(db_op).await;

            // If an error is returned, then channel is closed
            if res.is_err() {
                info!("Stopping file read {} on channel close!", self.path);
                progress.finish();
                return;
            }

            progress.inc(1);

            // Allow other threads to run
            task::yield_now().await;
        }

        // Error was thrown, EOF reached!
        info!("Reached end of file for {}. Stopping!", self.path);
        progress.finish();
        return;
    }
}
