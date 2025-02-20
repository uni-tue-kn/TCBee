pub mod tracepoints;
pub mod xdp_handler;

use std::marker::PhantomData;

use aya::maps::RingBuf;
use libc::O_NONBLOCK;
use log::{debug, error, info};
use tokio::{
    fs::OpenOptions,
    io::{AsyncWriteExt, BufWriter},
    task,
};
use tokio_util::sync::CancellationToken;

use crate::config::WRITER_BUFFER_SIZE;

// Turn sized struct into u8 buffer for datagram sockets
unsafe fn as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
}

// Has to be implemented for every type of queue entry
pub trait BufferHandlerImpl<T> {
    fn handle_event(&self, event: T) -> Option<T>;
}

// Basic class that implements reading from a queue with checking if read speed is enough
pub struct BufferHandler<T> {
    name: String,
    token: CancellationToken,
    buffer: RingBuf<aya::maps::MapData>,
    file_path: String,
    _entry: PhantomData<T>,
}

// TODO: T should be restricted to structs that are used for tracepoint queues!
impl<T: std::fmt::Debug + Clone + Copy + serde::ser::Serialize> BufferHandler<T> {
    pub fn new<Entry>(
        name: &str,
        token: CancellationToken,
        buffer: RingBuf<aya::maps::MapData>,
        file_path: String,
    ) -> Option<BufferHandler<Entry>>
    where
        BufferHandler<Entry>: Sized,
    {
        // TODO: better handling with error
        Some(BufferHandler::<Entry> {
            name: name.to_string(),
            token: token,
            buffer: buffer,
            file_path: file_path,
            _entry: PhantomData,
        })
    }

    // TODO: there is a chance this could be sped up by using a thread pool
    //        I.e. messages are split into blocks and passed into handling threads.
    //        This way, the next entries can e loaded without waiting for the write to finish
    pub async fn run(&mut self)
    where
        // This function can only be called if the BufferHandlerImpl trait is implemented for the type T
        Self: BufferHandlerImpl<T>,
    {
        let try_outfile = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .custom_flags(O_NONBLOCK) // Do not wait on OS to finish writing, this allows to write into the buffer earlier
            .open(&self.file_path)
            .await;

        if try_outfile.is_err() {
            error!(
                "Cannot open file {}. Error: {}",
                self.file_path,
                try_outfile.unwrap_err()
            );
            return;
        }

        // Create buffer writer with max WRITER_BUFFER_SIZE entries of T
        let entry_size = std::mem::size_of::<T>();
        let mut writer =
            BufWriter::with_capacity(entry_size * WRITER_BUFFER_SIZE, try_outfile.unwrap());

        info!("Handler {}, size: {} bytes", self.name, entry_size);

        loop {
            // Stop thread if signal received by parent
            if self.token.is_cancelled() {
                info!("Stopping {} handler on token cancel!", self.name);
                // Flush remaining entries in writer to file
                writer.flush().await;
                return;
            }

            // Check if ring buffer contains the next entry
            let possible_entry = self.buffer.next();

            // Check if entry was returned or queue was empty
            if let Some(ref entry) = possible_entry {
                // Unsafe cast into struct of type T
                // Will stay safe as long as a handler and queue have the same entry type T
                let val = unsafe { &*(entry.as_ptr() as *const T) };

                // Drop to return mutable borrow of self
                drop(possible_entry);

                // Call handling logic
                let res = self.handle_event(*val);

                // Event should be dropped if none is returned
                if res.is_none() {
                    return;
                }

                unsafe {

                    
                    let res_val = res.unwrap();
                    let slice = as_u8_slice(&res_val);

                    debug!("Entry: {:?}",slice);

                    let written = writer
                        .write(slice)
                        .await
                        .expect("Failed write!");

                    // Marker for alignment of packet in read step
                    // TODO: maybe remove for performanve reasons!
                    let _ = writer.write(&[255,255,255,255]).await;
                }
            } else {
                // Queue was empty, yield to let other tasks work
                // TODO: check if it is better to yield after every buffer.next()
                task::yield_now().await;
            }
        }
    }
}
