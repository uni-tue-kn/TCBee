use std::{collections::HashMap, error::Error};

use indicatif::ProgressBar;
use log::error;
use tokio::sync::mpsc::Receiver;
use ts_storage::{
    database_factory, sqlite::SQLiteTSDB, DBBackend, DataPoint, IpTuple, TSDBInterface,
};

use crate::{
    bindings::{
        cwnd::cwnd_trace_entry, sock::sock_trace_entry, tcp_packet::TcpPacket, tcp_probe::TcpProbe,
    },
    flow_tracker::{EventIndexer, FlowTracker},
};

#[derive(Debug)]
pub struct DBOperation {
    pub tuple: IpTuple,
    pub time_series: String,
    pub data_point: DataPoint,
}

pub fn as_db_operation<T: EventIndexer>(event: T) -> Vec<DBOperation> {
    let mut vec: Vec<DBOperation> = Vec::with_capacity(event.get_max_index());

    for i in 0..=event.get_max_index() {
        vec.push(DBOperation {
            tuple: event.get_ip_tuple(),
            time_series: event.get_field_name(i).to_string(),
            data_point: DataPoint {
                timestamp: event.get_timestamp(),
                value: event.get_field(i),
            },
        });
    }
    vec
}

pub struct DBWriter {
    db: Box<dyn TSDBInterface + Send>,
    streams: HashMap<IpTuple, FlowTracker>,
    rx: Receiver<DBOperation>,
    status: ProgressBar,
    num_flows: i32,
}

impl DBWriter {
    pub fn new(
        backend: DBBackend,
        rx: Receiver<DBOperation>,
        status: ProgressBar,
    ) -> Result<DBWriter, Box<dyn Error>> {
        let db: Box<dyn TSDBInterface + Send> = database_factory::<SQLiteTSDB>(backend)?;

        let streams: HashMap<IpTuple, FlowTracker> = HashMap::new();

        status.set_message(format!("Tracking {} Flows", 0));

        Ok(DBWriter {
            db,
            streams,
            rx,
            status,
            num_flows: 0,
        })
    }

    pub fn setup_new_stream(&mut self, tuple: &IpTuple) -> Result<(), Box<dyn Error>> {
        // Insert stream if not known
        if !self.streams.contains_key(tuple) {
            let new_tracker = FlowTracker::new(&self.db, tuple);

            // TODO: remove unwrap, error handling!
            self.streams.insert(tuple.clone(), new_tracker);

            // Update progress message!
            self.num_flows += 1;
            self.status
                .set_message(format!("Tracking {} Flows", self.num_flows));
        }

        Ok(())
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        // Time of first entry, will be used to normalize all other times
        while let Some(event) = self.rx.blocking_recv() {
            self.status.inc(1);

            if let Some(tracker) = self.streams.get_mut(&event.tuple) {
                let res = tracker.add_event(&self.db, event);

                if res.is_err() {
                    error!("Failed to handle event. Error: {}", res.err().unwrap());
                }
            } else {
                self.setup_new_stream(&event.tuple)?;
                let tracker = self.streams.get_mut(&event.tuple).unwrap();
                let res = tracker.add_event(&self.db, event);

                if res.is_err() {
                    error!("Failed to handle event. Error: {}", res.err().unwrap());
                }

            }
        }
        // This is reached when all tx channels are dropped, flush files!
        for (tuple, tracker) in self.streams.iter_mut() {
            tracker.flush(&self.db);
            //println!("Stream: {:?} - Tracker: {:?}",tuple,tracker);
        }
        Ok(())
    }
}
