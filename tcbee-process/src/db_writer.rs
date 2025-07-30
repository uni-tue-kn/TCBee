use std::{collections::HashMap, error::Error};

use indicatif::ProgressBar;
use log::error;
use tokio::sync::mpsc::Receiver;
use ts_storage::{database_factory, sqlite::SQLiteTSDB, DBBackend, IpTuple, TSDBInterface};

use crate::{
    bindings::{sock::sock_trace_entry, cwnd::cwnd_trace_entry, tcp_packet::TcpPacket, tcp_probe::TcpProbe},
    flow_tracker::{EventIndexer, EventType, FlowTracker},
};

#[derive(Debug)]
pub enum DBOperation {
    Packet(TcpPacket),
    Probe(TcpProbe),
    Socket(sock_trace_entry),
    Cwnd(cwnd_trace_entry)
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
        file: &str,
        rx: Receiver<DBOperation>,
        status: ProgressBar,
    ) -> Result<DBWriter, Box<dyn Error>> {
        let db: Box<dyn TSDBInterface + Send> =
            database_factory::<SQLiteTSDB>(DBBackend::SQLite(file.to_string()))?;

        let streams: HashMap<IpTuple, FlowTracker> = HashMap::new();

        status.set_message(format!("Tracking {} Flows",0));

        Ok(DBWriter {
            db,
            streams,
            rx,
            status,
            num_flows: 0
        })
    }

    pub fn setup_new_stream(&mut self, tuple: &IpTuple) -> Result<(), Box<dyn Error>>  {
        // Insert stream if not known
        if !self.streams.contains_key(tuple) {
            let new_tracker = FlowTracker::new(&self.db, tuple);

            // TODO: remove unwrap, error handling!
            self.streams.insert(tuple.clone(), new_tracker);

            // Update progress message!
            self.num_flows += 1;
            self.status.set_message(format!("Tracking {} Flows",self.num_flows));
        }

        Ok(())
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        // Time of first entry, will be used to normalize all other times
        // TODO: if order is scrambled, does this fail?
        let time_base: f64 = 0.0;

        while let Some(event) = self.rx.blocking_recv() {
            self.status.inc(1);
            match event {
                DBOperation::Packet(data) => {
                    if data.div != 0xFFFFFFFFu32.to_be_bytes() {
                        panic!("Misaligned PACKET: {:?}. Something went horribly wrong during recording!",data);
                    }

                    let tuple = data.get_ip_tuple();

                    self.setup_new_stream(&tuple)?;

                    let tracker = self.streams.get_mut(&tuple).unwrap();

                    let res = tracker.add_event(&self.db, EventType::Packet, &data);

                    if res.is_err() {
                        error!(
                            "Failed to trace packet: {:?}. Error: {}",
                            data,
                            res.err().unwrap()
                        );
                    }
                },
                DBOperation::Probe(data) => {
                    if data.div != 0xFFFFFFFFu32.to_be_bytes() {
                        panic!("Misaligned PROBE: {:?}. Something went horribly wrong during recording!",data);
                    }

                    let tuple = data.get_ip_tuple();
                    self.setup_new_stream(&tuple)?;

                    let tracker = self.streams.get_mut(&tuple).unwrap();

                    let res = tracker.add_event(&self.db, EventType::TcpProbe, &data);

                    if res.is_err() {
                        error!(
                            "Failed to trace packet: {:?}. Error: {}",
                            data,
                            res.err().unwrap()
                        );
                    }

                    //println!("Probe {:?}",data.ssthresh);
                },
                DBOperation::Socket(sock) => {
                    if sock.div != 0xFFFFFFFFu32.to_be_bytes() {
                        panic!("Misaligned SOCKET: {:?}. Something went horribly wrong during recording!",sock);
                    }

                    let tuple = sock.get_ip_tuple();
                    self.setup_new_stream(&tuple)?;

                    let tracker = self.streams.get_mut(&tuple).unwrap();

                    let res = tracker.add_event(&self.db, EventType::Socket, &sock);

                    if res.is_err() {
                        error!(
                            "Failed to trace socket: {:?}. Error: {}",
                            sock,
                            res.err().unwrap()
                        );
                    }
                },
                DBOperation::Cwnd(cwnd) => {
                    if cwnd.div != 0xFFFFFFFFu32.to_be_bytes() {
                        panic!("Misaligned CWND: {:?}. Something went horribly wrong during recording!",cwnd);
                    }

                    let tuple = cwnd.get_ip_tuple();
                    self.setup_new_stream(&tuple)?;

                    let tracker = self.streams.get_mut(&tuple).unwrap();

                    let res = tracker.add_event(&self.db, EventType::Cwnd, &cwnd);

                    if res.is_err() {
                        error!(
                            "Failed to trace socket: {:?}. Error: {}",
                            cwnd,
                            res.err().unwrap()
                        );
                    }
                },
                 //let a = sock.get_ip_tuple();
                  //println!("Socket: {:?}",sock.get_ip_tuple());
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
