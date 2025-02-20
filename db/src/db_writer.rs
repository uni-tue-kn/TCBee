use std::{collections::HashMap, error::Error};

use log::error;
use ts_storage::{database_factory, sqlite::SQLiteTSDB, DBBackend, IpTuple, TSDBInterface};
use tokio::sync::mpsc::Receiver;

use crate::{bindings::{tcp_packet::TcpPacket, tcp_probe::TcpProbe}, flow_tracker::{EventIndexer, EventType, FlowTracker}};

#[derive(Debug)]
pub enum DBOperation {
    Packet(TcpPacket),
    Probe(TcpProbe)
}


pub struct DBWriter {
    db: Box<dyn TSDBInterface + Send>,
    streams: HashMap<IpTuple, FlowTracker>,
    rx: Receiver<DBOperation>
}

impl DBWriter {
    pub fn new(file: &str, rx: Receiver<DBOperation>) -> Result<DBWriter, Box<dyn Error>> {
        let db: Box<dyn TSDBInterface + Send> =
            database_factory::<SQLiteTSDB>(DBBackend::SQLite(file.to_string()))?;


        let streams: HashMap<IpTuple, FlowTracker> = HashMap::new();

        Ok(DBWriter {
            db: db,
            streams: streams,
            rx: rx
        })
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {

        // Time of first entry, will be used to normalize all other times
        // TODO: if order is scrambled, does this fail?
        let time_base: f64 = 0.0;

        while let Some(event) = self.rx.blocking_recv() {

            match event {
                DBOperation::Packet(data) => {
                    if data.div != 0xFFFFFFFF {
                        panic!("Misaligned PACKET: {:?}. Something went horribly wrong during recording!",data);
                    }

                    let tuple = data.get_ip_tuple();

                    // Insert stream if not known
                    if !self.streams.contains_key(&tuple) {
                        let new_tracker = FlowTracker::new(&self.db, &tuple);

                        // TODO: remove unwrap, error handling!
                        self.streams.insert(tuple.clone(), new_tracker);
                    } 

                    let tracker = self.streams.get_mut(&tuple).unwrap();

                    let res = tracker.add_event(&self.db, EventType::Packet, &data);

                    if res.is_err() {
                        error!("Failed to trace packet: {:?}. Error: {}",data,res.err().unwrap());
                    }

                    

                },
                DBOperation::Probe(data) => {
                    if data.div != 0xFFFFFFFF {
                        panic!("Misaligned PROBE: {:?}. Something went horribly wrong during recording!",data);
                    }

                    let tuple = data.get_ip_tuple();

                    // Insert stream if not known
                    if !self.streams.contains_key(&tuple) {
                        let new_tracker = FlowTracker::new(&self.db, &tuple);

                        // TODO: remove unwrap, error handling!
                        self.streams.insert(tuple.clone(), new_tracker);
                    } 

                    let tracker = self.streams.get_mut(&tuple).unwrap();

                    let res = tracker.add_event(&self.db, EventType::TcpProbe, &data);

                    if res.is_err() {
                        error!("Failed to trace packet: {:?}. Error: {}",data,res.err().unwrap());
                    }

                    //println!("Probe {:?}",data.ssthresh);

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
