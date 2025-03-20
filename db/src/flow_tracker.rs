use core::default;
use log::{error, info};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use ts_storage::{DataPoint, DataValue, Flow, IpTuple, TSDBInterface, TimeSeries};

use crate::{
    bindings::{sock::sock_trace_entry, tcp_packet::TcpPacket, tcp_probe::TcpProbe},
    db_writer::DBOperation,
};
const BUFFER_SIZE: usize = 10000;

pub const AF_INET: u16 = 2;

pub trait EventIndexer {
    // TODO: is there a way to do this cleaner?
    // First filed is always timestamp, second is address
    fn get_field(&self, index: usize) -> Option<DataValue>;
    fn get_default_field(&self, index: usize) -> DataValue;
    fn get_field_name(&self, index: usize) -> &str;
    fn get_ip_tuple(&self) -> IpTuple;
    fn get_max_index(&self) -> usize;
    fn get_timestamp(&self) -> f64;
    fn as_db_op(self) -> DBOperation;
    fn get_struct_length(&self) -> usize;
}
#[derive(Debug)]
pub struct TsTracker {
    ts: TimeSeries,
    events: Vec<DataPoint>,
    handled: usize,
    name: String,
}

impl TsTracker {
    pub fn new(
        db: &Box<dyn TSDBInterface + Send>,
        name: &str,
        flow: &Flow,
        ts_type: DataValue,
    ) -> TsTracker {
        let ts = db.create_time_series(&flow, name, ts_type).expect(&format!(
            "Failed to create {} TS for flow: {:?}",
            name, flow
        ));

        TsTracker {
            ts: ts,
            events: Vec::with_capacity(BUFFER_SIZE),
            handled: 0,
            name: name.to_string(),
        }
    }

    pub fn add_entry(
        &mut self,
        entry: DataPoint,
        db: &Box<dyn TSDBInterface + Send>,
    ) -> Result<(), Box<dyn Error>> {
        // Track number of entries handled
        self.handled = self.handled + 1;

        // If space is left then push entry, else write to db, clear and then write entry
        if self.events.len() <= BUFFER_SIZE {
            self.events.push(entry);
        } else {
            // TODO: if one of these inserts fail, it reverts the entire write!
            // Implement better error handling!
            let result = db.insert_multiple_points(&self.ts, &self.events)?;
            self.events.clear();
            self.events.push(entry);
        }
        Ok(())
    }

    pub fn flush(
        &mut self,
        flow: &Flow,
        db: &Box<dyn TSDBInterface + Send>,
    ) -> Result<(), Box<dyn Error>> {
        // Check if own buffer is currently empty
        if self.events.len() < 1 {
            // Special case, buffer was never filled
            // Delete time series as it does not contain any values
            if self.handled < 1 {
                // no events handled, delete time series
                info!(
                    "Deleting TS {} for flow {:?} due to no entries!",
                    self.name, flow.tuple
                );
                let res = db.delete_time_series(flow, &self.ts);

                if res.is_err() {
                    error!("Error on TS delete: {}",res.err().unwrap());
                } else {
                    info!("Done! {}",res.unwrap());
                }
            }
            return Ok(());
        }
        // Flush remaining events int oDB
        // TODO: error handling better
        let result = db.insert_multiple_points(&self.ts, &self.events)?;
        self.events.clear();
        Ok(())
    }
}

#[derive(Clone)]
pub enum EventType {
    Packet,
    TcpProbe,
    Socket
}

#[derive(Debug)]
pub struct FlowTracker {
    flow: Flow,
    packet_trackers: Vec<TsTracker>,
    probe_trackers: Vec<TsTracker>,
    sock_trackers: Vec<TsTracker>,
}

impl FlowTracker {
    pub fn new(db: &Box<dyn TSDBInterface + Send>, tuple: &IpTuple) -> FlowTracker {
        let flow = db.create_flow(tuple).expect("Failed to create flow entry!");
        let packet = TcpPacket::default();
        let probe = TcpProbe::default();
        let sock = sock_trace_entry::default();

        let packet_tracker = FlowTracker::create_time_series::<TcpPacket>(db, &flow, &packet);
        let probe_tracker = FlowTracker::create_time_series::<TcpProbe>(db, &flow, &probe);
        let sock_tracker = FlowTracker::create_time_series::<sock_trace_entry>(db, &flow, &sock);

        FlowTracker {
            flow: flow,
            packet_trackers: packet_tracker,
            probe_trackers: probe_tracker,
            sock_trackers: sock_tracker
        }
    }

    pub fn add_event<T: EventIndexer>(
        &mut self,
        db: &Box<dyn TSDBInterface + Send>,
        etype: EventType,
        event: &T,
    ) -> Result<(), Box<dyn Error>> {
        match etype {
            EventType::Packet => {
                let time = event.get_timestamp();

                for i in 0..=event.get_max_index() {

                    if let Some(value) = event.get_field(i) {
                        let entry = DataPoint {
                            timestamp: time,
                            value: value,
                        };
    
                        self.packet_trackers[i].add_entry(entry, db)?;
                    }

                    
                }
            }

            EventType::TcpProbe => {
                let time = event.get_timestamp();

                for i in 0..=event.get_max_index() {
                    if let Some(value) = event.get_field(i) {

                        let entry = DataPoint {
                            timestamp: time,
                            value: value,
                        };
    
                        self.probe_trackers[i].add_entry(entry, db)?;
                    }
                }
            },

            EventType::Socket => {
                let time = event.get_timestamp();

                for i in 0..=event.get_max_index() {
                    if let Some(value) = event.get_field(i) {

                        let entry = DataPoint {
                            timestamp: time,
                            value: value,
                        };
    
                        self.sock_trackers[i].add_entry(entry, db)?;
                    }
                }
            },
        }

        Ok(())
    }

    // TODO: this should use enum instead of the first event
    fn create_time_series<T: EventIndexer>(
        db: &Box<dyn TSDBInterface + Send>,
        flow: &Flow,
        event: &T,
    ) -> Vec<TsTracker> {
        // Vector to hold created time series trackers
        let mut trackers: Vec<TsTracker> = Vec::with_capacity(event.get_max_index() + 1);

        // Loop over number of fields
        for i in 0..=event.get_max_index() {
            trackers.push(TsTracker::new(
                &db,
                event.get_field_name(i),
                &flow,
                event.get_default_field(i),
            ));
        }
        trackers
    }

    pub fn flush(&mut self, db: &Box<dyn TSDBInterface + Send>) {
        for tracker in self.packet_trackers.iter_mut() {
            let res = tracker.flush(&self.flow, &db);
            if res.is_err() {
                error!(
                    "Failed flush packet trackers on {:?} - {}. Continuing...",
                    tracker.ts,
                    res.err().unwrap()
                )
            }
        }
        for tracker in self.probe_trackers.iter_mut() {
            let res = tracker.flush(&self.flow, &db);

            if res.is_err() {
                error!(
                    "Failed flush probe trackers on {:?} - {}. Continuing...",
                    tracker.ts,
                    res.err().unwrap()
                )
            }
        }

        for tracker in self.sock_trackers.iter_mut() {
            let res = tracker.flush(&self.flow, &db);

            if res.is_err() {
                error!(
                    "Failed flush sock trackers on {:?} - {}. Continuing...",
                    tracker.ts,
                    res.err().unwrap()
                )
            }
        }
    }
}
