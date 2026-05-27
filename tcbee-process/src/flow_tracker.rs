use log::{error, info};
use std::{collections::HashMap, error::Error, iter::Map};
use ts_storage::{DataPoint, DataValue, Flow, IpTuple, TSDBInterface, TimeSeries};

use crate::{
    bindings::{
        cwnd::cwnd_trace_entry, sock::sock_trace_entry, tcp_packet::TcpPacket, tcp_probe::TcpProbe,
    },
    db_writer::DBOperation,
};
const BUFFER_SIZE: usize = 100_000;

pub const AF_INET: u16 = 2;

#[derive(Debug)]
pub struct TimeSeriesWriter {
    series: TimeSeries,
    buffer: Vec<DataPoint>,
}

impl TimeSeriesWriter {
    pub fn new(series: TimeSeries, capacity: usize) -> TimeSeriesWriter {
        TimeSeriesWriter {
            buffer: Vec::with_capacity(capacity),
            series,
        }
    }

    pub fn add_point(&mut self, point: DataPoint) {
        self.buffer.push(point);
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    // TODO: better error handling....
    pub fn flush(&mut self, db: &Box<dyn TSDBInterface + Send>) {
        let _result = db
            .insert_multiple_points(&self.series, &self.buffer)
            .unwrap_or_else(|e| panic!("Failed flush for {:?}: {}", self.series, e));
        self.buffer.clear();
    }
}

#[derive(Debug)]
pub struct FlowTracker {
    flow: Flow,
    time_series_collection: HashMap<String, TimeSeriesWriter>,
}

impl FlowTracker {
    pub fn new(db: &Box<dyn TSDBInterface + Send>, tuple: &IpTuple) -> FlowTracker {
        let flow = db.create_flow(tuple).expect("Failed to create flow entry!");

        // IDEA:
        // Each struct has a name for each filed in EventIndexer.
        // We create a map where the name is the key and a buffered writer is the value
        // This way, we can have a generalized handling, independent of which source trace struct is used
        // TODO: Does this make performance go down, can it be improved?
        let time_series_collection: HashMap<String, TimeSeriesWriter> = HashMap::new();

        FlowTracker {
            flow,
            time_series_collection,
        }
    }

    pub fn add_event(
        &mut self,
        db: &Box<dyn TSDBInterface + Send>,
        event: DBOperation,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(writer) = self.time_series_collection.get_mut(&event.time_series) {
            writer.add_point(event.data_point);

            if writer.len() == BUFFER_SIZE {
                writer.flush(db);
            }
        } else {
            // Not recorded yet, create new and insert
            let value = event.data_point.value.clone();

            let series = db.create_time_series(&self.flow, &event.time_series, value)?;
            let mut writer = TimeSeriesWriter::new(series, BUFFER_SIZE);
            writer.add_point(event.data_point);

            self.time_series_collection
                .insert(event.time_series, writer);
        }
        Ok(())
    }

    pub fn flush(&mut self, db: &Box<dyn TSDBInterface + Send>) {
        for (_name, writer) in self.time_series_collection.iter_mut() {
            writer.flush(db);
        }
    }
}
