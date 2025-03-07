// dummy implementation
// primarily used to provide means to debug and test
// operation of the module system

use iced::widget::canvas::Cache;
use rust_ts_storage::DataValue;

// used to generate random data
use rand::distr::{Distribution, Uniform};
use rand::rng;

use crate::modules::{
    backend::database_processor::trait_database_processor::PreProcessor,
    ui::lib_widgets::lib_graphs::{
        struct_flow_series_data::FlowSeriesData, struct_processed_plot_data::ProcessedPlotData,
    },
};

pub struct DummyProcessor {
    required_timeseries_as_string: Vec<String>,
}

impl Default for DummyProcessor {
    fn default() -> Self {
        DummyProcessor {
            required_timeseries_as_string: Vec::from([
                "ack_num".to_string(),
                "seq_num".to_string(),
                // "retransmission".to_string(),
            ]),
        }
    }
}

impl PreProcessor for DummyProcessor {
    fn receive_name(&self) -> String {
        "Dummy Processr".to_string()
    }

    fn receive_description(&self) -> String {
        "
This simple implementation does not much but add a new entry thats a line with a constant value throughout the whole timeline.
Its written to provide means to understand and implement new modules
    ".to_string()
    }

    fn create_new_time_series_from_plot_data(
        &self,
        plot_data: &ProcessedPlotData,
    ) -> Result<Vec<FlowSeriesData>, String> {
        // TODO: add constant value for each timestamp given by plot_data
        // create given FlowSeriesData from that
        let collection_of_series = &plot_data.point_collection;
        let maybe_first_series = collection_of_series.first();
        let first_series = match maybe_first_series {
            None => return Err("no series received".to_string()),
            Some(series) => series,
        };

        let timestamps = first_series.timestamps.clone();

        let mut num_thread = rng();
        let num_distribution = Uniform::new(40000000.0, 520000000.0).unwrap();
        let new_values: Vec<DataValue> = timestamps
            .iter()
            .map(|_| {
                let random_value = num_distribution.sample(&mut num_thread);
                DataValue::Float(random_value)
            })
            .collect();
        let new_flow_series = FlowSeriesData {
            data: new_values.clone(),
            name: "tst_rndm".to_string(),
            timestamps: timestamps,
            max_timestamp: first_series.max_timestamp,
            min_timestamp: first_series.min_timestamp,
            min_val: Some(DataValue::Float(30.0)),
            max_val: Some(DataValue::Float(0.0)),
            data_val_type: DataValue::Float(0.0),
            zoom_bounds: first_series.zoom_bounds.clone(),
            chart_height: first_series.chart_height,
            line_color: first_series.line_color,
            cache: Cache::new(),
        };
        Ok(Vec::from([new_flow_series]))
    }

    fn receive_required_timeseries(&self) -> Vec<String> {
        self.required_timeseries_as_string.clone()
    }
}
