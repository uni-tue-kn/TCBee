//  contains trate for implementing a processor for data from Flows and their series-data
// database_processor can:
//  - create new datapoints based on given flow-series-data
//  - modify the database with new elements / delete entries from database

use crate::{modules::backend::database_processor::plugin_upper_window::UpperWindow, DataValue, FlowSeriesData, ProcessedPlotData};
// ----- //
use std::slice::Iter;

use super::processor_dummy::DummyProcessor;

pub trait PreProcessor {
    // internal constants
    // const MODULE_NAME:str;
    // const MODULE_ID:i32;
    // const MODULE_DESCRIPTION:str;
    // const MODULE_REQUIRED_TIME_SERIES_NAMES:Vec<str>;

    fn receive_name(&self) -> String;

    /// returns description of module
    fn receive_description(&self) -> String;

    /// reteurns a Vector rcontaining string representation of the names for each time series required
    /// REQUIREMENT: must contain a valid name for a timeseries!
    fn receive_required_timeseries(&self) -> Vec<String>;

    fn receive_required_series_formatted(&self, collection_of_names: Vec<String>) -> String {
        let mut formatted_string_collection = String::new();

        for entry in collection_of_names {
            let formatted_line = format!("name of timeseries: {:?}", entry);
            formatted_string_collection =
                format!("{formatted_string_collection}\n{formatted_line}");
        }
        formatted_string_collection
    }

    // fn process_time_values( time_information: &ProcessedPlotData) -> ProcessedPlotData;
    /// takes ProcessedPlotData representing a single Flow and the required time_series values
    /// returns a vector of the newly generated Time-Series for the given Flow
    /// ASSUMPTION:the supplied database has not been modified yet
    fn create_new_time_series_from_plot_data(
        &self,
        plot_data: &ProcessedPlotData,
    ) -> Result<Vec<FlowSeriesData>, String>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProcessorImplementation {
    // None,
    DummyProcessor,
    UpperWindow
}
impl ToString for ProcessorImplementation {
    fn to_string(&self) -> String {
        match self {
            ProcessorImplementation::DummyProcessor => "Dummy Processor".to_string(),
            ProcessorImplementation::UpperWindow => "Upper TCP Window Number".to_string(),
            _ => "None selected".to_string(),
        }
    }
}
impl ProcessorImplementation {
    pub const ALL: &'static [Self] = &[Self::DummyProcessor, Self::UpperWindow];

    pub fn create_processor(&self) -> Box<dyn PreProcessor> {
        match self {
            Self::DummyProcessor => Box::new(DummyProcessor::default()),
            Self::UpperWindow => Box::new(UpperWindow::default())
        }
    }
}

//     pub fn iterator() -> Iter<'static, PreProcessor> {
//         ProcessorImplementation::ALL.iter()
//     }
// }
