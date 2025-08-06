use std::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TSDBError {
    #[error("Could not setup main table 'flows' in database. - Original Error : {orig_e}")]
    SetupError {
        orig_e: Box<dyn Error>
    },
    #[error("DB main table flows not setup, cannot perform any operations!")]
    NotSetupError,

    #[error("No FlowAttribute found for flow {id} - attribute {name}")]
    NoAttriuteError {
        id: i64,
        name: String
    },
    #[error("Unknown data type enum: {val}")]
    UnknownDataType {
        val: i16
    },
    #[error("Unknown time series ID: {ts_id}")]
    TimeSeriesNotFoundError {
        ts_id: i64
    },
    #[error("Could not parse info for time series ID: {ts_id}. DB entry may be corrupted!")]
    TimeSeriesReadError {
        ts_id: i64
    },
    #[error("Mismatch in type of data point and time series: {type1} vs {type2}")]
    DataPointTypeMismatchError {
        type1: String,
        type2: String
    },
    #[error("Supplied database type not implemented!")]
    DBTypeNotImplementedError,
    #[error("Could not read Flow ID of created flow. Possibly due to a faulty table setup!")]
    ReadFlowIDError,
    #[error("The supplied flow has no valid ID field!")]
    FlowNotSetup,
    #[error("Could not read ID of created time series. Possibly due to a faulty table setup!")]
    ReadTSIDError,
    #[error("The supplied time series has no valid ID field!")]
    TimeSeriesNotSetup,
    #[error("The queried TimeSeries does not have any values!")]
    TimeSeriesNoValue,
}
