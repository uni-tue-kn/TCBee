use crate::duckdb::DuckDBTSDB;
use crate::error::TSDBError;
use crate::sqlite::SQLiteTSDB;
use std::net::IpAddr;
use std::cmp::Eq;
use std::hash::Hash;

pub mod sqlite;
pub mod duckdb;
pub mod error;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct IpTuple {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: i64,
    pub dport: i64,
    // Should always be 6 since tool focuses on TCP
    pub l4proto: i64,
}

#[derive(Debug, Clone)]
pub struct TSBounds {
    pub xmax: f64,
    pub xmin: f64,
    pub ymax: Option<DataValue>,
    pub ymin: Option<DataValue>,
}

#[derive(Debug)]
pub struct Flow {
    pub id: i64,
    pub tuple: IpTuple,
}

impl Flow {
    pub fn new(id: i64, tuple: IpTuple) -> Flow {
        Flow { id, tuple }
    }
}

#[derive(Debug)]
pub struct FlowAttribute {
    pub name: String,
    pub value: DataValue,
}

#[derive(Debug, Clone)]
pub enum DataValue {
    Int(i64),
    Float(f64),
    Boolean(bool),
    String(String),
}

impl DataValue {
    pub(crate) const INT: i16 = 0;
    pub(crate) const FLOAT: i16 = 1;
    pub(crate) const BOOLEAN: i16 = 2;
    pub(crate) const STRING: i16 = 3;

    pub fn type_from_int(val: i16) -> Result<Self, TSDBError> {
        match val {
            DataValue::INT => Ok(DataValue::Int(0)),
            DataValue::FLOAT => Ok(DataValue::Float(0.0)),
            DataValue::BOOLEAN => Ok(DataValue::Boolean(false)),
            DataValue::STRING => Ok(DataValue::String("".to_string())),
            _ => Err(TSDBError::UnknownDataType { val }),
        }
    }

    pub fn type_to_int(&self) -> i16 {
        match self {
            DataValue::Int(_) => DataValue::INT,
            DataValue::Float(_) => DataValue::FLOAT,
            DataValue::Boolean(_) => DataValue::BOOLEAN,
            DataValue::String(_) => DataValue::STRING,
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            DataValue::Int(val) => val.to_string(),
            DataValue::Float(val) => val.to_string(),
            DataValue::Boolean(val) => if *val { "1".to_string() } else { "0".to_string() },
            DataValue::String(val) => val.clone(),
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        if let DataValue::Float(val) = self { Some(*val) } else { None }
    }

    pub fn as_int(&self) -> Option<i64> {
        if let DataValue::Int(val) = self { Some(*val) } else { None }
    }

    pub fn type_equal(&self, other: &DataValue) -> bool {
        self.type_to_int() == other.type_to_int()
    }

    pub fn type_as_string(&self) -> String {
        match self {
            DataValue::Int(_) => "Integer".to_string(),
            DataValue::Float(_) => "Float".to_string(),
            DataValue::Boolean(_) => "Boolean".to_string(),
            DataValue::String(_) => "String".to_string(),
        }
    }

    // SQLite-specific: maps the DataValue type to the corresponding column name
    pub(crate) fn column_name(&self) -> Result<&str, TSDBError> {
        match self.type_to_int() {
            DataValue::INT => Ok("value_integer"),
            DataValue::FLOAT => Ok("value_float"),
            DataValue::BOOLEAN => Ok("value_boolean"),
            DataValue::STRING => Ok("value_text"),
            _ => Err(TSDBError::UnknownDataType { val: self.type_to_int() }),
        }
    }
}

#[derive(Debug)]
pub struct DataPoint {
    pub timestamp: f64,
    pub value: DataValue,
}

#[derive(Debug, Clone)]
pub struct TimeSeries {
    pub id: i64,
    pub ts_type: DataValue,
    pub flow_id: i64,
    pub name: String,
}

impl TimeSeries {
    pub fn new(id: i64, ts_type: DataValue, flow_id: i64, name: &str) -> TimeSeries {
        TimeSeries { id, ts_type, flow_id, name: name.to_string() }
    }
}

#[derive(Debug)]
pub enum Condition {
    Greater(DataValue),
    Less(DataValue),
    Equal(DataValue),
    GreaterEqual(DataValue),
    LessEqual(DataValue),
}

impl ToString for Condition {
    fn to_string(&self) -> String {
        let op = match self {
            Condition::Greater(_) => "> ",
            Condition::Less(_) => "< ",
            Condition::Equal(_) => "= ",
            Condition::GreaterEqual(_) => ">= ",
            Condition::LessEqual(_) => "<= ",
        };

        let val = match self {
            Condition::Greater(v)
            | Condition::Less(v)
            | Condition::Equal(v)
            | Condition::GreaterEqual(v)
            | Condition::LessEqual(v) => v,
        };

        format!("{}{}", op, val.as_string())
    }
}

pub trait TSDBInterface {
    // --- FLOW CREATION AND MANAGEMENT
    fn create_flow(&self, tuple: &IpTuple) -> Result<Flow, TSDBError>;
    fn delete_flow(&self, flow: &Flow) -> Result<bool, TSDBError>;
    fn list_flows(&self) -> Result<Box<dyn Iterator<Item = Flow> + '_>, TSDBError>;
    fn get_flow(&self, tuple: &IpTuple) -> Result<Option<Flow>, TSDBError>;
    fn get_flow_by_id(&self, id: i64) -> Result<Option<Flow>, TSDBError>;

    // --- FLOW ATTRIBUTE CREATION AND MANAGEMENT
    fn get_flow_attribute(&self, flow: &Flow, name: &str) -> Result<FlowAttribute, TSDBError>;
    fn list_flow_attributes(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = FlowAttribute> + '_>, TSDBError>;
    fn add_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, TSDBError>;
    fn set_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, TSDBError>;
    fn delete_flow_attribute(&self, flow: &Flow, name: &str) -> Result<bool, TSDBError>;
    fn get_flow_attribute_by_id(&self, id: i64) -> Result<Option<FlowAttribute>, TSDBError>;

    // --- TIME SERIES CREATION AND MANAGEMENT
    fn create_time_series(
        &self,
        flow: &Flow,
        name: &str,
        ts_type: DataValue,
    ) -> Result<TimeSeries, TSDBError>;
    fn delete_time_series(
        &self,
        flow: &Flow,
        series: &TimeSeries,
    ) -> Result<bool, TSDBError>;
    fn list_time_series(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = TimeSeries> + '_>, TSDBError>;
    fn get_time_series_by_id(&self, id: i64) -> Result<Option<TimeSeries>, TSDBError>;
    fn get_time_series_bounds(&self, series: &TimeSeries) -> Result<TSBounds, TSDBError>;
    fn get_flow_bounds(&self, flow: &Flow) -> Result<TSBounds, TSDBError>;

    // --- DATA PER TIME SERIES CREATION AND MANAGEMENT
    fn get_data_points(
        &self,
        series: &TimeSeries,
    ) -> Result<Box<dyn Iterator<Item = DataPoint> + '_>, TSDBError>;
    fn get_data_points_in_range(
        &self,
        series: &TimeSeries,
        t_start: f64,
        t_end: f64,
    ) -> Result<Box<dyn Iterator<Item = DataPoint> + '_>, TSDBError>;
    fn insert_data_point(
        &self,
        series: &TimeSeries,
        point: &DataPoint,
    ) -> Result<bool, TSDBError>;
    fn insert_multiple_points(
        &self,
        series: &TimeSeries,
        points: &[DataPoint],
    ) -> Result<bool, TSDBError>;
    fn get_data_points_count(&self, series: &TimeSeries) -> Result<i64, TSDBError>;
}

pub enum DBBackend {
    SQLite(String),
    DuckDB(String),
}

pub fn database_factory(
    backend: DBBackend,
) -> Result<Box<dyn TSDBInterface + Send>, TSDBError> {
    match backend {
        DBBackend::SQLite(path) => Ok(Box::new(SQLiteTSDB::new(path)?)),
        DBBackend::DuckDB(path) => Ok(Box::new(DuckDBTSDB::new(path)?)),
    }
}
