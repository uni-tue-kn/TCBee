use crate::error::TSDBError;
use crate::sqlite::SQLiteTSDB;
use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;
use std::cmp::Eq;
use std::hash::Hash;

pub mod sqlite;
mod error;

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
    pub ymin: Option<DataValue>
}

#[derive(Debug)]
pub struct Flow {
    pub id: Option<i64>,
    pub tuple: IpTuple,
}
impl Flow {
    pub fn get_id(&self) -> Option<i64> {
        return self.id;
    }
    pub fn new(tuple: IpTuple) -> Flow {
        return Flow {
            id: None,
            tuple: tuple,
        };
    }
    pub fn new_with_id(id: i64, tuple: IpTuple) -> Flow {
        return Flow {
            id: Some(id),
            tuple: tuple,
        };
    }
}

#[derive(Debug)]
pub struct FlowAttribute {
    pub name: String,
    pub value: DataValue,
}

// Structs that represent time series data
// Todo: possible vectors?
#[derive(Debug, Clone)]
pub enum DataValue {
    Int(i64),
    Float(f64),
    Boolean(bool),
    String(String),
}

impl DataValue {
    pub fn type_from_int(val: i64) -> Result<Self, TSDBError> {
        match val {
            0 => Ok(DataValue::Int(0)),
            1 => Ok(DataValue::Float(0.0)),
            2 => Ok(DataValue::Boolean(false)),
            3 => Ok(DataValue::String("".to_string())),
            _ => Err(TSDBError::UnknownDataType { val: val }), // TODO: better error handling?
        }
    }
    pub fn type_to_int(&self) -> i64 {
        match self {
            DataValue::Int(_) => 0,
            DataValue::Float(_) => 1,
            DataValue::Boolean(_) => 2,
            DataValue::String(_) => 3,
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            DataValue::Int(val) => val.to_string(),
            DataValue::Float(val) => val.to_string(),
            DataValue::Boolean(val) => {
                if *val {
                    1.to_string()
                } else {
                    0.to_string()
                }
            }
            DataValue::String(val) => val.clone(),
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        if let DataValue::Float(val) = self {
            return Some(*val)
        } else {
            return None
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        if let DataValue::Int(val) = self {
            return Some(*val)
        } else {
            return None
        }
    }

    pub fn type_equal(&self, other: &DataValue) -> bool {
        return self.type_to_int() == other.type_to_int();
    }

    pub fn type_as_string(&self) -> String {
        match self {
            DataValue::Int(_) => String::from_str("Integer").unwrap(),
            DataValue::Float(_) => String::from_str("Float").unwrap(),
            DataValue::Boolean(_) => String::from_str("Boolean").unwrap(),
            DataValue::String(_) => String::from_str("String").unwrap(),
        }
    }
    pub fn column_name(&self) -> Result<&str, TSDBError> {
        match self.type_to_int() {
            0 => Ok("value_integer"),
            1 => Ok("value_float"),
            2 => Ok("value_boolean"),
            3 => Ok("value_text"),
            _ => Err(TSDBError::UnknownDataType { val: self.type_to_int() })
        }
    }
}

#[derive(Debug)]
pub struct DataPoint {
    pub timestamp: f64,
    pub value: DataValue,
}
#[derive(Debug)]
pub struct TimeSeries {
    pub id: Option<i64>,
    pub ts_type: DataValue,
    pub flow_id: i64,
    pub name: String,
}

impl TimeSeries {
    pub fn get_id(&self) -> Option<i64> {
        return self.id;
    }
    pub fn new(ts_type: DataValue, flow: &Flow, name: &str) -> TimeSeries {
        return TimeSeries {
            id: None,
            ts_type: ts_type,
            flow_id: flow.get_id().unwrap(),
            name: name.to_string(),
        };
    }
    pub fn new_with_id(id: i64, ts_type: DataValue, flow_id: i64, name: &str) -> TimeSeries {
        return TimeSeries {
            id: Some(id),
            ts_type: ts_type,
            flow_id: flow_id,
            name: name.to_string(),
        };
    }
}

// For conditional loading of data
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
        // TODO: this can be done prettier
        let str = match self {
            Condition::Greater(_) => "> ",
            Condition::Less(_) => "< ",
            Condition::Equal(_) => "= ",
            Condition::GreaterEqual(_) => ">= ",
            Condition::LessEqual(_) => "<= ",
        };

        let mut s = String::from_str(str).unwrap();

        // TODO: make prettier
        if let Condition::Greater(val)
        | Condition::Less(val)
        | Condition::Equal(val)
        | Condition::GreaterEqual(val)
        | Condition::LessEqual(val) = self
        {
            s.push_str(val.as_string().as_str());
        }

        s
    }
}

// Trait that defines functions supported by TS Database implementation
// TODO: move type of flow ID etc to type definition
// TODO: get flow by ID, delete flow by id?
// TODO: consume Flow object when deleting a flow to ensure it is not accessed naymore?
pub trait TSDBInterface {
    // --- FLOW CREATION AND MANAGEMENT
    fn create_flow(&self, tuple: &IpTuple) -> Result<Flow, Box<dyn Error>>;
    fn delete_flow(&self, flow: &Flow) -> Result<bool, Box<dyn Error>>;
    fn list_flows(&self) -> Result<Box<dyn Iterator<Item = Flow> + '_>, Box<dyn Error>>;
    fn get_flow(&self, tuple: &IpTuple) -> Result<Option<Flow>, Box<dyn Error>>;
    fn get_flow_by_id(&self, id: i64) -> Result<Option<Flow>, Box<dyn Error>>;

    // --- FLOW ATTRIBUTE CREATION AND MANAGEMENT
    fn get_flow_attribute(&self, flow: &Flow, name: &str) -> Result<FlowAttribute, Box<dyn Error>>;
    fn list_flow_attributes(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = FlowAttribute> + '_>, Box<dyn Error>>;
    fn add_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, Box<dyn Error>>;
    fn set_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, Box<dyn Error>>;
    fn delete_flow_attribute(&self, flow: &Flow, name: &str) -> Result<bool, Box<dyn Error>>;
    fn get_flow_attribute_by_id(&self, id: i64) -> Result<Option<FlowAttribute>, Box<dyn Error>>;

    // --- TIME SERIES CREATION AND MANAGEMENT
    fn create_time_series(
        &self,
        flow: &Flow,
        name: &str,
        ts_type: DataValue,
    ) -> Result<TimeSeries, Box<dyn Error>>;
    fn delete_time_series(&self, flow: &Flow, series: &TimeSeries) -> Result<bool, Box<dyn Error>>;
    fn list_time_series(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = TimeSeries> + '_>, Box<dyn Error>>;
    fn get_time_series_by_id(&self, id: i64) -> Result<Option<TimeSeries>, Box<dyn Error>>;
    fn get_time_series_bounds(&self, series: &TimeSeries) -> Result<TSBounds, Box<dyn Error>>;
    fn get_flow_bounds(&self, flow: &Flow) -> Result<TSBounds, Box<dyn Error>>;

    // --- DATA PER TIME SERIES CREATION AND MANAGEMENT
    // TODO: also implement function that allows WHERE conditions
    fn get_data_points(
        &self,
        series: &TimeSeries,
    ) -> Result<Box<dyn Iterator<Item = DataPoint> + '_>, Box<dyn Error>>;
    fn insert_data_point(
        &self,
        series: &TimeSeries,
        point: &DataPoint,
    ) -> Result<bool, Box<dyn Error>>;
    fn insert_multiple_points(
        &self,
        series: &TimeSeries,
        points: &Vec<DataPoint>,
    ) -> Result<bool, Box<dyn Error>>;
    fn get_data_points_count(&self, series: &TimeSeries) -> Result<i64, Box<dyn Error>>;

    /*
    fn delete_data_points(&self, flow: &Flow, name: String, conditions: Vec<Condition>) -> bool;
    // Allow direct query execution for special cases
    //  should not be used on a regular basis
    fn execute_query(&self) -> Box<dyn TSDBCursor>;
    */
}

pub enum DBBackend {
    SQLite(String),
}

pub fn database_factory<T: TSDBInterface>(
    backend: DBBackend,
) -> Result<Box<dyn TSDBInterface + Send>, Box<dyn Error>> {
    match backend {
        DBBackend::SQLite(path) => Ok(Box::new(SQLiteTSDB::new(path)?)),
        _ => Err(Box::new(TSDBError::DBTypeNotImplementedError)), // Default case for future implementations
    }
}
