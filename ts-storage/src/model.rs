//! Plain data types shared by the reader and the writer.

use std::net::IpAddr;

/// The 5-tuple that identifies a flow.
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct IpTuple {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: i64,
    pub dport: i64,
    // Should always be 6 since tool focuses on TCP
    pub l4proto: i64,
}

/// A TCP flow with its id in the database.
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

/// A connection that groups flows, such as an MPTCP connection and its subflows.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionInfo {
    pub id: i64,
    /// Protocol of the connection, e.g. "mptcp"
    pub kind: String,
    /// The protocol's identifier of the connection, for MPTCP the local token
    pub key: i64,
    /// Flow that holds the connection's own series, if it has any
    pub flow_id: Option<i64>,
    /// First and last time the connection was seen, ns since boot
    pub start_ts: i64,
    pub end_ts: i64,
}

/// A flow that belonged to a connection from `first_ts` to `last_ts`. A flow tuple can be
/// reused, so it may belong to several connections, one after the other.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionFlow {
    pub conn_id: i64,
    pub flow_id: i64,
    /// Number of the flow within the connection, for MPTCP the subflow id
    pub subflow_id: Option<i64>,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// One value of a series.
#[derive(Debug, Clone)]
pub enum DataValue {
    Int(i64),
    Float(f64),
    Boolean(bool),
    String(String),
}

impl DataValue {
    pub fn as_string(&self) -> String {
        match self {
            DataValue::Int(val) => val.to_string(),
            DataValue::Float(val) => val.to_string(),
            DataValue::Boolean(val) => {
                if *val {
                    "1".to_string()
                } else {
                    "0".to_string()
                }
            }
            DataValue::String(val) => val.clone(),
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        if let DataValue::Float(val) = self {
            Some(*val)
        } else {
            None
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        if let DataValue::Int(val) = self {
            Some(*val)
        } else {
            None
        }
    }

    pub fn type_as_string(&self) -> String {
        match self {
            DataValue::Int(_) => "Integer".to_string(),
            DataValue::Float(_) => "Float".to_string(),
            DataValue::Boolean(_) => "Boolean".to_string(),
            DataValue::String(_) => "String".to_string(),
        }
    }
}

/// A sample: `timestamp` in nanoseconds since boot, as `f64`.
#[derive(Debug)]
pub struct DataPoint {
    pub timestamp: f64,
    pub value: DataValue,
}
