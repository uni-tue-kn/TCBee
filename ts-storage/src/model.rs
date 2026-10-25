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

impl ConnectionInfo {
    /// `kind` of an MPTCP connection
    pub const KIND_MPTCP: &'static str = "mptcp";
}

/// A flow that belonged to a connection from `first_ts` to `last_ts`. A flow tuple can be
/// reused, so it may belong to several connections, one after the other.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionFlow {
    pub connection_id: i64,
    pub flow_id: i64,
    /// Number of the flow within the connection, for MPTCP the subflow id
    pub subflow_id: Option<i64>,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// The process that owned a flow from `ts` on: it opened the connection (the recorder's owner
/// records), or held its socket when the recording started. A flow may have several owners: a
/// tuple can be reused, and several processes can share a socket. Table `flow_owners`, which
/// databases written before owners were recorded do not have.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FlowOwner {
    pub flow_id: i64,
    /// When the process opened the connection, or when the snapshot of the existing connections
    /// was taken; ns since boot
    pub ts: i64,
    /// How the owner is known, one of the `SOURCE_*` constants
    pub source: String,
    pub pid: i64,
    pub uid: Option<i64>,
    /// Name of the process
    pub comm: String,
    /// Command line, the arguments joined by spaces; None if it is not known
    pub cmdline: Option<String>,
    /// Start of the process, ns since boot; with the pid it names the process
    pub start_time: Option<i64>,
    pub cgroup_id: Option<i64>,
    /// cgroup v2 path
    pub cgroup: Option<String>,
    /// Inode number of the network namespace of the socket
    pub netns: Option<i64>,
    /// A kernel thread opened the connection
    pub kthread: bool,
}

impl FlowOwner {
    /// The process connected the socket
    pub const SOURCE_CONNECT: &'static str = "connect";
    /// The process accepted the connection
    pub const SOURCE_ACCEPT: &'static str = "accept";
    /// The process held the socket when the recording started
    pub const SOURCE_SNAPSHOT: &'static str = "snapshot";
    /// The owner of the flow's connection: an MPTCP subflow that the path manager added
    pub const SOURCE_CONNECTION: &'static str = "connection";
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
