use std::marker::PhantomData;
use std::net::IpAddr;
use std::str::FromStr;

use duckdb::{types::Value, Row, Rows, Statement};

use crate::{DataPoint, DataValue, Flow, FlowAttribute, IpTuple, TimeSeries};

fn parse_value(row: &Row) -> Option<DataValue> {
    // Parse UNION to corresponding type
    let Ok(value_type) = row.get::<&str, i16>("value_type") else {
        return None;
    };

    match value_type {
        DataValue::INT => {
            let Ok(value) = row.get::<&str, i64>("value") else {
                return None;
            };
            Some(DataValue::Int(value))
        }
        DataValue::STRING => {
            let Ok(value) = row.get::<&str, String>("value") else {
                return None;
            };
            Some(DataValue::String(value))
        }
        DataValue::FLOAT => {
            let Ok(value) = row.get::<&str, f64>("value") else {
                return None;
            };
            Some(DataValue::Float(value))
        }
        DataValue::BOOLEAN => {
            let Ok(value) = row.get::<&str, bool>("value") else {
                return None;
            };
            Some(DataValue::Boolean(value))
        }
        val => panic!("Invalid column type: {}", val), // THis should never be reached
    }
}

pub trait DuckDBCursorStruct: Sized {
    fn from_row(row: &Row) -> Option<Self>;
}

impl DuckDBCursorStruct for Flow {
    fn from_row(row: &Row) -> Option<Self> {
        // Get Flow ID
        let Ok(id) = row.get::<&str, i64>("id") else {
            return None;
        };

        if let Some(tuple) = IpTuple::from_row(row) {
            Some(Flow::new_with_id(id, tuple))
        } else {
            None // No IpTuple to be parsed
        }
    }
}

impl DuckDBCursorStruct for DataPoint {
    fn from_row(row: &Row) -> Option<Self> {
        let Ok(timestamp) = row.get::<&str, f64>("timestamp") else {
            return None;
        };

        // Parse UNION value
        let point_value = parse_value(row);

        if let Some(value) = point_value {
            Some(DataPoint { timestamp, value })
        } else {
            None
        }
    }
}

// From DataValue into sqlite::value
impl Into<Value> for DataValue {
    fn into(self) -> Value {
        match self {
            DataValue::Boolean(val) => (if val { 1 } else { 0 }).into(),
            DataValue::Float(val) => val.into(),
            DataValue::Int(val) => val.into(),
            DataValue::String(val) => val.into(),
        }
    }
}

impl DuckDBCursorStruct for TimeSeries {
    fn from_row(row: &Row) -> Option<Self> {
        // Parse columns
        let Ok(name) = row.get::<&str, String>("name") else {
            return None;
        };
        let Ok(flow_id) = row.get::<&str, i64>("flow_id") else {
            return None;
        };
        let Ok(time_series_id) = row.get::<&str, i64>("time_series_id") else {
            return None;
        };
        let Ok(val_type) = row.get::<&str, i16>("type") else {
            return None;
        };

        if let Ok(ts_type) = DataValue::type_from_int(val_type) {
            Some(TimeSeries::new_with_id(
                time_series_id,
                ts_type,
                flow_id,
                &name,
            ))
        } else {
            None
        }
    }
}

impl DuckDBCursorStruct for FlowAttribute {
    fn from_row(row: &Row) -> Option<Self> {
        let Ok(name) = row.get::<&str, String>("name") else {
            return None;
        };

        // Parse UNION "value"
        let value = parse_value(row);

        if let Some(value) = value {
            Some(FlowAttribute {
                name, 
                value,
            })
        } else {
            None
        }
    }
}

impl DuckDBCursorStruct for IpTuple {
    fn from_row(row: &Row) -> Option<Self> {
        // TODO: can this be cleaner?
        // Get values from row
        let Ok(src) = row.get::<&str, String>("src") else {
            return None;
        };
        let Ok(dst) = row.get::<&str, String>("dst") else {
            return None;
        };
        
        let Ok(sport) = row.get::<&str, i64>("sport") else {
            return None;
        };
        let Ok(dport) = row.get::<&str, i64>("dport") else {
            return None;
        };

        let Ok(l4proto) = row.get::<&str, i64>("l4proto") else {
            return None;
        };

        // Convert strings to IP address
        let Ok(src) = IpAddr::from_str(&src) else {
            return None;
        };
        let Ok(dst) = IpAddr::from_str(&dst) else {
            return None;
        };

        Some(IpTuple {
            src,
            dst,
            sport,
            dport,
            l4proto,
        })
    }

}


pub struct DuckDBCursor<'row, T>
where
    T: DuckDBCursorStruct,
{
    rows: Rows<'row>,
    _phantom: PhantomData<T>,
}

impl<'row, T> DuckDBCursor<'row, T>
where
    T: DuckDBCursorStruct,
{
    // Constructor for struct A
    pub fn new(rows: Rows<'row>) -> Self {
        Self {
            rows,
            _phantom: PhantomData,
        }
    }
}

impl<'stmt, T> Iterator for DuckDBCursor<'stmt, T>
where
    T: DuckDBCursorStruct,
{
    // Type of every iterator item
    type Item = T;

    // Get next element by moving cursor
    fn next(&mut self) -> Option<Self::Item> {
        // Load next road
        let Ok(row_option) = self.rows.next() else {
            return None;
        };

        // row_option is None when all rows have been handled!
        let row = row_option?;

        // Parse row based on given generic T
        let parsed: Option<Self::Item> = Self::Item::from_row(row);

        // Return parsed value
        // Is already wrapped as option
        parsed
    }
}
