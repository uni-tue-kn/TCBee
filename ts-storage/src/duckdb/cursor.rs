use std::net::IpAddr;
use std::os::linux::raw;
use std::str::FromStr;
use std::str;
use std::{error::Error, marker::PhantomData};

use duckdb::arrow::array::{Datum, UnionArray};
use duckdb::types::ValueRef;
use duckdb::{types::Value, Connection, Row, Rows, Statement, ToSql};

use crate::{DataPoint, DataValue, Flow, FlowAttribute, IpTuple, TimeSeries};

fn parse_value(row: &Row) -> Option<DataValue> {
    // Value is of type "Union(Text("{'inum': 10}"))"
    // Thats the way the duckdb library does Unions I guess...
    let Ok(value) = row.get::<&str,Value>("value") else {
        return None;
    };
    // Get iner Union
    let Value::Union(val) = value else {
        return None;
    };
    // Read text from boxed Balue
    let Value::Text(val_text) = *val else {
        return None;
    };
    // Get value type
    let Ok(val_type) = row.get::<&str,i16>("type") else {
        return None;
    };

    // Parse text based on value typoe

    // TODO, the names for struct fields should be constants
    match val_type {
        DataValue::INT => {
            // "{'inum': 10}"
            // -> 9 chars (including whitespace) until value starts
            // -> split at } in remaining str and select first part
            // Result is: ' 10' -> Remove space with tr
            let raw_val = val_text[9..].split("}").next()?;

            Some(DataValue::Int(i64::from_str(raw_val).ok()?))
        },
        DataValue::FLOAT => {
            // "{'fnum': 10.0}"
            // -> 9 chars (including whitespace) until value starts
            // -> split at } in remaining str and select first part
            // Result is: '10.0'
            let raw_val = val_text[9..].split("}").next()?;

            Some(DataValue::Float(f64::from_str(raw_val).ok()?))
        },
        DataValue::BOOLEAN => {
            // "{'bool': 1}"
            // -> 9 chars (including whitespace) until value starts
            // -> split at } in remaining str and select first part
            // Result is: '1'
            let raw_val = val_text[9..].split("}").next()?;
            // bool::from_Str does not work as source is 1 for true and 0 for false
            // So just compare the int val to 1
            Some(DataValue::Boolean(i16::from_str(raw_val).ok()? == 1))
        },
        DataValue::STRING => {
            // TODO: this will cause problems if string contains }!

            // "{'str': aaa}"
            // -> 8 chars (including whitespace) until value starts
            // -> split at } in remaining str and select first part
            // Result is: 'aaa'
            let raw_val = val_text[9..].split("}").next()?;

            Some(DataValue::String(raw_val.to_string()))
        },
        // TODO This should return a library Error
        _ => panic!("Unknown type value!")
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

        IpTuple::from_row(row).map(|tuple| Flow::new_with_id(id, tuple))
    }
}

impl DuckDBCursorStruct for DataPoint {
    fn from_row(row: &Row) -> Option<Self> {
        let Ok(timestamp) = row.get::<&str, f64>("timestamp") else {
            return None;
        };

        // Parse UNION value
        let point_value = parse_value(row);

        point_value.map(|value| DataPoint { timestamp, value })
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

        value.map(|value| FlowAttribute { name, value })
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
pub struct DuckDBCursor<'a, T>
where
    T: DuckDBCursorStruct,
{
    rows: Rows<'a>,
    _phantom: PhantomData<T>,
}

impl<'a, T> DuckDBCursor<'a, T>
where
    T: DuckDBCursorStruct,
{
    pub fn new(rows: Rows<'a>) -> Self {
        Self {
            rows,
            _phantom: PhantomData,
        }
    }
}

impl<T> Iterator for DuckDBCursor<'_, T>
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
