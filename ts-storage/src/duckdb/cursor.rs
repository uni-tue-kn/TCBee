use std::marker::PhantomData;
use std::net::IpAddr;
use std::str::FromStr;

use duckdb::types::Value;
use duckdb::{Connection, Row, Rows, Statement, ToSql};
use ouroboros::self_referencing;

use crate::{DataPoint, DataValue, Flow, FlowAttribute, IpTuple, TimeSeries};

// Parses a DuckDB UNION column value of the form {'key': <value>} into DataValue.
fn parse_value(row: &Row) -> Option<DataValue> {
    let Ok(value) = row.get::<&str, Value>("value") else {
        return None;
    };
    let Value::Union(val) = value else {
        return None;
    };
    let Value::Text(val_text) = *val else {
        return None;
    };
    let Ok(val_type) = row.get::<&str, i16>("type") else {
        return None;
    };

    // Format is always "{'key': <value>}" — find the ': ' separator and read to the last '}'
    let colon_pos = val_text.find(": ")?;
    let raw = val_text[colon_pos + 2..val_text.len() - 1].trim();

    match val_type {
        DataValue::INT => Some(DataValue::Int(i64::from_str(raw).ok()?)),
        DataValue::FLOAT => Some(DataValue::Float(f64::from_str(raw).ok()?)),
        DataValue::BOOLEAN => Some(DataValue::Boolean(i16::from_str(raw).ok()? == 1)),
        DataValue::STRING => Some(DataValue::String(raw.to_string())),
        _ => None,
    }
}

pub trait DuckDBCursorStruct: Sized {
    fn from_row(row: &Row) -> Option<Self>;
}

impl DuckDBCursorStruct for Flow {
    fn from_row(row: &Row) -> Option<Self> {
        let Ok(id) = row.get::<&str, i64>("id") else {
            return None;
        };
        IpTuple::from_row(row).map(|tuple| Flow::new(id, tuple))
    }
}

impl DuckDBCursorStruct for DataPoint {
    fn from_row(row: &Row) -> Option<Self> {
        let Ok(timestamp) = row.get::<&str, f64>("timestamp") else {
            return None;
        };
        parse_value(row).map(|value| DataPoint { timestamp, value })
    }
}

impl From<DataValue> for Value {
    fn from(v: DataValue) -> Value {
        match v {
            DataValue::Boolean(val) => Value::Int(if val { 1 } else { 0 }),
            DataValue::Float(val) => Value::Double(val),
            DataValue::Int(val) => Value::BigInt(val),
            DataValue::String(val) => Value::Text(val),
        }
    }
}

impl DuckDBCursorStruct for TimeSeries {
    fn from_row(row: &Row) -> Option<Self> {
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
        DataValue::type_from_int(val_type)
            .ok()
            .map(|ts_type| TimeSeries::new(time_series_id, ts_type, flow_id, &name))
    }
}

impl DuckDBCursorStruct for FlowAttribute {
    fn from_row(row: &Row) -> Option<Self> {
        let Ok(name) = row.get::<&str, String>("name") else {
            return None;
        };
        parse_value(row).map(|value| FlowAttribute { name, value })
    }
}

impl DuckDBCursorStruct for IpTuple {
    fn from_row(row: &Row) -> Option<Self> {
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
        let Ok(src) = IpAddr::from_str(&src) else {
            return None;
        };
        let Ok(dst) = IpAddr::from_str(&dst) else {
            return None;
        };
        Some(IpTuple { src, dst, sport, dport, l4proto })
    }
}

// Self-referential inner struct: stmt is prepared from an external connection ('conn),
// and rows self-references stmt via ouroboros so both can be stored together.
// This is the key to lazy iteration without materialising the full result set.
#[self_referencing]
pub(crate) struct DuckDBCursorInner<'conn> {
    stmt: Statement<'conn>,
    #[borrows(mut stmt)]
    #[not_covariant]
    rows: Rows<'this>,
}

pub struct DuckDBCursor<'conn, T: DuckDBCursorStruct> {
    inner: DuckDBCursorInner<'conn>,
    _phantom: PhantomData<T>,
}

impl<'conn, T: DuckDBCursorStruct> DuckDBCursor<'conn, T> {
    /// Prepares `query` on the given connection, binds `param_vals`, and returns a
    /// cursor that iterates lazily over the result set one row at a time.
    pub fn new(
        conn: &'conn Connection,
        query: &str,
        param_vals: Vec<Value>,
    ) -> Result<Self, duckdb::Error> {
        let stmt = conn.prepare(query)?;
        let inner = DuckDBCursorInnerTryBuilder {
            stmt,
            rows_builder: |stmt: &mut Statement<'_>| {
                let param_refs: Vec<&dyn ToSql> =
                    param_vals.iter().map(|v| v as &dyn ToSql).collect();
                stmt.query(param_refs.as_slice())
            },
        }
        .try_build()?;
        Ok(Self { inner, _phantom: PhantomData })
    }
}

impl<T: DuckDBCursorStruct> Iterator for DuckDBCursor<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.with_rows_mut(|rows| {
            let row = rows.next().ok()??;
            T::from_row(row)
        })
    }
}
