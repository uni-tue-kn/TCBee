use duckdb::types::Value;
use duckdb::{params, Appender, Connection};

use crate::duckdb::cursor::{DuckDBCursor, DuckDBCursorStruct};
use crate::duckdb::queries::{
    COUNT_TIME_SERIES_DATA, CREATE_FLOW_ATTRIBUTE_ID_SEQ, CREATE_FLOW_ATTRIBUTE_TABLE,
    CREATE_FLOW_ID_SEQ, CREATE_FLOW_TABLE, CREATE_TIME_SERIES_DATA_TABLE,
    CREATE_TIME_SERIES_TABLE, CREATE_TS_ID_SEQ, DELETE_FLOW_ATTRIBUTE_BY_NAME,
    DELETE_FLOW_BY_TUPLE, DELETE_TIME_SERIES_BY_NAME, DELETE_TIME_SERIES_DATA_BY_SERIES,
    INSERT_FLOW, INSERT_FLOW_ATTRIBUTE, INSERT_TIME_SERIES, INSERT_TIME_SERIES_DATA,
    SELECT_ALL_FLOWS, SELECT_FIRST_TIME_SERIES_DATA, SELECT_FLOW_ATTRIBUTES_BY_FLOW_ID,
    SELECT_FLOW_ATTRIBUTE_BY_ID, SELECT_FLOW_ATTRIBUTE_BY_NAME, SELECT_FLOW_BY_ID,
    SELECT_FLOW_BY_TUPLE, SELECT_HIGHEST_TIME_SERIES_DATA, SELECT_LAST_TIME_SERIES_DATA,
    SELECT_LOWEST_TIME_SERIES_DATA, SELECT_TIME_SERIES_BY_FLOW, SELECT_TIME_SERIES_BY_FLOW_AND_NAME,
    SELECT_TIME_SERIES_BY_ID, SELECT_TIME_SERIES_DATA_BY_SERIES, SELECT_TIME_SERIES_DATA_IN_RANGE,
    TIME_SERIES_DATA_TABLE,
};
use crate::duckdb::DuckDBTSDB;
use crate::error::TSDBError;
use crate::{DataPoint, DataValue, Flow, FlowAttribute, IpTuple, TSBounds, TSDBInterface, TimeSeries};

use std::f64;

// Fetches the first matching row directly on the provided connection.
// Single-row lookups don't need the lazy cursor since no iterator is returned.
fn get_entry<T: DuckDBCursorStruct>(
    param_vals: Vec<Value>,
    query: &str,
    conn: &Connection,
) -> Result<Option<T>, TSDBError> {
    let mut stmt = conn.prepare(query)?;
    let param_refs: Vec<&dyn duckdb::ToSql> =
        param_vals.iter().map(|v| v as &dyn duckdb::ToSql).collect();
    let mut rows = stmt.query(param_refs.as_slice())?;
    // Row is processed immediately before stmt/rows go out of scope — no lifetime issue.
    Ok(rows.next()?.and_then(|row| T::from_row(row)))
}

fn val_to_union(value: &DataValue) -> String {
    match value.type_to_int() {
        DataValue::INT => format!("{{'inum': {}}}", value.as_string()),
        DataValue::FLOAT => format!("{{'fnum': {}}}", value.as_string()),
        DataValue::STRING => format!("{{'str': {}}}", value.as_string()),
        DataValue::BOOLEAN => format!("{{'bool': {}}}", value.as_string()),
        _ => panic!("Unknown value type!"),
    }
}

impl DuckDBTSDB {
    pub fn new(path: String) -> Result<Self, TSDBError> {
        let conn = duckdb::Connection::open(&path)?;
        let mut db = DuckDBTSDB { path, conn, is_setup: false };
        db.setup().map_err(|e: TSDBError| TSDBError::SetupError { orig_e: Box::new(e) })?;
        db.is_setup = true;
        Ok(db)
    }

    fn setup(&self) -> Result<(), TSDBError> {
        self.conn.execute(CREATE_FLOW_ID_SEQ, [])?;
        self.conn.execute(CREATE_FLOW_ATTRIBUTE_ID_SEQ, [])?;
        self.conn.execute(CREATE_TS_ID_SEQ, [])?;
        self.conn.execute(CREATE_FLOW_TABLE, params![])?;
        self.conn.execute(CREATE_FLOW_ATTRIBUTE_TABLE, params![])?;
        self.conn.execute(CREATE_TIME_SERIES_TABLE, params![])?;
        self.conn.execute(CREATE_TIME_SERIES_DATA_TABLE, params![])?;
        Ok(())
    }

    fn check_setup(&self) -> Result<(), TSDBError> {
        if !self.is_setup {
            return Err(TSDBError::NotSetupError);
        }
        Ok(())
    }

    fn lazy_cursor<T: DuckDBCursorStruct>(
        &self,
        query: &str,
        param_vals: Vec<Value>,
    ) -> Result<DuckDBCursor<'_, T>, TSDBError> {
        Ok(DuckDBCursor::<T>::new(&self.conn, query, param_vals)?)
    }
}

impl TSDBInterface for DuckDBTSDB {
    fn get_flow(&self, tuple: &IpTuple) -> Result<Option<Flow>, TSDBError> {
        self.check_setup()?;
        get_entry(
            vec![
                Value::Text(tuple.src.to_string()),
                Value::Text(tuple.dst.to_string()),
                Value::BigInt(tuple.sport),
                Value::BigInt(tuple.dport),
                Value::BigInt(tuple.l4proto),
            ],
            SELECT_FLOW_BY_TUPLE,
            &self.conn,
        )
    }

    fn get_flow_by_id(&self, id: i64) -> Result<Option<Flow>, TSDBError> {
        self.check_setup()?;
        get_entry(vec![Value::BigInt(id)], SELECT_FLOW_BY_ID, &self.conn)
    }

    fn get_flow_attribute_by_id(&self, id: i64) -> Result<Option<FlowAttribute>, TSDBError> {
        self.check_setup()?;
        get_entry(vec![Value::BigInt(id)], SELECT_FLOW_ATTRIBUTE_BY_ID, &self.conn)
    }

    fn get_time_series_by_id(&self, id: i64) -> Result<Option<TimeSeries>, TSDBError> {
        self.check_setup()?;
        get_entry(vec![Value::BigInt(id)], SELECT_TIME_SERIES_BY_ID, &self.conn)
    }

    fn create_flow(&self, tuple: &IpTuple) -> Result<Flow, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(INSERT_FLOW)?;
        let tuple_params = params![
            tuple.src.to_string(),
            tuple.dst.to_string(),
            tuple.sport,
            tuple.dport,
            tuple.l4proto
        ];
        stmt.execute(tuple_params)?;

        get_entry(
            vec![
                Value::Text(tuple.src.to_string()),
                Value::Text(tuple.dst.to_string()),
                Value::BigInt(tuple.sport),
                Value::BigInt(tuple.dport),
                Value::BigInt(tuple.l4proto),
            ],
            SELECT_FLOW_BY_TUPLE,
            &self.conn,
        )?
        .ok_or(TSDBError::ReadFlowIDError)
    }

    fn delete_flow(&self, flow: &Flow) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let tuple = &flow.tuple;
        let mut stmt = self.conn.prepare(DELETE_FLOW_BY_TUPLE)?;
        let p = params![
            tuple.src.to_string(),
            tuple.dst.to_string(),
            tuple.sport,
            tuple.dport,
            tuple.l4proto
        ];
        stmt.execute(p)?;
        Ok(true)
    }

    fn list_flows(&self) -> Result<Box<dyn Iterator<Item = Flow> + '_>, TSDBError> {
        self.check_setup()?;
        Ok(Box::new(self.lazy_cursor::<Flow>(SELECT_ALL_FLOWS, vec![])?))
    }

    fn get_flow_attribute(&self, flow: &Flow, name: &str) -> Result<FlowAttribute, TSDBError> {
        self.check_setup()?;
        get_entry::<FlowAttribute>(
            vec![Value::BigInt(flow.id), Value::Text(name.to_owned())],
            SELECT_FLOW_ATTRIBUTE_BY_NAME,
            &self.conn,
        )?
        .ok_or(TSDBError::NoAttributeError { name: name.to_owned(), id: flow.id })
    }

    fn list_flow_attributes(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = FlowAttribute> + '_>, TSDBError> {
        self.check_setup()?;
        Ok(Box::new(self.lazy_cursor::<FlowAttribute>(
            SELECT_FLOW_ATTRIBUTES_BY_FLOW_ID,
            vec![Value::BigInt(flow.id)],
        )?))
    }

    fn add_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let attr_value = &attribute.value;
        let mut stmt = self.conn.prepare(INSERT_FLOW_ATTRIBUTE)?;
        let p = params![
            flow.id,
            attribute.name,
            val_to_union(attr_value),
            attr_value.type_to_int()
        ];
        stmt.execute(p)?;
        Ok(true)
    }

    fn set_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, TSDBError> {
        self.check_setup()?;
        self.delete_flow_attribute(flow, &attribute.name)?;
        self.add_flow_attribute(flow, attribute)
    }

    fn delete_flow_attribute(&self, flow: &Flow, name: &str) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(DELETE_FLOW_ATTRIBUTE_BY_NAME)?;
        stmt.execute(params![flow.id, name])?;
        Ok(true)
    }

    fn create_time_series(
        &self,
        flow: &Flow,
        name: &str,
        ts_type: DataValue,
    ) -> Result<TimeSeries, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(INSERT_TIME_SERIES)?;
        stmt.execute(params![flow.id, name, ts_type.type_to_int()])?;

        get_entry::<TimeSeries>(
            vec![
                Value::BigInt(flow.id),
                Value::Text(name.to_owned()),
                Value::SmallInt(ts_type.type_to_int()),
            ],
            SELECT_TIME_SERIES_BY_FLOW_AND_NAME,
            &self.conn,
        )?
        .ok_or(TSDBError::ReadTSIDError)
    }

    fn delete_time_series(&self, flow: &Flow, series: &TimeSeries) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let mut data_stmt = self.conn.prepare(DELETE_TIME_SERIES_DATA_BY_SERIES)?;
        data_stmt.execute(params![series.id])?;

        let mut stmt = self.conn.prepare(DELETE_TIME_SERIES_BY_NAME)?;
        stmt.execute(params![flow.id, series.name])?;
        Ok(true)
    }

    fn list_time_series(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = TimeSeries> + '_>, TSDBError> {
        self.check_setup()?;
        Ok(Box::new(self.lazy_cursor::<TimeSeries>(
            SELECT_TIME_SERIES_BY_FLOW,
            vec![Value::BigInt(flow.id)],
        )?))
    }

    fn get_data_points(
        &self,
        series: &TimeSeries,
    ) -> Result<Box<dyn Iterator<Item = DataPoint> + '_>, TSDBError> {
        self.check_setup()?;
        Ok(Box::new(self.lazy_cursor::<DataPoint>(
            SELECT_TIME_SERIES_DATA_BY_SERIES,
            vec![Value::BigInt(series.id)],
        )?))
    }

    fn get_data_points_in_range(
        &self,
        series: &TimeSeries,
        t_start: f64,
        t_end: f64,
    ) -> Result<Box<dyn Iterator<Item = DataPoint> + '_>, TSDBError> {
        self.check_setup()?;
        Ok(Box::new(self.lazy_cursor::<DataPoint>(
            SELECT_TIME_SERIES_DATA_IN_RANGE,
            vec![
                Value::BigInt(series.id),
                Value::Double(t_start),
                Value::Double(t_end),
            ],
        )?))
    }

    fn insert_data_point(
        &self,
        series: &TimeSeries,
        point: &DataPoint,
    ) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let ts_type = &series.ts_type;
        if !ts_type.type_equal(&point.value) {
            return Err(TSDBError::DataPointTypeMismatchError {
                type1: point.value.type_as_string(),
                type2: ts_type.type_as_string(),
            });
        }
        let union_string = val_to_union(&point.value);
        let mut stmt = self.conn.prepare(INSERT_TIME_SERIES_DATA)?;
        stmt.execute(params![series.id, point.timestamp, union_string, ts_type.type_to_int()])?;
        Ok(true)
    }

    fn insert_multiple_points(
        &self,
        series: &TimeSeries,
        points: &[DataPoint],
    ) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let mut appender: Appender = self.conn.appender(TIME_SERIES_DATA_TABLE)?;
        for p in points {
            appender.append_row(params![
                series.id,
                p.timestamp,
                val_to_union(&p.value),
                p.value.type_to_int()
            ])?;
        }
        appender.flush()?;
        Ok(true)
    }

    fn get_time_series_bounds(&self, series: &TimeSeries) -> Result<TSBounds, TSDBError> {
        self.check_setup()?;
        let id = series.id;

        let xmin = get_entry::<DataPoint>(
            vec![Value::BigInt(id)],
            SELECT_FIRST_TIME_SERIES_DATA,
            &self.conn,
        )?
        .ok_or(TSDBError::TimeSeriesNoValue)?
        .timestamp;

        let xmax = get_entry::<DataPoint>(
            vec![Value::BigInt(id)],
            SELECT_LAST_TIME_SERIES_DATA,
            &self.conn,
        )?
        .ok_or(TSDBError::TimeSeriesNoValue)?
        .timestamp;

        let mut bounds = TSBounds { xmin, xmax, ymin: None, ymax: None };

        match series.ts_type {
            DataValue::Boolean(_) | DataValue::String(_) => return Ok(bounds),
            _ => (),
        }

        let ymin = get_entry::<DataPoint>(
            vec![Value::BigInt(id)],
            SELECT_LOWEST_TIME_SERIES_DATA,
            &self.conn,
        )?
        .ok_or(TSDBError::TimeSeriesNoValue)?
        .value;

        let ymax = get_entry::<DataPoint>(
            vec![Value::BigInt(id)],
            SELECT_HIGHEST_TIME_SERIES_DATA,
            &self.conn,
        )?
        .ok_or(TSDBError::TimeSeriesNoValue)?
        .value;

        bounds.ymin = Some(ymin);
        bounds.ymax = Some(ymax);
        Ok(bounds)
    }

    fn get_data_points_count(&self, series: &TimeSeries) -> Result<i64, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(COUNT_TIME_SERIES_DATA)?;
        let mut rows = stmt.query(params![series.id])?;
        if let Some(row) = rows.next()? {
            Ok(row.get(0)?)
        } else {
            Ok(0)
        }
    }

    fn get_flow_bounds(&self, flow: &Flow) -> Result<TSBounds, TSDBError> {
        let mut bounds = TSBounds { xmax: f64::MIN, xmin: f64::MAX, ymin: None, ymax: None };
        let mut found = false;

        let mut flow_ts = self.list_time_series(flow)?;
        while let Some(ts) = flow_ts.next() {
            found = true;
            let new_bounds = self.get_time_series_bounds(&ts)?;
            bounds.xmax = bounds.xmax.max(new_bounds.xmax);
            bounds.xmin = bounds.xmin.min(new_bounds.xmin);
        }

        if !found {
            return Err(TSDBError::TimeSeriesNotFoundError { ts_id: flow.id });
        }

        Ok(bounds)
    }
}
