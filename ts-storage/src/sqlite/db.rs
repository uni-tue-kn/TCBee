use crate::{DataPoint, DataValue, Flow, FlowAttribute, IpTuple, TSDBInterface, TimeSeries, TSBounds};
use crate::sqlite::cursor::SQLiteCursor;
use crate::sqlite::queries::{
    COUNT_TIME_SERIES_DATA, CREATE_FLOW_ATTRIBUTE_TABLE, CREATE_FLOW_TABLE,
    CREATE_TIME_SERIES_DATA_TABLE, CREATE_TIME_SERIES_TABLE, DELETE_FLOW_ATTRIBUTE_BY_NAME,
    DELETE_FLOW_BY_TUPLE, DELETE_TIME_SERIES_BY_NAME, INSERT_FLOW, INSERT_TIME_SERIES,
    PRAGMA_FOREIGN_KEYS, SELECT_ALL_FLOWS, SELECT_FIRST_TIME_SERIES_DATA,
    SELECT_FLOW_ATTRIBUTE_BY_ID, SELECT_FLOW_ATTRIBUTE_BY_NAME, SELECT_FLOW_ATTRIBUTES_BY_FLOW_ID,
    SELECT_FLOW_BY_ID, SELECT_FLOW_BY_TUPLE, SELECT_HIGHEST_FLOAT_TIME_SERIES_DATA,
    SELECT_HIGHEST_INT_TIME_SERIES_DATA, SELECT_LAST_TIME_SERIES_DATA,
    SELECT_LOWEST_FLOAT_TIME_SERIES_DATA, SELECT_LOWEST_INT_TIME_SERIES_DATA,
    SELECT_TIME_SERIES_BY_FLOW, SELECT_TIME_SERIES_BY_FLOW_AND_NAME, SELECT_TIME_SERIES_BY_ID,
    SELECT_TIME_SERIES_DATA_BY_SERIES, SELECT_TIME_SERIES_DATA_IN_RANGE,
};
use crate::sqlite::SQLiteTSDB;
use crate::error::TSDBError;

use std::f64;
use sqlite::{State, Value};

impl SQLiteTSDB {
    pub fn new(path: String) -> Result<Self, TSDBError> {
        let conn = sqlite::open(&path)?;
        let mut db = SQLiteTSDB { path, conn, is_setup: false };
        db.setup().map_err(|e: TSDBError| TSDBError::SetupError { orig_e: Box::new(e) })?;
        db.is_setup = true;
        Ok(db)
    }

    fn setup(&self) -> Result<(), TSDBError> {
        self.conn.execute(PRAGMA_FOREIGN_KEYS)?;
        self.conn.execute(CREATE_FLOW_TABLE)?;
        self.conn.execute(CREATE_FLOW_ATTRIBUTE_TABLE)?;
        self.conn.execute(CREATE_TIME_SERIES_TABLE)?;
        self.conn.execute(CREATE_TIME_SERIES_DATA_TABLE)?;
        Ok(())
    }

    fn check_setup(&self) -> Result<(), TSDBError> {
        if !self.is_setup {
            return Err(TSDBError::NotSetupError);
        }
        Ok(())
    }
}

impl TSDBInterface for SQLiteTSDB {

    fn get_flow(&self, tuple: &IpTuple) -> Result<Option<Flow>, TSDBError> {
        self.check_setup()?;
        let params: &[(_, Value)] = &[
            (":src", tuple.src.to_string().into()),
            (":dst", tuple.dst.to_string().into()),
            (":sport", tuple.sport.into()),
            (":dport", tuple.dport.into()),
            (":l4proto", tuple.l4proto.into()),
        ][..];
        let mut stmt = self.conn.prepare(SELECT_FLOW_BY_TUPLE)?;
        stmt.bind::<&[(_, Value)]>(params)?;
        Ok(SQLiteCursor::<Flow>::new(stmt).next())
    }

    fn get_flow_by_id(&self, id: i64) -> Result<Option<Flow>, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(SELECT_FLOW_BY_ID)?;
        stmt.bind::<&[(_, Value)]>(&[(":id", id.into())][..])?;
        Ok(SQLiteCursor::<Flow>::new(stmt).next())
    }

    fn get_flow_attribute_by_id(&self, id: i64) -> Result<Option<FlowAttribute>, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(SELECT_FLOW_ATTRIBUTE_BY_ID)?;
        stmt.bind::<&[(_, Value)]>(&[(":id", id.into())][..])?;
        Ok(SQLiteCursor::<FlowAttribute>::new(stmt).next())
    }

    fn get_time_series_by_id(&self, id: i64) -> Result<Option<TimeSeries>, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(SELECT_TIME_SERIES_BY_ID)?;
        stmt.bind::<&[(_, Value)]>(&[(":id", id.into())][..])?;
        Ok(SQLiteCursor::<TimeSeries>::new(stmt).next())
    }

    fn create_flow(&self, tuple: &IpTuple) -> Result<Flow, TSDBError> {
        self.check_setup()?;
        let params: &[(_, Value)] = &[
            (":src", tuple.src.to_string().into()),
            (":dst", tuple.dst.to_string().into()),
            (":sport", tuple.sport.into()),
            (":dport", tuple.dport.into()),
            (":l4proto", tuple.l4proto.into()),
        ][..];

        let mut insert = self.conn.prepare(INSERT_FLOW)?;
        insert.bind::<&[(_, Value)]>(params)?;
        let _ = insert.next()?;

        let mut get = self.conn.prepare(SELECT_FLOW_BY_TUPLE)?;
        get.bind::<&[(_, Value)]>(params)?;
        SQLiteCursor::<Flow>::new(get).next().ok_or(TSDBError::ReadFlowIDError)
    }

    fn delete_flow(&self, flow: &Flow) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let tuple = &flow.tuple;
        let mut stmt = self.conn.prepare(DELETE_FLOW_BY_TUPLE)?;
        stmt.bind::<&[(_, Value)]>(&[
            (":src", tuple.src.to_string().into()),
            (":dst", tuple.dst.to_string().into()),
            (":sport", tuple.sport.into()),
            (":dport", tuple.dport.into()),
            (":l4proto", tuple.l4proto.into()),
        ][..])?;
        Ok(stmt.next()? == State::Done)
    }

    fn list_flows(&self) -> Result<Box<dyn Iterator<Item = Flow> + '_>, TSDBError> {
        self.check_setup()?;
        let stmt = self.conn.prepare(SELECT_ALL_FLOWS)?;
        Ok(Box::new(SQLiteCursor::<Flow>::new(stmt)))
    }

    fn get_flow_attribute(&self, flow: &Flow, name: &str) -> Result<FlowAttribute, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(SELECT_FLOW_ATTRIBUTE_BY_NAME)?;
        stmt.bind::<&[(_, Value)]>(&[(":id", flow.id.into()), (":name", name.into())][..])?;
        SQLiteCursor::<FlowAttribute>::new(stmt)
            .next()
            .ok_or(TSDBError::NoAttributeError { name: name.to_owned(), id: flow.id })
    }

    fn list_flow_attributes(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = FlowAttribute> + '_>, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(SELECT_FLOW_ATTRIBUTES_BY_FLOW_ID)?;
        stmt.bind::<&[(_, Value)]>(&[(":id", flow.id.into())][..])?;
        Ok(Box::new(SQLiteCursor::<FlowAttribute>::new(stmt)))
    }

    fn add_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let attr_value = &attribute.value;
        let val_type: &str = match attr_value {
            DataValue::Boolean(_) => "value_boolean",
            DataValue::Int(_) => "value_integer",
            DataValue::Float(_) => "value_float",
            DataValue::String(_) => "value_text",
        };
        let query_str = format!(
            "INSERT INTO flow_attributes (flow_id, name, {val_type}) VALUES (:id, :name, :value);"
        );
        let mut stmt = self.conn.prepare(query_str)?;
        let value: Value = match attr_value {
            DataValue::Boolean(val) => if *val { 1i64.into() } else { 0i64.into() },
            DataValue::Int(val) => (*val).into(),
            DataValue::Float(val) => (*val).into(),
            DataValue::String(val) => val.clone().into(),
        };
        stmt.bind::<&[(_, Value)]>(&[
            (":id", flow.id.into()),
            (":name", attribute.name.clone().into()),
            (":value", value),
        ][..])?;
        Ok(stmt.next()? == State::Done)
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
        stmt.bind::<&[(_, Value)]>(&[(":id", flow.id.into()), (":name", name.into())][..])?;
        Ok(stmt.next()? == State::Done)
    }

    fn create_time_series(
        &self,
        flow: &Flow,
        name: &str,
        ts_type: DataValue,
    ) -> Result<TimeSeries, TSDBError> {
        self.check_setup()?;
        let params: &[(_, Value)] = &[
            (":flow_id", flow.id.into()),
            (":name", name.to_string().into()),
            (":type", (ts_type.type_to_int() as i64).into()),
        ][..];

        let mut insert = self.conn.prepare(INSERT_TIME_SERIES)?;
        insert.bind::<&[(_, Value)]>(params)?;
        let _ = insert.next()?;

        let mut get = self.conn.prepare(SELECT_TIME_SERIES_BY_FLOW_AND_NAME)?;
        get.bind::<&[(_, Value)]>(params)?;
        SQLiteCursor::<TimeSeries>::new(get).next().ok_or(TSDBError::ReadTSIDError)
    }

    fn delete_time_series(&self, flow: &Flow, series: &TimeSeries) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(DELETE_TIME_SERIES_BY_NAME)?;
        stmt.bind::<&[(_, Value)]>(&[
            (":flow_id", flow.id.into()),
            (":name", series.name.to_string().into()),
        ][..])?;
        Ok(stmt.next()? == State::Done)
    }

    fn list_time_series(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = TimeSeries> + '_>, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(SELECT_TIME_SERIES_BY_FLOW)?;
        stmt.bind::<&[(_, Value)]>(&[(":flow_id", flow.id.into())][..])?;
        Ok(Box::new(SQLiteCursor::<TimeSeries>::new(stmt)))
    }

    fn get_data_points(
        &self,
        series: &TimeSeries,
    ) -> Result<Box<dyn Iterator<Item = DataPoint> + '_>, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(SELECT_TIME_SERIES_DATA_BY_SERIES)?;
        stmt.bind::<&[(_, Value)]>(&[(":time_series_id", series.id.into())][..])?;
        Ok(Box::new(SQLiteCursor::<DataPoint>::new(stmt)))
    }

    fn get_data_points_in_range(
        &self,
        series: &TimeSeries,
        t_start: f64,
        t_end: f64,
    ) -> Result<Box<dyn Iterator<Item = DataPoint> + '_>, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(SELECT_TIME_SERIES_DATA_IN_RANGE)?;
        stmt.bind::<&[(_, Value)]>(&[
            (":time_series_id", series.id.into()),
            (":t_start", t_start.into()),
            (":t_end", t_end.into()),
        ][..])?;
        Ok(Box::new(SQLiteCursor::<DataPoint>::new(stmt)))
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
        let col = point.value.column_name()?;
        let full_query = format!(
            "INSERT INTO time_series_data (time_series_id, timestamp, {col}) VALUES (:time_series_id, :timestamp, :{col});"
        );
        let mut stmt = self.conn.prepare(full_query)?;
        stmt.bind::<&[(_, Value)]>(&[
            (":time_series_id", series.id.into()),
            (":timestamp", point.timestamp.into()),
            (format!(":{col}").as_str(), point.value.clone().into()),
        ][..])?;
        Ok(stmt.next()? == State::Done)
    }

    fn insert_multiple_points(
        &self,
        series: &TimeSeries,
        points: &[DataPoint],
    ) -> Result<bool, TSDBError> {
        self.check_setup()?;
        let col = series.ts_type.column_name()?;
        let mut query = format!(
            "INSERT INTO time_series_data (time_series_id, timestamp, {col}) VALUES"
        );
        let mut it = points.iter().peekable();
        while let Some(entry) = it.next() {
            query.push_str(&format!(
                " ({}, {}, {})",
                series.id,
                entry.timestamp,
                entry.value.as_string()
            ));
            if it.peek().is_some() {
                query.push(',');
            }
        }
        query.push(';');
        self.conn.execute(query)?;
        Ok(true)
    }

    fn get_time_series_bounds(&self, series: &TimeSeries) -> Result<TSBounds, TSDBError> {
        self.check_setup()?;
        let id = series.id;

        let mut xmin_stmt = self.conn.prepare(SELECT_FIRST_TIME_SERIES_DATA)?;
        xmin_stmt.bind::<&[(_, Value)]>(&[(":id", id.into())][..])?;
        let xmin = SQLiteCursor::<DataPoint>::new(xmin_stmt)
            .next()
            .ok_or(TSDBError::TimeSeriesNoValue)?
            .timestamp;

        let mut xmax_stmt = self.conn.prepare(SELECT_LAST_TIME_SERIES_DATA)?;
        xmax_stmt.bind::<&[(_, Value)]>(&[(":id", id.into())][..])?;
        let xmax = SQLiteCursor::<DataPoint>::new(xmax_stmt)
            .next()
            .ok_or(TSDBError::TimeSeriesNoValue)?
            .timestamp;

        let mut bounds = TSBounds { xmin, xmax, ymin: None, ymax: None };

        match series.ts_type {
            DataValue::Boolean(_) | DataValue::String(_) => return Ok(bounds),
            _ => (),
        }

        let (q_min, q_max) = if let DataValue::Int(_) = series.ts_type {
            (SELECT_LOWEST_INT_TIME_SERIES_DATA, SELECT_HIGHEST_INT_TIME_SERIES_DATA)
        } else {
            (SELECT_LOWEST_FLOAT_TIME_SERIES_DATA, SELECT_HIGHEST_FLOAT_TIME_SERIES_DATA)
        };

        let mut ymax_stmt = self.conn.prepare(q_max)?;
        ymax_stmt.bind::<&[(_, Value)]>(&[(":id", id.into())][..])?;
        bounds.ymax = Some(
            SQLiteCursor::<DataPoint>::new(ymax_stmt)
                .next()
                .ok_or(TSDBError::TimeSeriesNoValue)?
                .value,
        );

        let mut ymin_stmt = self.conn.prepare(q_min)?;
        ymin_stmt.bind::<&[(_, Value)]>(&[(":id", id.into())][..])?;
        bounds.ymin = Some(
            SQLiteCursor::<DataPoint>::new(ymin_stmt)
                .next()
                .ok_or(TSDBError::TimeSeriesNoValue)?
                .value,
        );

        Ok(bounds)
    }

    fn get_data_points_count(&self, series: &TimeSeries) -> Result<i64, TSDBError> {
        self.check_setup()?;
        let mut stmt = self.conn.prepare(COUNT_TIME_SERIES_DATA)?;
        stmt.bind::<&[(_, Value)]>(&[(":id", series.id.into())][..])?;
        stmt.next()?;
        Ok(stmt.read::<i64, _>(0)?)
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
