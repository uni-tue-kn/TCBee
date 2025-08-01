use duckdb::arrow::row;
use duckdb::{params, Appender, Connection, ToSql};

use crate::duckdb::cursor::{DuckDBCursor, DuckDBCursorStruct};
use crate::duckdb::DuckDBTSDB;
use crate::error::TSDBError;
use crate::{
    DataPoint, DataValue, Flow, FlowAttribute, IpTuple, TSBounds, TSDBInterface, TimeSeries,
};

use std::error::Error;
use std::f64;

// Gets first entry from query
fn get_entry<T: DuckDBCursorStruct>(
    params: &[&dyn ToSql],
    query: &str,
    conn: &Connection,
) -> Result<Option<T>, Box<dyn Error>> {
    let mut get_query = conn.prepare(query)?;
    let rows = get_query.query(params)?;

    let mut cursor = Box::new(DuckDBCursor::<T>::new(rows));
    Ok(cursor.next())
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
    // Creates SQLite connection to file under given path
    // Passes error from rusqlite connection if one occurs
    pub fn new(path: String) -> Result<Self, Box<dyn Error>> {
        let conn = duckdb::Connection::open(&path)?;
        let mut db = DuckDBTSDB {
            path,
            conn,
            is_setup: false,
        };

        // Ensure that main table flows exists
        db.setup()
            .map_err(|e| TSDBError::SetupError { orig_e: e })?;
        // Set flag to enable operations on DB
        db.is_setup = true;
        Ok(db)
    }

    fn setup(&self) -> Result<(), Box<dyn Error>> {
        // TODO: Check if some settigns are needed
        
        // Causes error if not 
        self.conn.execute("CREATE SEQUENCE IF NOT EXISTS flow_id_seq;", []);
        self.conn.execute("CREATE SEQUENCE IF NOT EXISTS flow_attribute_id_seq;", []);
        self.conn.execute("CREATE SEQUENCE IF NOT EXISTS time_series_id_seq;", []);

        let flows_query = "CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY DEFAULT nextval('flow_id_seq'),
            src TEXT NOT NULL,
            dst TEXT NOT NULL,
            sport INTEGER NOT NULL,
            dport INTEGER NOT NULL,
            l4proto INTEGER NOT NULL,
            UNIQUE (src, dst, sport, dport, l4proto)
        );";
        self.conn.execute(flows_query, params![])?;

        let flow_attributes_query = "CREATE TABLE IF NOT EXISTS flow_attributes (
            id INTEGER PRIMARY KEY DEFAULT nextval('flow_attribute_id_seq'),
            flow_id INTEGER,
            name TEXT NOT NULL,
            value UNION(inum INTEGER, str VARCHAR, fnum DOUBLE, bool BOOLEAN),
            type INTEGER,
            UNIQUE (flow_id, name),
            FOREIGN KEY (flow_id) REFERENCES flows(id)
        );";
        self.conn.execute(flow_attributes_query, params![])?;

        // Time series table stores name of time series for a flow id and provides time series ID
        // The type defines what data type is sotred in the time series
        // The rust implementation will use this type to parse all values for this time series
        let time_series_query = "CREATE TABLE IF NOT EXISTS time_series (
            time_series_id INTEGER PRIMARY KEY DEFAULT nextval('time_series_id_seq'),
            flow_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type INTEGER NOT NULL,
            UNIQUE (flow_id, name),
            FOREIGN KEY (flow_id) REFERENCES flows(id)
        );";
        self.conn.execute(time_series_query, params![])?;

        // This table stores the actual time series data and can be accessed more quickly via the time_series_id
        // When a time_series entry is deleted, the entries in this table are cascaded as well!
        let time_series_data_query = "CREATE TABLE IF NOT EXISTS time_series_data (
            time_series_id INTEGER NOT NULL,
            timestamp DOUBLE NOT NULL,
            value UNION(inum INTEGER, str VARCHAR, fnum DOUBLE, bool BOOLEAN),
            type INTEGER,
            PRIMARY KEY (time_series_id, timestamp),
            FOREIGN KEY (time_series_id) REFERENCES time_series(time_series_id)
        );";

        self.conn.execute(time_series_data_query, params![])?;

        Ok(())
    }
    // Check if DB is setup correctly to perform an operation
    // TODO: move to a wrapper?
    fn check_setup(&self) -> Result<(), TSDBError> {
        if !self.is_setup {
            return Err(TSDBError::NotSetupError);
        }
        Ok(())
    }

    fn check_flow(&self, flow: &Flow) -> Result<i64, TSDBError> {
        let id = flow.get_id();
        if id.is_none() {
            return Err(TSDBError::FlowNotSetup);
        }
        Ok(id.unwrap())
    }

    fn check_ts(&self, series: &TimeSeries) -> Result<i64, TSDBError> {
        let id = series.get_id();
        if id.is_none() {
            return Err(TSDBError::TimeSeriesNotSetup);
        }
        Ok(id.unwrap())
    }
}

impl TSDBInterface for DuckDBTSDB {
    // Gets a flow based on an IP tuple
    // Returns None if no flow found in DB
    fn get_flow(&self, tuple: &IpTuple) -> Result<Option<Flow>, Box<dyn Error>> {
        // Ensure that database is ready to add this flow
        self.check_setup()?;

        let params = params![
            tuple.src.to_string(),
            tuple.dst.to_string(),
            tuple.sport,
            tuple.dport,
            tuple.l4proto
        ];

        get_entry(params, "SELECT * FROM flows WHERE src = ? AND dst = ? AND sport = ? AND dport = ? AND l4proto = ?;", &self.conn)
    }

    fn get_flow_by_id(&self, id: i64) -> Result<Option<Flow>, Box<dyn Error>> {
        // Ensure that database is ready to add this flow
        self.check_setup()?;

        let params = params![id];

        get_entry(params, "SELECT * FROM flows WHERE id = ?;", &self.conn)
    }

    fn get_flow_attribute_by_id(&self, id: i64) -> Result<Option<FlowAttribute>, Box<dyn Error>> {
        // Ensure that database is ready to add this flow
        self.check_setup()?;

        let params = params![id];

        get_entry(
            params,
            "SELECT * FROM flow_attributes WHERE id = ?;",
            &self.conn,
        )
    }

    fn get_time_series_by_id(&self, id: i64) -> Result<Option<TimeSeries>, Box<dyn Error>> {
        // Ensure that database is ready to add this flow
        self.check_setup()?;

        let params = params![id];

        get_entry(
            params,
            "SELECT * FROM time_series WHERE time_series_id = ?;",
            &self.conn,
        )
    }

    // Flow interaction
    // Will overwrite Flow ID field!
    fn create_flow(&self, tuple: &IpTuple) -> Result<Flow, Box<dyn Error>> {
        // Ensure that database is ready to add this flow
        self.check_setup()?;

        // First: create flow entry
        let mut query = self
            .conn
            .prepare("INSERT INTO flows (src, dst, sport, dport, l4proto) VALUES(?,?,?,?,?);")?;
        let params = params![
            tuple.src.to_string(),
            tuple.dst.to_string(),
            tuple.sport,
            tuple.dport,
            tuple.l4proto
        ];
        query.execute(params);

        // Second: query flow entry to get ID field

        match get_entry::<Flow>(params, "SELECT * FROM flows WHERE src = ? AND dst = ? AND sport = ? AND dport = ? AND l4proto = ?;", &self.conn)? {
            Some(entry) => Ok(entry),
            None => Err(Box::new(TSDBError::ReadFlowIDError))
        }
    }

    fn delete_flow(&self, flow: &Flow) -> Result<bool, Box<dyn Error>> {
        // Ensure that database is ready to remove this flow
        self.check_setup()?;
        //TODO: create query builder class
        let mut query = self.conn.prepare("DELETE FROM flows WHERE src = ? AND dst = ? AND sport = ? AND dport = ? AND l4proto = ?;")?;
        let tuple = &flow.tuple;
        let params = params![
            tuple.src.to_string(),
            tuple.dst.to_string(),
            tuple.sport,
            tuple.dport,
            tuple.l4proto
        ];
        // Map usize return to bool value
        match query.execute(params) {
            Ok(_) => Ok(true),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn list_flows(&self) -> Result<Box<dyn Iterator<Item = Flow> + '_>, Box<dyn Error>> {
        // Ensure that database is ready to list flows
        self.check_setup()?;
        let mut stmt = self.conn.prepare("SELECT * FROM flows;")?;

        // This is really stupid but I cant figure out a fix currently....
        // May need to redo the interface definition....
        // TODO: THIS NEEDS TO BE CHANGED
        let rows = stmt.query_map(params![], |row| Ok(Flow::from_row(row)))?;

        let mut vec: Vec<Flow> = Vec::new();
        for r in rows {
            if let Ok(row) = r {
                if let Some(row) = row {
                    vec.push(row);
                }
            }
        }
        let iter: Box<dyn Iterator<Item = Flow>> = Box::new(vec.into_iter());

        Ok(iter)
    }

    fn get_flow_attribute(&self, flow: &Flow, name: &str) -> Result<FlowAttribute, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_flow(flow)?;

        match get_entry::<FlowAttribute>(
            params![id,name],
            "SELECT * FROM flow_attributes WHERE flow_id = ? AND name = ?;",
            &self.conn,
        )? {
            Some(entry) => Ok(entry),
            None => Err(Box::new(TSDBError::NoAttriuteError {
                name: name.to_owned(),
                id,
            })),
        }
    }

    fn list_flow_attributes(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = FlowAttribute> + '_>, Box<dyn Error>> {
        // Ensure that database is ready to list flows
        self.check_setup()?;
        let id = self.check_flow(flow)?;
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM flow_attributes WHERE flow_id = ?")?;

        // This is really stupid but I cant figure out a fix currently....
        // May need to redo the interface definition....
        // TODO: THIS NEEDS TO BE CHANGED
        let rows = stmt.query_map(params![id], |row| Ok(FlowAttribute::from_row(row)))?;

        let mut vec: Vec<FlowAttribute> = Vec::new();
        for r in rows {
            if let Ok(row) = r {
                if let Some(row) = row {
                    vec.push(row);
                }
            }
        }
        let iter: Box<dyn Iterator<Item = FlowAttribute>> = Box::new(vec.into_iter());

        Ok(iter)
    }

    fn add_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, Box<dyn Error>> {
        self.check_setup()?;

        let attr_value = &attribute.value;
        // Prepare query string
        let query_str = format!(
            "INSERT INTO flow_attributes (flow_id, name, value, type) VALUES (?, ?, ?, ?);"
        );

        let mut query = self.conn.prepare(&query_str)?;

        let params = params![
            flow.get_id(),
            attribute.name,
            val_to_union(attr_value),
            attr_value.type_to_int()
        ];

        match query.execute(params) {
            Ok(_) => Ok(true),
            Err(e) => Err(Box::new(e)),
        }
    }

    // ENSURES THAT ONLY ONE OF THE value_X is set by deleting the entry first!
    fn set_flow_attribute(
        &self,
        flow: &Flow,
        attribute: &FlowAttribute,
    ) -> Result<bool, Box<dyn Error>> {
        self.check_setup()?;

        // Ensure that old values are deleted
        self.delete_flow_attribute(flow, &attribute.name)?;

        // Add updated attribute to flow again
        let result = self.add_flow_attribute(flow, attribute)?;

        Ok(result)
    }

    fn delete_flow_attribute(&self, flow: &Flow, name: &str) -> Result<bool, Box<dyn Error>> {
        self.check_setup()?;

        // Prepare query string
        let query_str = "DELETE FROM flow_attributes WHERE flow_id = ? AND name = ?;";
        let mut query = self.conn.prepare(query_str)?;

        let params = params![flow.get_id(), name,];

        match query.execute(params) {
            Ok(_) => Ok(true),
            Err(e) => Err(Box::new(e)),
        }
    }

    // Time Series interaction
    // Interaction with whole time series with given name
    fn create_time_series(
        &self,
        flow: &Flow,
        name: &str,
        ts_type: DataValue,
    ) -> Result<TimeSeries, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_flow(flow)?;

        // First step: Create time series entry
        let query_string = "INSERT INTO time_series (flow_id, name, type) VALUES (?, ?, ?);";

        let mut query = self.conn.prepare(query_string)?;

        let params = params![id, name.to_string(), ts_type.type_to_int()];

        query.execute(params)?;

        match get_entry::<TimeSeries>(
            params,
            "SELECT * FROM time_series WHERE flow_id = ? AND name = ? AND type = ?;",
            &self.conn,
        )? {
            Some(entry) => Ok(entry),
            None => Err(Box::new(TSDBError::ReadTSIDError)),
        }
    }

    fn delete_time_series(&self, flow: &Flow, series: &TimeSeries) -> Result<bool, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_flow(flow)?;

        let query_string = "DELETE FROM time_series WHERE flow_id = ? AND name = ?;";
        let mut query = self.conn.prepare(query_string)?;

        let params = params![id, series.name,];

        match query.execute(params) {
            Ok(_) => Ok(true),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn list_time_series(
        &self,
        flow: &Flow,
    ) -> Result<Box<dyn Iterator<Item = TimeSeries> + '_>, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_flow(flow)?;

        let mut query = self
            .conn
            .prepare("SELECT * FROM time_series WHERE flow_id = ?;")?;

        let rows = query.query_map(params![id], |row| Ok(TimeSeries::from_row(row)))?;

        let mut vec: Vec<TimeSeries> = Vec::new();
        for r in rows {
            if let Ok(row) = r {
                if let Some(row) = row {
                    vec.push(row);
                }
            }
        }
        let iter: Box<dyn Iterator<Item = TimeSeries>> = Box::new(vec.into_iter());

        Ok(iter)
    }
    // Interaction with data points of time series with given name

    fn get_data_points(
        &self,
        series: &TimeSeries,
    ) -> Result<Box<dyn Iterator<Item = DataPoint> + '_>, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_ts(series)?;

        let mut query = self.conn.prepare(
            "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by timestamp ASC",
        )?;

        let rows = query.query_map(params![id], |row| Ok(DataPoint::from_row(row)))?;

        let mut vec: Vec<DataPoint> = Vec::new();
        for r in rows {
            if let Ok(row) = r {
                if let Some(row) = row {
                    vec.push(row);
                }
            }
        }
        let iter: Box<dyn Iterator<Item = DataPoint>> = Box::new(vec.into_iter());

        Ok(iter)
    }

    fn insert_data_point(
        &self,
        series: &TimeSeries,
        point: &DataPoint,
    ) -> Result<bool, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_ts(series)?;
        let ts_type = &series.ts_type;

        // Check if data point type matches TS type!
        if !ts_type.type_equal(&point.value) {
            return Err(Box::new(TSDBError::DataPointTypeMismatchError {
                type1: point.value.type_as_string(),
                type2: ts_type.type_as_string(),
            }));
        }

        // Get type of value from data type
        let union_string = val_to_union(&point.value);

        let query_str = format!("INSERT INTO time_series_data (time_series_id, timestamp, value, type) VALUES (?, ?, ?, ?);");
        let mut query = self.conn.prepare(&query_str)?;

        let params = params![id, point.timestamp, union_string, ts_type.type_to_int()];

        match query.execute(params) {
            Ok(_) => Ok(true),
            Err(e) => Err(Box::new(e)),
        }
    }
    fn insert_multiple_points(
        &self,
        series: &TimeSeries,
        points: &Vec<DataPoint>,
    ) -> Result<bool, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_ts(series)?;

        let mut appender = self.conn.appender("time_series_data")?;
        for p in points {
            appender.append_row(params![
                id,
                p.timestamp,
                val_to_union(&p.value),
                p.value.type_to_int()
            ])?;
        }
        appender.flush()?;

        Ok(true)
    }

    // TODO: split this into tinier functions
    fn get_time_series_bounds(&self, series: &TimeSeries) -> Result<TSBounds, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_ts(series)?;

        // XMIN
        let Some(xmin_point) = get_entry::<DataPoint>(params![id], "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by timestamp ASC LIMIT 1", &self.conn)? else {
            return Err(Box::new(TSDBError::TimeSeriesNoValue))
        };
        // XMAX
        let Some(xmax_point) = get_entry::<DataPoint>(params![id], "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by timestamp DESC LIMIT 1", &self.conn)? else {
            return Err(Box::new(TSDBError::TimeSeriesNoValue))
        };

        let mut bounds = TSBounds {
            xmin: xmin_point.timestamp,
            xmax: xmax_point.timestamp,
            ymin: None,
            ymax: None,
        };

        // Cannot get Ymin/Ymax for bool or string, stop here if that is the case
        match series.ts_type {
            DataValue::Boolean(_) => return Ok(bounds),
            DataValue::String(_) => return Ok(bounds),
            _ => (),
        }

        // Get query string for sorting
        let q1: &str;
        let q2: &str;

        if let DataValue::Int(_) = series.ts_type {
            q1 = "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by value DESC LIMIT 1";
            q2 = "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by value ASC LIMIT 1";
        } else {
            q1 = "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by value DESC LIMIT 1";
            q2 = "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by value ASC LIMIT 1";
        }

        // YMIN
        let Some(ymin_point) = get_entry::<DataPoint>(params![id], q1, &self.conn)? else {
            return Err(Box::new(TSDBError::TimeSeriesNoValue));
        };
        // YMAX
        let Some(ymax_point) = get_entry::<DataPoint>(params![id], q2, &self.conn)? else {
            return Err(Box::new(TSDBError::TimeSeriesNoValue));
        };

        bounds.ymin = Some(ymin_point.value);
        bounds.ymax = Some(ymax_point.value);

        Ok(bounds)
    }

    fn get_data_points_count(&self, series: &TimeSeries) -> Result<i64, Box<dyn Error>> {
        self.check_setup()?;
        let id = self.check_ts(series)?;

        let mut  query = self
            .conn
            .prepare("SELECT COUNT(*) FROM time_series_data WHERE time_series_id = ?;")?;

        let mut row = query.query(params![id])?;

        if let Some(value) = row.next()? {
            Ok(value.get(0)?)
        } else {
            Ok(0)
        }
    }
    fn get_flow_bounds(&self, flow: &Flow) -> Result<TSBounds, Box<dyn Error>> {
        // Goal: find smalles and largest x over all time series in flow
        let mut bounds: TSBounds = TSBounds {
            xmax: f64::MIN,
            xmin: f64::MAX,
            ymin: None,
            ymax: None,
        };

        let mut found_ts: bool = false;

        // Iterate over all TimeSeries stored for this flow
        let mut flow_ts = self.list_time_series(flow)?;
        while let Some(ts) = flow_ts.next() {
            // Flag to show that some values were processed
            found_ts = true;

            let new_bounds = self.get_time_series_bounds(&ts)?;

            // Compare bounds to known and store larger/smaller one
            bounds.xmax = bounds.xmax.max(new_bounds.xmax);
            bounds.xmin = bounds.xmin.min(new_bounds.xmin);
        }

        // No TS for flow, return error
        if !found_ts {
            return Err(Box::new(TSDBError::TimeSeriesNotFoundError { ts_id: 1 }));
        }

        Ok(bounds)
    }

    /*
    fn delete_data_points(&self, flow: &Flow, name: String, conditions: Vec<Condition>) -> bool {};

    // Allow direct query execution for special cases
    //  should not be used on a regular basis

    fn execute_query(&self) -> Box<dyn TSDBCursor> {};
    */
}
