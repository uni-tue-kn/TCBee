use std::marker::PhantomData;
use std::net::IpAddr;
use std::str::FromStr;


use sqlite::{self, State, Statement, Value};
use crate::{Flow, IpTuple, DataPoint, TimeSeries, DataValue, FlowAttribute};


pub trait SQLiteCursorStruct: Sized {
    fn from_statement(stmt: &Statement) -> Option<Self>;
}

impl SQLiteCursorStruct for Flow {
    fn from_statement(stmt: &Statement) -> Option<Self> {
        let id = stmt.read::<i64,_>("id");

        // Check if ID can be read
        if id.is_err() {
            return None;
        }

        let tuple = IpTuple::from_statement(stmt);

        // Chek if tuple could be parsed
        if tuple.is_none() {
            return None;
        }

        // Return parsed flow object
        return Some(Flow::new_with_id(id.unwrap(),tuple.unwrap()));

    }
}

impl SQLiteCursorStruct for DataPoint {
    fn from_statement(stmt: &Statement) -> Option<Self> {

        // Get timestamp
        let timestamp = stmt.read::<f64,_>("timestamp");
        if timestamp.is_err() {return None}

        // Try to parse all values, check later which one did succeed
        // TODO: fix this in new version
        let value: DataValue;
        let int_val = stmt.read::<i64,_>("value_integer").unwrap();
        let boolean_val = stmt.read::<i64,_>("value_boolean").unwrap();
        let float_val = stmt.read::<f64,_>("value_float").unwrap();
        let text_val = stmt.read::<String,_>("value_text");

        if int_val != -1 {
            value = DataValue::Int(int_val);
        } else if boolean_val != -1 {
            value = DataValue::Boolean(boolean_val  == 1);
        } else if float_val != -1.0 {
            value = DataValue::Float(float_val);
        } else if text_val.is_ok() {
            value = DataValue::String(text_val.unwrap());
        } else {
            // No value was set, return none
            return None
        }

        Some(DataPoint{timestamp: timestamp.unwrap(), value: value})
    }
}

// From DataValue into sqlite::value
impl Into<Value> for DataValue {
    fn into(self) -> Value {
        match self {
            DataValue::Boolean(val) => (if val {1} else {0}).into(),
            DataValue::Float(val) => val.into(),
            DataValue::Int(val) => val.into(),
            DataValue::String(val) => val.into()
        }
    }
}


impl SQLiteCursorStruct for TimeSeries {
    fn from_statement(stmt: &Statement) -> Option<Self> {

        let name = stmt.read::<String,_>("name");
        let flow_id = stmt.read::<i64,_>("flow_id");
        let ts_id = stmt.read::<i64,_>("time_series_id");
        let ts_type_raw = stmt.read::<i64,_>("type");

        // Check if all values were read without error
        if name.is_err() || flow_id.is_err() || ts_id.is_err() || ts_type_raw.is_err() {
            return None;
        }

        // Get type of TS values
        // TODO: this parsing from enum to int has to be possible in a simpler way....
        let ts_type = DataValue::type_from_int(ts_type_raw.unwrap());
        if ts_type.is_err() {return None;}

        Some(
            TimeSeries::new_with_id(ts_id.unwrap(), ts_type.unwrap(), flow_id.unwrap(), &name.unwrap())
        )
    }
}

impl SQLiteCursorStruct for FlowAttribute {
    fn from_statement(stmt: &Statement) -> Option<Self> {
        let name = stmt.read::<String,_>("name");

        // If name cannot be read, return none
        if name.is_err() {return None}

        // Try to parse all values, check later which one did succeed
        let value: DataValue;
        let int_val = stmt.read::<i64,_>("value_integer").unwrap();
        let boolean_val = stmt.read::<i64,_>("value_boolean").unwrap();
        let float_val = stmt.read::<f64,_>("value_float").unwrap();
        let text_val = stmt.read::<String,_>("value_text");

        // DEBUG
        //println!("Values Int {int_val:?}, Bool: {boolean_val:?}, Float: {float_val:?}, Text: {text_val:?}");

        // Check which of the four values ist set
        // IMPORTANT: only one of these values may be set per entry!
        if int_val != -1 {
            value = DataValue::Int(int_val);
        } else if boolean_val != -1 {
            value = DataValue::Boolean(boolean_val  == 1);
        } else if float_val != -1.0 {
            value = DataValue::Float(float_val);
        } else if text_val.is_ok() {
            value = DataValue::String(text_val.unwrap());
        } else {
            // No value was set, return none
            return None
        }

        let result = FlowAttribute{
            name: name.unwrap(), // already checked if name.is_err() above
            value: value
        };

        Some(result)
    }
}

impl SQLiteCursorStruct for IpTuple {

    fn from_statement(stmt: &Statement) -> Option<Self> {

        // Try to read values from SQL row
        let src = stmt.read::<String,_>("src");
        let dst = stmt.read::<String,_>("dst");
        let sport = stmt.read::<i64,_>("sport");
        let dport = stmt.read::<i64,_>("dport");
        let l4proto = stmt.read::<i64,_>("l4proto");

        // Check if any conversion error happened?
        let err_happened = src.is_err() || dst.is_err() || sport.is_err() || dport.is_err() || l4proto.is_err();

        // If error happened, return no entry
        // This is common for rust iterators
        if err_happened {
            return None;
        }

        // Convert strings to IP address
        let src_ip = IpAddr::from_str(&src.unwrap());
        let dst_ip = IpAddr::from_str(&dst.unwrap());

        // Return none if conversion from string to IP address fails
        if src_ip.is_err() || dst_ip.is_err() {
            return None;
        }

        // Build return struct
        let tuple = IpTuple {
            src: src_ip.unwrap(),
            dst: dst_ip.unwrap(),
            sport: sport.unwrap(),
            dport: dport.unwrap(),
            l4proto: l4proto.unwrap()
        };

        return Some(tuple)
    }
}

//struct AttributeQuery {
 //   query: String,
 //   value: DataValue
//
//}
pub struct SQLiteCursor<'stmt,T> 
where 
    T: SQLiteCursorStruct 
{
    stmt: Statement<'stmt>,
    _phantom: PhantomData<T>
}

impl <'stmt,T>SQLiteCursor<'stmt,T>
where 
    T: SQLiteCursorStruct
{
     // Constructor for struct A
     pub fn new(stmt: Statement<'stmt>) -> Self {
        Self {
            stmt,
            _phantom: PhantomData
        }
    }
}

impl<'stmt, T> Iterator for SQLiteCursor<'stmt, T> 
where 
    T: SQLiteCursorStruct
{
    // Type of every iterator item
    type Item = T;

    // Get next element by moving cursor
    fn next(&mut self) -> Option<Self::Item> {
        
        // Load next road
        let next = self.stmt.next();

        // Catch error, return none if error returned
        if next.is_err() {return None}

        let state = next.unwrap();

        // Return None if no rows left
        if state == State::Done {return None;}

        // Parse row based on given generic T
        let parsed: Option<Self::Item> = Self::Item::from_statement(&self.stmt);

        // Return parsed value
        // Is already wrapped as option
        parsed
    }
}