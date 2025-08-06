// -------- Other references
pub const TIME_SERIES_DATA_TABLE: &str = "time_series_data";

// -------- Sequence numbers for auto increment
pub const CREATE_FLOW_ID_SEQ: &str = "CREATE SEQUENCE IF NOT EXISTS flow_id_seq;";
pub const CREATE_FLOW_ATTRIBUTE_ID_SEQ: &str = "CREATE SEQUENCE IF NOT EXISTS flow_attribute_id_seq;";
pub const CREATE_TS_ID_SEQ: &str = "CREATE SEQUENCE IF NOT EXISTS time_series_id_seq;";

// -------- Main Tables
pub const CREATE_FLOW_TABLE: &str = "CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY DEFAULT nextval('flow_id_seq'),
            src TEXT NOT NULL,
            dst TEXT NOT NULL,
            sport INTEGER NOT NULL,
            dport INTEGER NOT NULL,
            l4proto INTEGER NOT NULL,
            UNIQUE (src, dst, sport, dport, l4proto)
        );";
pub const CREATE_FLOW_ATTRIBUTE_TABLE: &str = "CREATE TABLE IF NOT EXISTS flow_attributes (
            id INTEGER PRIMARY KEY DEFAULT nextval('flow_attribute_id_seq'),
            flow_id INTEGER,
            name TEXT NOT NULL,
            value UNION(inum INTEGER, str VARCHAR, fnum DOUBLE, bool BOOLEAN),
            type INTEGER,
            UNIQUE (flow_id, name),
            FOREIGN KEY (flow_id) REFERENCES flows(id)
        );";
// Time series table stores name of time series for a flow id and provides time series ID
// The type defines what data type is sotred in the time series
// The rust implementation will use this type to parse all values for this time series
pub const CREATE_TIME_SERIES_TABLE: &str = "CREATE TABLE IF NOT EXISTS time_series (
            time_series_id INTEGER PRIMARY KEY DEFAULT nextval('time_series_id_seq'),
            flow_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type INTEGER NOT NULL,
            UNIQUE (flow_id, name),
            FOREIGN KEY (flow_id) REFERENCES flows(id)
        );";
// This table stores the actual time series data and can be accessed more quickly via the time_series_id
// When a time_series entry is deleted, the entries in this table are cascaded as well!
pub const CREATE_TIME_SERIES_DATA_TABLE: &str = "CREATE TABLE IF NOT EXISTS time_series_data (
            time_series_id INTEGER NOT NULL,
            timestamp DOUBLE NOT NULL,
            value UNION(inum INTEGER, str VARCHAR, fnum DOUBLE, bool BOOLEAN),
            type INTEGER,
            PRIMARY KEY (time_series_id, timestamp),
            FOREIGN KEY (time_series_id) REFERENCES time_series(time_series_id)
        );";

// -------- SELECT queries
pub const SELECT_FLOW_BY_TUPLE: &str = "SELECT * FROM flows WHERE src = ? AND dst = ? AND sport = ? AND dport = ? AND l4proto = ?;";
pub const SELECT_FLOW_BY_ID: &str = "SELECT * FROM flows WHERE id = ?;";
pub const SELECT_FLOW_ATTRIBUTE_BY_ID: &str = "SELECT * FROM flow_attributes WHERE id = ?;";
pub const SELECT_FLOW_ATTRIBUTE_BY_NAME: &str = "SELECT * FROM flow_attributes WHERE flow_id = ? AND name = ?;";
pub const SELECT_FLOW_ATTRIBUTES_BY_FLOW_ID: &str = "SELECT * FROM flow_attributes WHERE flow_id = ?";
pub const SELECT_TIME_SERIES_BY_ID: &str = "SELECT * FROM flow_attributes WHERE id = ?;";
pub const SELECT_ALL_FLOWS: &str = "SELECT * FROM flows;";
pub const SELECT_TIME_SERIES_BY_FLOW_AND_NAME: &str = "SELECT * FROM time_series WHERE flow_id = ? AND name = ? AND type = ?;";
pub const SELECT_TIME_SERIES_BY_FLOW: &str = "SELECT * FROM time_series WHERE flow_id = ?;";
pub const SELECT_TIME_SERIES_DATA_BY_SERIES: &str = "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by timestamp ASC";

pub const SELECT_FIRST_TIME_SERIES_DATA: &str = "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by timestamp ASC LIMIT 1";
pub const SELECT_LAST_TIME_SERIES_DATA: &str =  "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by timestamp DESC LIMIT 1";
pub const SELECT_LOWEST_TIME_SERIES_DATA: &str =  "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by value DESC LIMIT 1";
pub const SELECT_HIGHEST_TIME_SERIES_DATA: &str =  "SELECT * FROM time_series_data WHERE time_series_id = ? ORDER by value ASC LIMIT 1";

pub const COUNT_TIME_SERIES_DATA: &str = "SELECT COUNT(*) FROM time_series_data WHERE time_series_id = ?;";

// -------- INSERT queries
pub const INSERT_FLOW: &str = "INSERT INTO flows (src, dst, sport, dport, l4proto) VALUES(?,?,?,?,?);";
pub const INSERT_FLOW_ATTRIBUTE: &str = "INSERT INTO flow_attributes (flow_id, name, value, type) VALUES (?, ?, ?, ?);";
pub const INSERT_TIME_SERIES: &str = "INSERT INTO time_series (flow_id, name, type) VALUES (?, ?, ?);";
pub const INSERT_TIME_SERIES_DATA: &str = "INSERT INTO time_series_data (time_series_id, timestamp, value, type) VALUES (?, ?, ?, ?);";

// -------- DELETE queries
pub const DELETE_FLOW_BY_TUPLE: &str = "DELETE FROM flows WHERE src = ? AND dst = ? AND sport = ? AND dport = ? AND l4proto = ?;";
pub const DELETE_FLOW_ATTRIBUTE_BY_NAME: &str = "DELETE FROM flow_attributes WHERE flow_id = ? AND name = ?;";
pub const DELETE_TIME_SERIES_BY_NAME: &str =  "DELETE FROM time_series WHERE flow_id = ? AND name = ?;";

