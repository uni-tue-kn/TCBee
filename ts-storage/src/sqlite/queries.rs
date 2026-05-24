// -------- Schema setup
pub const PRAGMA_FOREIGN_KEYS: &str = "PRAGMA foreign_keys=ON";

pub const CREATE_FLOW_TABLE: &str = "CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src TEXT NOT NULL,
            dst TEXT NOT NULL,
            sport INTEGER NOT NULL,
            dport INTEGER NOT NULL,
            l4proto INTEGER NOT NULL,
            UNIQUE (src, dst, sport, dport, l4proto)
        )";

pub const CREATE_FLOW_ATTRIBUTE_TABLE: &str = "CREATE TABLE IF NOT EXISTS flow_attributes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER,
            name TEXT NOT NULL,
            value_boolean INTEGER DEFAULT -1,
            value_text TEXT,
            value_integer INTEGER DEFAULT -1,
            value_float REAL DEFAULT -1,
            UNIQUE (flow_id, name),
            FOREIGN KEY (flow_id) REFERENCES flows(id)
        )";

pub const CREATE_TIME_SERIES_TABLE: &str = "CREATE TABLE IF NOT EXISTS time_series (
            time_series_id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type INTEGER NOT NULL,
            UNIQUE (flow_id, name),
            FOREIGN KEY (flow_id) REFERENCES flows(id)
        )";

pub const CREATE_TIME_SERIES_DATA_TABLE: &str = "CREATE TABLE IF NOT EXISTS time_series_data (
            time_series_id INTEGER NOT NULL,
            timestamp FLOAT NOT NULL,
            value_boolean INTEGER DEFAULT -1,
            value_text TEXT,
            value_integer INTEGER DEFAULT -1,
            value_float REAL DEFAULT -1,
            PRIMARY KEY (time_series_id, timestamp),
            FOREIGN KEY (time_series_id) REFERENCES time_series(time_series_id) ON DELETE CASCADE
        )";

// -------- SELECT queries
pub const SELECT_FLOW_BY_TUPLE: &str = "SELECT * FROM flows WHERE src = :src AND dst = :dst AND sport = :sport AND dport = :dport AND l4proto = :l4proto;";
pub const SELECT_FLOW_BY_ID: &str = "SELECT * FROM flows WHERE id = :id;";
pub const SELECT_ALL_FLOWS: &str = "SELECT * FROM flows";
pub const SELECT_FLOW_ATTRIBUTE_BY_ID: &str = "SELECT * FROM flow_attributes WHERE id = :id;";
pub const SELECT_FLOW_ATTRIBUTE_BY_NAME: &str = "SELECT * FROM flow_attributes WHERE flow_id = :id AND name = :name";
pub const SELECT_FLOW_ATTRIBUTES_BY_FLOW_ID: &str = "SELECT * FROM flow_attributes WHERE flow_id = :id";
pub const SELECT_TIME_SERIES_BY_ID: &str = "SELECT * FROM time_series WHERE time_series_id = :id;";
pub const SELECT_TIME_SERIES_BY_FLOW_AND_NAME: &str = "SELECT * FROM time_series WHERE flow_id = :flow_id AND name = :name AND type = :type;";
pub const SELECT_TIME_SERIES_BY_FLOW: &str = "SELECT * FROM time_series WHERE flow_id = :flow_id";
pub const SELECT_TIME_SERIES_DATA_BY_SERIES: &str = "SELECT * FROM time_series_data WHERE time_series_id = :time_series_id ORDER BY timestamp ASC";
pub const SELECT_TIME_SERIES_DATA_IN_RANGE: &str = "SELECT * FROM time_series_data WHERE time_series_id = :time_series_id AND timestamp >= :t_start AND timestamp <= :t_end ORDER BY timestamp ASC";
pub const SELECT_FIRST_TIME_SERIES_DATA: &str = "SELECT * FROM time_series_data WHERE time_series_id = :id ORDER BY timestamp ASC LIMIT 1";
pub const SELECT_LAST_TIME_SERIES_DATA: &str = "SELECT * FROM time_series_data WHERE time_series_id = :id ORDER BY timestamp DESC LIMIT 1";
pub const SELECT_LOWEST_INT_TIME_SERIES_DATA: &str = "SELECT * FROM time_series_data WHERE time_series_id = :id ORDER BY value_integer ASC LIMIT 1";
pub const SELECT_HIGHEST_INT_TIME_SERIES_DATA: &str = "SELECT * FROM time_series_data WHERE time_series_id = :id ORDER BY value_integer DESC LIMIT 1";
pub const SELECT_LOWEST_FLOAT_TIME_SERIES_DATA: &str = "SELECT * FROM time_series_data WHERE time_series_id = :id ORDER BY value_float ASC LIMIT 1";
pub const SELECT_HIGHEST_FLOAT_TIME_SERIES_DATA: &str = "SELECT * FROM time_series_data WHERE time_series_id = :id ORDER BY value_float DESC LIMIT 1";
pub const COUNT_TIME_SERIES_DATA: &str = "SELECT COUNT(*) FROM time_series_data WHERE time_series_id = :id";

// -------- INSERT queries
// Note: INSERT_FLOW_ATTRIBUTE and INSERT_TIME_SERIES_DATA are built dynamically in db.rs
// because the value column name varies by type (value_boolean, value_integer, value_float, value_text).
pub const INSERT_FLOW: &str = "INSERT INTO flows (src, dst, sport, dport, l4proto) VALUES(:src,:dst,:sport,:dport,:l4proto);";
pub const INSERT_TIME_SERIES: &str = "INSERT INTO time_series (flow_id, name, type) VALUES (:flow_id, :name, :type);";

// -------- DELETE queries
pub const DELETE_FLOW_BY_TUPLE: &str = "DELETE FROM flows WHERE src = :src AND dst = :dst AND sport = :sport AND dport = :dport AND l4proto = :l4proto;";
pub const DELETE_FLOW_ATTRIBUTE_BY_NAME: &str = "DELETE FROM flow_attributes WHERE flow_id = :id AND name = :name;";
pub const DELETE_TIME_SERIES_BY_NAME: &str = "DELETE FROM time_series WHERE flow_id = :flow_id AND name = :name;";
