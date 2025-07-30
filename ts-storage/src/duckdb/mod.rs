mod cursor;

use duckdb::Connection;

pub struct SQLiteTSDB {
    path: String,
    is_setup: bool,
    conn: Connection,
}