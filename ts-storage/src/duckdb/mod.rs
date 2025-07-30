pub(crate) mod cursor;
pub(crate) mod db;

use duckdb::Connection;

pub struct DuckDBTSDB {
    path: String,
    is_setup: bool,
    conn: Connection,
}