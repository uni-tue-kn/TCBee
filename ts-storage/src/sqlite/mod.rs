mod db;
mod cursor;
mod queries;
use sqlite::Connection;

pub struct SQLiteTSDB {
    path: String,
    is_setup: bool,
    conn: Connection,
}