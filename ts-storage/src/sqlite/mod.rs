mod db;
mod cursor;
use sqlite::Connection;

pub struct SQLiteTSDB {
    path: String,
    is_setup: bool,
    conn: Connection,
}