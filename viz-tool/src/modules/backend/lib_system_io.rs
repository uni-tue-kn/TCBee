// contains logic interacting with the System IO
// this includes:
// - filesystem interactionA

use crate::DataSource;
use std::path::PathBuf;

pub fn receive_source_from_path(path: &PathBuf) -> Option<DataSource> {
    let extension = path.extension().unwrap().to_str().unwrap();
    match extension {
        "sqlite" => Some(DataSource::Sqllite),
        "influx" => Some(DataSource::Influx),
        _ => None,
    }
}
