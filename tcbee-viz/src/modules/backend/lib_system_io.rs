// contains logic interacting with the System IO
// this includes:
// - filesystem interactionA

use crate::DataSource;
use std::{fs::{self, Metadata}, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

pub fn receive_source_from_path(path: &PathBuf) -> Option<DataSource> {
    let extension = path.extension().unwrap().to_str().unwrap();
    match extension {
        "sqlite" => Some(DataSource::Sqllite),
        "influx" => Some(DataSource::Influx),
        _ => None,
    }
}

pub fn receive_file_metadata(path: &PathBuf) -> String { 
    let metadata_object = fs::metadata(path).unwrap();
    let file_size = metadata_object.len();
    let file_size_as_mb = (file_size / 1_048_576) as f64;
    let maybe_cr_time = metadata_object.created();
    let cr_time = match maybe_cr_time{
        Ok(cr_time) => {
            format!("{:?}",cr_time.duration_since(UNIX_EPOCH))
        }
        Err(_) => {
            "could not obtain creation time".to_string()
        }
    };
    let bundled_information = String::from(format!("size:{:?}mb\ncreated:{:?}",file_size_as_mb,cr_time));
    bundled_information

}