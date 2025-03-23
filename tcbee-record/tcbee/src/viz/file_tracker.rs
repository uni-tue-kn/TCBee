use std::{fs::File, os::linux::fs::MetadataExt};

use log::error;

pub struct FileTracker {
    files: Vec<File>
}

impl FileTracker {
    pub fn new() -> FileTracker {
        // Open all .tcp files to watch file size!
        let mut files: Vec<File> = Vec::new();
        if let Ok(paths) = glob::glob("/tmp/*.tcp") {
            for p in paths {
                if let Ok(path) = p {
                    let open = File::open(path);
                    if open.is_ok() {
                        files.push(open.unwrap());
                    }
                }
            }
        } else {
            error!("No *.tcp files found in /tmp/! Will not display write speed corrently!")
        }

        FileTracker { files: files }
    }
    pub fn get_file_size(&self) -> u64 {
         // Get sum of file sizes
         let mut sum: u64 = 0;
         for f in self.files.iter() {
             if let Ok(meta) = f.metadata() {
                 sum = sum + meta.st_size();
             } else {
                 error!("Could not get metadata of file {:?}",f);
             }
         }
         sum
    }
}