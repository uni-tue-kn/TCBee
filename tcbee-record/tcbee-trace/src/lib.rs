use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::Local;

/// All trace file types produced by tcbee-record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFile {
    Bbr,
    Cubic,
    TcpProbe,
    TcpRetransmitSynack,
    TcpBadCsum,
    SendSock,
    RecvSock,
    SendCwnd,
    RecvCwnd,
    Tcp4Receive,
    Tcp4Send,
    Tcp6Receive,
    Tcp6Send,
}

impl TraceFile {
    pub const fn filename(self) -> &'static str {
        match self {
            TraceFile::Bbr => "bbr.tcp",
            TraceFile::Cubic => "cubic.tcp",
            TraceFile::TcpProbe => "tcp_probe.tcp",
            TraceFile::TcpRetransmitSynack => "tcp_retransmit_synack.tcp",
            TraceFile::TcpBadCsum => "tcp_bad_csum.tcp",
            TraceFile::SendSock => "send_sock.tcp",
            TraceFile::RecvSock => "recv_sock.tcp",
            TraceFile::SendCwnd => "send_cwnd.tcp",
            TraceFile::RecvCwnd => "recv_cwnd.tcp",
            TraceFile::Tcp4Receive => "tcp4_receive.tcp",
            TraceFile::Tcp4Send => "tcp4_send.tcp",
            TraceFile::Tcp6Receive => "tcp6_receive.tcp",
            TraceFile::Tcp6Send => "tcp6_send.tcp",
        }
    }

    pub const fn all() -> &'static [TraceFile] {
        &[
            TraceFile::Bbr,
            TraceFile::Cubic,
            TraceFile::TcpProbe,
            TraceFile::TcpRetransmitSynack,
            TraceFile::TcpBadCsum,
            TraceFile::SendSock,
            TraceFile::RecvSock,
            TraceFile::SendCwnd,
            TraceFile::RecvCwnd,
            TraceFile::Tcp4Receive,
            TraceFile::Tcp4Send,
            TraceFile::Tcp6Receive,
            TraceFile::Tcp6Send,
        ]
    }
}

/// Represents a single TCBee recording session — a timestamped directory
/// containing `.tcp` trace files.
pub struct TCBeeTrace {
    path: PathBuf,
}

impl TCBeeTrace {
    /// Create a new timestamped `tcbee_YYYY-MM-DDTHH-MM-SS` directory inside
    /// `base_dir` and return a handle to it.
    pub fn create(base_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let timestamp = Local::now().format("%Y-%m-%dT%H-%M-%S");
        let path = base_dir.as_ref().join(format!("tcbee_{}", timestamp));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Open an existing trace directory by its full path.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Trace directory does not exist: {}", path.display()),
            ));
        }
        Ok(Self { path })
    }

    /// Find the most-recently-created `tcbee_*` directory inside `base_dir`.
    /// Returns `None` if no matching directory exists.
    pub fn find_latest(base_dir: impl AsRef<Path>) -> Option<Self> {
        let mut entries: Vec<PathBuf> = fs::read_dir(base_dir)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("tcbee_"))
                        .unwrap_or(false)
            })
            .collect();

        entries.sort();
        entries.pop().map(|path| Self { path })
    }

    /// List all `tcbee_*` directories inside `base_dir`, sorted newest-first.
    pub fn list_all(base_dir: impl AsRef<Path>) -> Vec<Self> {
        let mut entries: Vec<PathBuf> = fs::read_dir(base_dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("tcbee_"))
                        .unwrap_or(false)
            })
            .collect();

        entries.sort();
        entries.reverse();
        entries.into_iter().map(|path| Self { path }).collect()
    }

    /// The path to the trace directory.
    pub fn dir(&self) -> &Path {
        &self.path
    }

    /// The path to a specific trace file within this recording.
    pub fn path_for(&self, file: TraceFile) -> PathBuf {
        self.path.join(file.filename())
    }

    /// Which trace files actually exist on disk in this recording.
    pub fn available_traces(&self) -> Vec<TraceFile> {
        TraceFile::all()
            .iter()
            .copied()
            .filter(|&f| self.path.join(f.filename()).exists())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn create_and_open_roundtrip() {
        let base = std::env::temp_dir().join("tcbee_test_roundtrip");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let trace = TCBeeTrace::create(&base).unwrap();
        let dir_name = trace.dir().file_name().unwrap().to_str().unwrap();
        assert!(dir_name.starts_with("tcbee_"));

        let reopened = TCBeeTrace::open(trace.dir()).unwrap();
        assert_eq!(reopened.dir(), trace.dir());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn find_latest_returns_newest() {
        let base = std::env::temp_dir().join("tcbee_test_latest");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        fs::create_dir_all(base.join("tcbee_2026-01-01T00-00-00")).unwrap();
        fs::create_dir_all(base.join("tcbee_2026-06-01T12-00-00")).unwrap();
        fs::create_dir_all(base.join("tcbee_2026-03-15T08-30-00")).unwrap();

        let latest = TCBeeTrace::find_latest(&base).unwrap();
        assert_eq!(
            latest.dir().file_name().unwrap().to_str().unwrap(),
            "tcbee_2026-06-01T12-00-00"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn available_traces_only_existing_files() {
        let base = std::env::temp_dir().join("tcbee_test_avail");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        fs::write(base.join("bbr.tcp"), b"").unwrap();
        fs::write(base.join("cubic.tcp"), b"").unwrap();

        let trace = TCBeeTrace::open(&base).unwrap();
        let avail = trace.available_traces();
        assert!(avail.contains(&TraceFile::Bbr));
        assert!(avail.contains(&TraceFile::Cubic));
        assert!(!avail.contains(&TraceFile::TcpProbe));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn path_for_correct_filename() {
        let base = std::env::temp_dir().join("tcbee_test_path");
        fs::create_dir_all(&base).unwrap();
        let trace = TCBeeTrace::open(&base).unwrap();
        assert_eq!(
            trace.path_for(TraceFile::Bbr).file_name().unwrap(),
            "bbr.tcp"
        );
        let _ = fs::remove_dir_all(&base);
    }
}
