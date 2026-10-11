//! The run metadata that tcbee-record writes with `--metadata`, stored as `run.*` rows of the
//! meta table. The JSON is flattened: object members become dotted keys, array elements their
//! index (`run.interfaces.0.name`), nulls are left out. Rows can be read with plain SQL and need
//! no JSON support in the reader.

use std::{fs, io, path::Path};

use std::collections::BTreeMap;

use serde_json::Value;
use tcbee_trace::{DROP_REASONS_FILE, METADATA_FILE};

/// Prefix of the meta keys that come from the metadata file
pub const PREFIX: &str = "run";

/// The meta rows of the metadata file in `trace_dir`, none if there is no such file. A file
/// that cannot be read or parsed is an error the caller reports as a warning.
pub fn read(trace_dir: &Path) -> Result<Vec<(String, String)>, String> {
    let path = trace_dir.join(METADATA_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    let mut rows = Vec::new();
    flatten(PREFIX.to_string(), &value, &mut rows);
    Ok(rows)
}

/// The names of the kernel's drop reasons by value, from the file `tcbee-record --drops`
/// writes; empty if there is none. Errors as for `read`.
pub fn drop_reasons(trace_dir: &Path) -> Result<BTreeMap<u32, String>, String> {
    let path = trace_dir.join(DROP_REASONS_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let names: BTreeMap<String, String> = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a JSON object of names: {e}", path.display()))?;
    names
        .into_iter()
        .map(|(value, name)| match value.parse() {
            Ok(value) => Ok((value, name)),
            Err(_) => Err(format!("{}: {value} is no drop reason", path.display())),
        })
        .collect()
}

fn flatten(key: String, value: &Value, rows: &mut Vec<(String, String)>) {
    match value {
        Value::Null => {}
        Value::Bool(b) => rows.push((key, b.to_string())),
        Value::Number(n) => rows.push((key, n.to_string())),
        Value::String(s) => rows.push((key, s.clone())),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                flatten(format!("{key}.{i}"), item, rows);
            }
        }
        Value::Object(members) => {
            for (name, member) in members {
                flatten(format!("{key}.{name}"), member, rows);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(json: &str) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        flatten(
            PREFIX.to_string(),
            &serde_json::from_str(json).unwrap(),
            &mut rows,
        );
        rows
    }

    #[test]
    fn objects_and_arrays_become_dotted_keys() {
        let got = rows(
            r#"{"format":1,"host":{"hostname":"a","boot_id":null},
                "interfaces":[{"name":"eth0.100","offloads":{"tso":true}}],
                "sysctls":{"net.ipv4.tcp_rmem":"4096 131072 6291456"},
                "start":{"clock":{"realtime_minus_monotonic_ns":-5}}}"#,
        );
        let want = [
            ("run.format", "1"),
            ("run.host.hostname", "a"),
            ("run.interfaces.0.name", "eth0.100"),
            ("run.interfaces.0.offloads.tso", "true"),
            ("run.start.clock.realtime_minus_monotonic_ns", "-5"),
            ("run.sysctls.net.ipv4.tcp_rmem", "4096 131072 6291456"),
        ];
        let mut got = got;
        got.sort();
        let want: Vec<(String, String)> = want
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn drop_reasons_by_value() {
        let dir = tempfile::tempdir().unwrap();
        assert!(drop_reasons(dir.path()).unwrap().is_empty());
        fs::write(
            dir.path().join(DROP_REASONS_FILE),
            r#"{"2": "NOT_SPECIFIED", "3": "NO_SOCKET"}"#,
        )
        .unwrap();
        let reasons = drop_reasons(dir.path()).unwrap();
        assert_eq!(reasons[&3], "NO_SOCKET");
        fs::write(dir.path().join(DROP_REASONS_FILE), r#"{"x": "A"}"#).unwrap();
        assert!(drop_reasons(dir.path()).is_err());
    }

    #[test]
    fn missing_file_gives_no_rows_and_bad_json_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path()).unwrap(), vec![]);
        fs::write(dir.path().join(METADATA_FILE), "{").unwrap();
        let err = read(dir.path()).unwrap_err();
        assert!(err.contains("not valid JSON"), "{err}");
    }
}
