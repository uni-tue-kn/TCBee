//! Command line of `tcbee-process`.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use argparse::{ArgumentParser, Store, StoreOption, StoreTrue};
use ts_storage::Engine;

use crate::Args;

const DEFAULT_SQLITE: &str = "/tmp/db.sqlite";
const DEFAULT_DUCKDB: &str = "/tmp/db.duck";

/// The engine implied by the extension of the output file.
pub fn engine_for_output(path: &Path) -> Option<Engine> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "sqlite" | "db" => Some(Engine::Sqlite),
        "duck" | "duckdb" => Some(Engine::DuckDb),
        _ => None,
    }
}

/// Display name and cargo feature of an engine.
fn engine_names(e: Engine) -> (&'static str, &'static str) {
    match e {
        Engine::Sqlite => ("SQLite", "sqlite"),
        Engine::DuckDb => ("DuckDB", "duckdb"),
    }
}

/// Parses the arguments (without the program name). `Err` carries the exit status: 0 after
/// `--help`, 2 for bad flags; the message has been written to `out` or `err`.
pub fn parse_args(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> Result<Args, i32> {
    let mut source = "/tmp/".to_string();
    let mut output: Option<String> = None;
    let mut sqlite = false;
    let mut duckdb = false;
    let mut threads: Option<usize> = None;
    let mut force = false;

    {
        let mut p = ArgumentParser::new();
        p.set_description(
            "Converts a TCBee recording into a SQLite or DuckDB database. The engine follows \
             -q/-d, or else the extension of the output file (.sqlite/.db, .duck/.duckdb).",
        );
        p.refer(&mut source).add_option(
            &["-s", "--source"],
            Store,
            "TCBee recording directory, or a directory to search for the latest tcbee_* \
             recording. Defaults to /tmp/",
        );
        p.refer(&mut output).add_option(
            &["-o", "--output"],
            StoreOption,
            "Path of the output database file. Defaults to /tmp/db.sqlite with -q and \
             /tmp/db.duck with -d",
        );
        p.refer(&mut sqlite)
            .add_option(&["-q", "--sqlite"], StoreTrue, "Write a SQLite database");
        p.refer(&mut duckdb)
            .add_option(&["-d", "--duckdb"], StoreTrue, "Write a DuckDB database");
        p.refer(&mut threads).add_option(
            &["-t", "--threads"],
            StoreOption,
            "Worker threads (default: number of cores)",
        );
        p.refer(&mut force).add_option(
            &["-f", "--force"],
            StoreTrue,
            "Replace the output file if it exists",
        );
        let mut full = vec!["tcbee-process".to_string()];
        full.extend_from_slice(argv);
        p.parse(full, out, err)?;
    }

    let mut fail = |msg: &str| -> i32 {
        let _ = writeln!(err, "tcbee-process: {msg}");
        2
    };

    if sqlite && duckdb {
        return Err(fail("--sqlite and --duckdb are mutually exclusive"));
    }
    if threads == Some(0) {
        return Err(fail("--threads must be at least 1"));
    }
    let (engine, output) = match (sqlite, duckdb, output) {
        (true, _, o) => (
            Engine::Sqlite,
            o.unwrap_or_else(|| DEFAULT_SQLITE.to_string()),
        ),
        (_, true, o) => (
            Engine::DuckDb,
            o.unwrap_or_else(|| DEFAULT_DUCKDB.to_string()),
        ),
        (false, false, Some(o)) => match engine_for_output(Path::new(&o)) {
            Some(e) => (e, o),
            None => {
                return Err(fail(&format!(
                    "cannot tell the engine from the extension of {o}: use .sqlite/.db or \
                     .duck/.duckdb, or select --sqlite or --duckdb"
                )))
            }
        },
        (false, false, None) => {
            return Err(fail(
                "select an engine with --sqlite or --duckdb, or give --output with a known \
                 extension (.sqlite, .db, .duck, .duckdb)",
            ))
        }
    };
    if !engine.is_enabled() {
        let (name, feature) = engine_names(engine);
        return Err(fail(&format!(
            "this build has no {name} support (rebuild with --features {feature})"
        )));
    }

    Ok(Args {
        source: PathBuf::from(source),
        output: PathBuf::from(output),
        engine,
        threads,
        force,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, (i32, String)> {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        parse_args(&argv, &mut out, &mut err).map_err(|c| {
            (
                c,
                String::from_utf8_lossy(&[out, err].concat()).into_owned(),
            )
        })
    }

    #[test]
    fn engine_follows_flags_extension_and_defaults() {
        #[cfg(feature = "sqlite")]
        {
            let a = parse(&["-q"]).unwrap();
            assert_eq!(a.engine, Engine::Sqlite);
            assert_eq!(a.output, Path::new("/tmp/db.sqlite"));
            assert_eq!(a.source, Path::new("/tmp/"));
            assert!(!a.force && a.threads.is_none());
            for name in ["x.sqlite", "x.db", "X.DB"] {
                assert_eq!(parse(&["-o", name]).unwrap().engine, Engine::Sqlite);
            }
            // A flag wins over the extension.
            assert_eq!(
                parse(&["-q", "-o", "x.duck"]).unwrap().engine,
                Engine::Sqlite
            );
            let a = parse(&["-s", "d", "-o", "o.db", "-t", "3", "-f"]).unwrap();
            assert_eq!((a.threads, a.force), (Some(3), true));
            assert_eq!(a.source, Path::new("d"));
        }
        #[cfg(feature = "duckdb")]
        {
            let a = parse(&["-d"]).unwrap();
            assert_eq!(a.engine, Engine::DuckDb);
            assert_eq!(a.output, Path::new("/tmp/db.duck"));
            for name in ["x.duck", "x.duckdb"] {
                assert_eq!(parse(&["-o", name]).unwrap().engine, Engine::DuckDb);
            }
        }
    }

    #[test]
    fn flag_errors_exit_with_2() {
        for bad in [
            &[][..],
            &["-q", "-d"],
            &["-o", "out.dat"],
            &["-o", "noext"],
            &["-q", "-t", "0"],
            &["-q", "-t", "x"],
            &["-q", "--nonsense"],
            &["-q", "-s"],
        ] {
            let (code, msg) = parse(bad).unwrap_err();
            assert_eq!(code, 2, "{bad:?}: {msg}");
            assert!(!msg.is_empty(), "{bad:?}");
        }
    }

    #[test]
    fn help_exits_with_0() {
        let (code, msg) = parse(&["-h"]).unwrap_err();
        assert_eq!(code, 0);
        assert!(msg.contains("--threads"));
    }

    #[cfg(not(feature = "duckdb"))]
    #[test]
    fn engine_not_built_in_is_a_clear_error() {
        let (code, msg) = parse(&["-d"]).unwrap_err();
        assert_eq!(code, 2);
        assert!(msg.contains("no DuckDB support"), "{msg}");
        assert_eq!(parse(&["-o", "x.duck"]).unwrap_err().0, 2);
    }

    #[cfg(not(feature = "sqlite"))]
    #[test]
    fn sqlite_not_built_in_is_a_clear_error() {
        let (code, msg) = parse(&["-q"]).unwrap_err();
        assert_eq!(code, 2);
        assert!(msg.contains("no SQLite support"), "{msg}");
    }
}
