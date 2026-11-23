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
    let mut version = false;

    {
        let mut p = ArgumentParser::new();
        p.set_description(
            "Converts a TCBee recording into a SQLite or DuckDB database. The engine follows \
             --sqlite/--duckdb, or else the extension of the output file (.sqlite/.db, .duck/.duckdb). \
             Exit status: 0 success, 1 processing failed, 2 wrong arguments.",
        );
        p.refer(&mut source).add_option(
            &["-i", "--input"],
            Store,
            "TCBee recording directory, or a directory to search for the latest tcbee_* \
             recording. Defaults to /tmp/",
        );
        p.refer(&mut output).add_option(
            &["-o", "--output"],
            StoreOption,
            "Path of the output database file. Defaults to /tmp/db.sqlite with --sqlite and \
             /tmp/db.duck with --duckdb",
        );
        p.refer(&mut sqlite)
            .add_option(&["--sqlite"], StoreTrue, "Write a SQLite database");
        p.refer(&mut duckdb)
            .add_option(&["--duckdb"], StoreTrue, "Write a DuckDB database");
        p.refer(&mut threads).add_option(
            &["-j", "--threads"],
            StoreOption,
            "Worker threads (default: number of cores)",
        );
        p.refer(&mut force).add_option(
            &["-f", "--force"],
            StoreTrue,
            "Replace the output file if it exists",
        );
        p.refer(&mut version).add_option(
            &["-V", "--version"],
            StoreTrue,
            "Print the version and exit.",
        );
        let mut full = vec!["tcbee-process".to_string()];
        full.extend_from_slice(argv);
        p.parse(full, out, err)?;
    }

    if version {
        let _ = writeln!(out, "{}", version_string());
        return Err(0);
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

/// `tcbee-process <version> (<git sha>)`; the sha is set by the CI and release builds.
pub fn version_string() -> String {
    format!(
        "tcbee-process {} ({})",
        env!("CARGO_PKG_VERSION"),
        option_env!("TCBEE_GIT_SHA").unwrap_or("unknown")
    )
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
            let a = parse(&["--sqlite"]).unwrap();
            assert_eq!(a.engine, Engine::Sqlite);
            assert_eq!(a.output, Path::new("/tmp/db.sqlite"));
            assert_eq!(a.source, Path::new("/tmp/"));
            assert!(!a.force && a.threads.is_none());
            for name in ["x.sqlite", "x.db", "X.DB"] {
                assert_eq!(parse(&["-o", name]).unwrap().engine, Engine::Sqlite);
            }
            // A flag wins over the extension.
            assert_eq!(
                parse(&["--sqlite", "-o", "x.duck"]).unwrap().engine,
                Engine::Sqlite
            );
            let a = parse(&["-i", "d", "-o", "o.db", "-j", "3", "-f"]).unwrap();
            assert_eq!((a.threads, a.force), (Some(3), true));
            assert_eq!(a.source, Path::new("d"));
        }
        #[cfg(feature = "duckdb")]
        {
            let a = parse(&["--duckdb"]).unwrap();
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
            &["--sqlite", "--duckdb"],
            &["-o", "out.dat"],
            &["-o", "noext"],
            &["--sqlite", "-j", "0"],
            &["--sqlite", "-j", "x"],
            &["--sqlite", "--nonsense"],
            &["--sqlite", "-i"],
            // Old names
            &["-q"],
            &["-d"],
            &["-o", "x.db", "-s", "d"],
            &["-o", "x.db", "-t", "2"],
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

    #[test]
    fn version_exits_with_0() {
        let (code, msg) = parse(&["-V"]).unwrap_err();
        assert_eq!(code, 0);
        assert_eq!(msg.trim(), version_string());
    }

    #[cfg(not(feature = "duckdb"))]
    #[test]
    fn engine_not_built_in_is_a_clear_error() {
        let (code, msg) = parse(&["--duckdb"]).unwrap_err();
        assert_eq!(code, 2);
        assert!(msg.contains("no DuckDB support"), "{msg}");
        assert_eq!(parse(&["-o", "x.duck"]).unwrap_err().0, 2);
    }

    #[cfg(not(feature = "sqlite"))]
    #[test]
    fn sqlite_not_built_in_is_a_clear_error() {
        let (code, msg) = parse(&["--sqlite"]).unwrap_err();
        assert_eq!(code, 2);
        assert!(msg.contains("no SQLite support"), "{msg}");
    }
}
