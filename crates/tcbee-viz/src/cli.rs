//! Command line of tcbee-viz: an optional database to open.

use std::{io::Write, path::PathBuf};

use argparse::{ArgumentParser, StoreOption, StoreTrue};

use crate::backend::db::DB_EXTENSIONS;

/// Parses the command line (`argv[0]` is the program name) into the database to open, if
/// any. `Err` carries the exit code: 0 after the help or the version, 2 for a bad command
/// line.
pub fn parse_args(
    argv: Vec<String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Option<PathBuf>, i32> {
    let mut database: Option<String> = None;
    let mut version = false;
    let extensions = DB_EXTENSIONS
        .iter()
        .map(|e| format!(".{e}"))
        .collect::<Vec<_>>()
        .join(", ");
    let database_help =
        format!("Database written by tcbee-process ({extensions}). Without, pick one in the app.");
    {
        let mut p = ArgumentParser::new();
        p.set_description("Visualizes the flows in a TCBee database.");
        p.refer(&mut database)
            .add_argument("database", StoreOption, &database_help);
        p.refer(&mut version).add_option(
            &["-V", "--version"],
            StoreTrue,
            "Print the version and exit.",
        );
        p.parse(argv, out, err)?;
    }
    if version {
        let _ = writeln!(out, "{}", version_string());
        return Err(0);
    }
    Ok(database.map(PathBuf::from))
}

/// `tcbee-viz <version> (<git sha>)`; the sha is set by the CI and release builds.
pub fn version_string() -> String {
    format!(
        "tcbee-viz {} ({})",
        env!("CARGO_PKG_VERSION"),
        option_env!("TCBEE_GIT_SHA").unwrap_or("unknown")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> (Result<Option<PathBuf>, i32>, String) {
        let argv = std::iter::once("tcbee-viz")
            .chain(argv.iter().copied())
            .map(String::from)
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = parse_args(argv, &mut out, &mut err);
        (result, String::from_utf8([out, err].concat()).unwrap())
    }

    #[test]
    fn database_is_optional() {
        assert_eq!(parse(&[]).0, Ok(None));
        assert_eq!(parse(&["a.duck"]).0, Ok(Some(PathBuf::from("a.duck"))));
    }

    #[test]
    fn help_and_version_exit_with_0() {
        let (result, out) = parse(&["--help"]);
        assert_eq!(result, Err(0));
        assert!(out.contains(".duck"), "{out}");
        let (result, out) = parse(&["-V"]);
        assert_eq!(result, Err(0));
        assert_eq!(out.trim(), version_string());
    }

    #[test]
    fn unknown_flags_and_extra_arguments_exit_with_2() {
        for argv in [&["-x"][..], &["a.duck", "b.duck"], &["--bogus", "a.duck"]] {
            assert_eq!(parse(argv).0, Err(2), "{argv:?}");
        }
    }
}
