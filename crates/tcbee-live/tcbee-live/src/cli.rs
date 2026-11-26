//! Command line of tcbee-live, parsed before anything touches the kernel, so that `--help`
//! works without root.

use std::{collections::HashSet, io::Write};

use argparse::{ArgumentParser, Store, StoreTrue};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Args {
    /// Ports whose flows are selected as soon as they appear
    pub ports: HashSet<u16>,
    pub combined_plot: bool,
    pub auto_fit_x: bool,
}

/// Parses the command line (`argv[0]` is the program name). `Err` carries the exit code:
/// 0 after the help or the version, 2 for a bad command line.
pub fn parse_args(
    argv: Vec<String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Args, i32> {
    let mut ports = String::new();
    let mut args = Args::default();
    let mut version = false;
    {
        let mut p = ArgumentParser::new();
        p.set_description(
            "Live plot of the congestion window of TCP flows on this host (needs root).",
        );
        p.refer(&mut ports).add_option(
            &["--ports"],
            Store,
            "Comma-separated local or remote ports whose flows are selected as soon as they appear.",
        );
        p.refer(&mut args.combined_plot).add_option(
            &["--combined-plot"],
            StoreTrue,
            "Start with all selected flows shown on a single combined chart.",
        );
        p.refer(&mut args.auto_fit_x).add_option(
            &["--auto-fit-x"],
            StoreTrue,
            "Start with the x-axis locked to 0 → now, tracking the latest event.",
        );
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
    for port in ports.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match port.parse() {
            Ok(port) => {
                args.ports.insert(port);
            }
            Err(_) => {
                let _ = writeln!(err, "tcbee-live: --ports: '{port}' is not a port number");
                return Err(2);
            }
        }
    }
    Ok(args)
}

/// `tcbee-live <version> (<git sha>)`; the sha is set by the CI and release builds.
pub fn version_string() -> String {
    format!(
        "tcbee-live {} ({})",
        env!("CARGO_PKG_VERSION"),
        option_env!("TCBEE_GIT_SHA").unwrap_or("unknown")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> (Result<Args, i32>, String, String) {
        let argv = std::iter::once("tcbee-live")
            .chain(argv.iter().copied())
            .map(String::from)
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = parse_args(argv, &mut out, &mut err);
        (
            result,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn flags_parse() {
        let args = parse(&["--ports", "5201, 443", "--combined-plot", "--auto-fit-x"])
            .0
            .unwrap();
        assert_eq!(args.ports, HashSet::from([5201, 443]));
        assert!(args.combined_plot && args.auto_fit_x);
        assert_eq!(parse(&[]).0, Ok(Args::default()));
    }

    #[test]
    fn bad_command_lines_exit_with_2() {
        for argv in [
            &["--ports", "http"][..],
            &["--ports", "70000"],
            &["--select-port", "5201"],
            &["--bogus"],
        ] {
            assert_eq!(parse(argv).0, Err(2), "{argv:?}");
        }
    }

    #[test]
    fn help_and_version_exit_with_0() {
        let (result, out, _) = parse(&["-h"]);
        assert_eq!(result, Err(0));
        assert!(out.contains("--ports"), "{out}");
        let (result, out, _) = parse(&["-V"]);
        assert_eq!(result, Err(0));
        assert_eq!(out.trim(), version_string());
    }
}
