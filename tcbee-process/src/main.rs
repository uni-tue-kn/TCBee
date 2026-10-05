use std::process::ExitCode;

fn main() -> ExitCode {
    env_logger::init();

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args =
        match tcbee_process::parse_args(&argv, &mut std::io::stdout(), &mut std::io::stderr()) {
            Ok(args) => args,
            Err(code) => return ExitCode::from(code as u8),
        };

    match tcbee_process::run(args) {
        Ok(summary) => {
            for w in &summary.warnings {
                eprintln!("warning: {w}");
            }
            for s in &summary.skipped {
                eprintln!("skipped {s}: {}", tcbee_process::NO_DECODER);
            }
            eprintln!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}
