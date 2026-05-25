mod app;
mod backend;
mod data;
mod settings;
mod ui;

use std::path::PathBuf;

use app::TcbeeApp;

fn main() -> eframe::Result {
    let ascii_name = r#"
 ______________  ______   ____ _      __
/_  __/ ___/ _ \/ __/ /  / __ \ | /| / /
 / / / /__/ ___/ _// /__/ /_/ / |/ |/ /
/_/  \___/_/  /_/ /____/\____/|__/|__/
"#;
    println!("{}", ascii_name);
    let database_path = parse_database_path_arg();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("TCBee — TCP Flow Visualizer")
            .with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };

    eframe::run_native(
        "TCBee",
        options,
        Box::new(|_cc| Ok(Box::new(TcbeeApp::new(database_path)))),
    )
}

fn parse_database_path_arg() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next()?;

    if first == "--help" || first == "-h" {
        println!("Usage: tcbee-viz [DATABASE.sqlite|DATABASE.duck]");
        return None;
    }

    if let Some(extra) = args.next() {
        eprintln!(
            "Ignoring extra command line argument: {}",
            extra.to_string_lossy()
        );
    }

    Some(PathBuf::from(first))
}
