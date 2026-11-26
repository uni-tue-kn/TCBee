mod app;
mod backend;
mod cli;
mod data;
mod export;
mod logo;
mod plot_style;
mod settings;
mod ui;

use app::TcbeeApp;

fn main() -> eframe::Result {
    // A path that is not UTF-8 would make env::args panic; argparse takes strings
    let Ok(argv) = std::env::args_os().map(|a| a.into_string()).collect() else {
        eprintln!("tcbee-viz: arguments must be valid UTF-8");
        std::process::exit(2);
    };
    let database_path = match cli::parse_args(argv, &mut std::io::stdout(), &mut std::io::stderr())
    {
        Ok(path) => path,
        Err(code) => std::process::exit(code),
    };
    let ascii_name = r#"
 ______________  ______   ____ _      __
/_  __/ ___/ _ \/ __/ /  / __ \ | /| / /
 / / / /__/ ___/ _// /__/ /_/ / |/ |/ /
/_/  \___/_/  /_/ /____/\____/|__/|__/
"#;
    println!("{}", ascii_name);

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
