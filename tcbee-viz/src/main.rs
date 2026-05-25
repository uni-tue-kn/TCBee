mod app;
mod backend;
mod data;
mod settings;
mod ui;

use app::TcbeeApp;

fn main() -> eframe::Result {
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

    eframe::run_native("TCBee", options, Box::new(|_cc| Ok(Box::new(TcbeeApp::default()))))
}
