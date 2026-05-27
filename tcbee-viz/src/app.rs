use std::path::PathBuf;

use crate::{
    backend::db::DbBackend,
    settings::AppSettings,
    ui::{
        tab_home::TabHome, tab_multi_flow::TabMultiFlow, tab_process::TabProcess,
        tab_settings::TabSettings, tab_single_flow::TabSingleFlow, theme,
    },
};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Tab {
    Home,
    Single,
    Multi,
    Process,
    Settings,
}

const TABS: &[(Tab, &str)] = &[
    (Tab::Home, "Home"),
    (Tab::Single, "Single Flow"),
    (Tab::Multi, "Multi Flow"),
    (Tab::Process, "Process"),
    (Tab::Settings, "Settings"),
];

pub struct TcbeeApp {
    active_tab: Tab,
    settings: AppSettings,
    db: DbBackend,

    tab_home: TabHome,
    tab_single: TabSingleFlow,
    tab_multi: TabMultiFlow,
    tab_process: TabProcess,
    tab_settings: TabSettings,
}

impl Default for TcbeeApp {
    fn default() -> Self {
        Self {
            active_tab: Tab::Home,
            settings: AppSettings::default(),
            db: DbBackend::default(),
            tab_home: TabHome::default(),
            tab_single: TabSingleFlow::default(),
            tab_multi: TabMultiFlow::default(),
            tab_process: TabProcess::default(),
            tab_settings: TabSettings::default(),
        }
    }
}

impl eframe::App for TcbeeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        theme::apply(ctx, self.settings.dark_mode, self.settings.text_size);

        // Tab bar
        egui::TopBottomPanel::top("tab_bar")
            .exact_height(48.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::TOP_BAR_BG)
                    .inner_margin(egui::Margin::symmetric(14, 8)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(
                        egui::RichText::new("TCBee")
                            .strong()
                            .size(self.settings.text_size + 2.0)
                            .color(theme::TOP_BAR_TEXT),
                    );
                    ui.add_space(16.0);

                    for &(tab, label) in TABS {
                        let selected = self.active_tab == tab;
                        let button = egui::Button::new(egui::RichText::new(label).strong().color(
                            if selected {
                                egui::Color32::WHITE
                            } else {
                                theme::TOP_BAR_TEXT
                            },
                        ))
                        .fill(if selected {
                            theme::TOP_BAR_ACTIVE
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .stroke(egui::Stroke::new(
                            1.0,
                            if selected {
                                theme::TOP_BAR_ACTIVE
                            } else {
                                egui::Color32::TRANSPARENT
                            },
                        ));
                        if ui.add(button).clicked() && !selected {
                            self.reset_tab(self.active_tab);
                            self.active_tab = tab;
                        }
                    }
                });
            });

        // Main content
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::app_bg(self.settings.dark_mode)))
            .show(ctx, |ui| match self.active_tab {
                Tab::Home => {
                    self.tab_home.show(ui, &mut self.db, &mut self.settings);
                }
                Tab::Single => {
                    self.tab_single.show(ui, &self.db, &self.settings);
                }
                Tab::Multi => {
                    self.tab_multi.show(ui, &self.db, &self.settings);
                }
                Tab::Process => {
                    self.tab_process.show(ui, &self.db, &self.settings);
                }
                Tab::Settings => {
                    self.tab_settings.show(ui, &mut self.settings);
                }
            });
    }
}

impl TcbeeApp {
    pub fn new(database_path: Option<PathBuf>) -> Self {
        let mut app = Self::default();

        if let Some(path) = database_path {
            match DbBackend::open(path.clone()) {
                Ok(db) => {
                    app.db = db;
                    app.tab_home
                        .set_status(format!("Connected: {}", path.to_string_lossy()));
                }
                Err(e) => {
                    app.tab_home.set_status(format!(
                        "Error opening {}: {}",
                        path.to_string_lossy(),
                        e
                    ));
                }
            }
        }

        app
    }

    fn reset_tab(&mut self, tab: Tab) {
        match tab {
            Tab::Single => self.tab_single.reset(),
            Tab::Multi => self.tab_multi.reset(),
            Tab::Process => self.tab_process.reset(),
            _ => {}
        }
    }
}
