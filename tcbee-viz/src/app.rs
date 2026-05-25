use crate::{
    backend::db::DbBackend,
    settings::AppSettings,
    ui::{
        tab_home::TabHome,
        tab_multi_flow::TabMultiFlow,
        tab_process::TabProcess,
        tab_settings::TabSettings,
        tab_single_flow::TabSingleFlow,
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
        // Apply dark/light mode
        ctx.set_visuals(if self.settings.dark_mode {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });

        // Apply font size
        let mut style = (*ctx.style()).clone();
        style.text_styles.values_mut().for_each(|s| s.size = self.settings.text_size);
        ctx.set_style(style);

        // Tab bar
        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                for &(tab, label) in TABS {
                    if ui.selectable_label(self.active_tab == tab, label).clicked()
                        && self.active_tab != tab
                    {
                        self.reset_tab(self.active_tab);
                        self.active_tab = tab;
                    }
                }
            });
        });

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
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
            }
        });
    }
}

impl TcbeeApp {
    fn reset_tab(&mut self, tab: Tab) {
        match tab {
            Tab::Single => self.tab_single.reset(),
            Tab::Multi => self.tab_multi.reset(),
            Tab::Process => self.tab_process.reset(),
            _ => {}
        }
    }
}
