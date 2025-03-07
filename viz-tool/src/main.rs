// bundling logic for TCP-visual-analysis tool
// authored by Evelyn Stange -> https://scattered-lenity.space

// internal imports
mod modules {
    pub mod backend;
    pub mod ui;
}

use modules::backend::app_settings::ApplicationSettings;
use modules::backend::intermediate_backend::DataSource;
use modules::ui::lib_styling::app_style_settings::{
    APP_PADDING, CHART_HEIGHT, HOME_LEFT_COL_PORTION, HOME_RIGHT_COL_PORTION,
    HORIZONTAL_LINE_PRIMARY_HEIGHT, HORIZONTAL_LINE_SECONDARY_HEIGHT, PADDING_AROUND_CONTENT,
    PADDING_BUTTON, SPACE_BETWEEN_ELEMENTS, SPACE_BETWEEN_PLOT_ROWS, SPLIT_CHART_MAX_HEIGHT,
    SPLIT_CHART_MIN_HEIGHT, TEXT_HEADLINE_1_SIZE, TEXT_HEADLINE_2_SIZE, TEXT_HEADLINE_COLOR,
};
use modules::ui::lib_widgets::lib_graphs::struct_flow_series_data::FlowSeriesData;
use modules::ui::lib_widgets::lib_graphs::struct_processed_plot_data::ProcessedPlotData;

use modules::ui::lib_screens::{
    screen_database_modification::{MessageModifyDatabase, ScreenModifyDatabase},
    screen_home::{MessageHome, ScreenHome},
    screen_multiple_flow_plotting::{MessageMultiFlowPlotting, ScreenMultiFlowPlotting},
    screen_settings::{MessageSettings, ScreenSettings},
    screen_single_flow_plotting::{MessagePlotting, ScreenSingleFlowPlotting},
    trait_screen::Screen,
};

// external imports

use iced::Theme;
use iced_aw::style::tab_bar;
use iced_table::Table;

use iced::Element;
use iced_aw::Tabs;
use ts_storage::{DataValue, TSDBInterface};
use std::cell::RefCell;
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::{Duration, Instant};

// ---- //
// --- //

// fn main() -> iced::Result {
fn main() -> iced::Result {
    println!("Hi, this application was written by Evelyn :>\n this message is a secret");
    iced::application("TCPFLOW", StateContainer::update, StateContainer::view)
        .theme(StateContainer::theme)
        .run()
}

pub struct StateContainer {
    screen: ActiveScreen,

    screen_settings: ScreenSettings,
    screen_home: ScreenHome,
    screen_plotting: ScreenSingleFlowPlotting,
    screen_multi_flow_plotting: ScreenMultiFlowPlotting,
    screen_modify_database: ScreenModifyDatabase,
    application_settings: Arc<RwLock<ApplicationSettings>>,
    theme: Theme,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum ActiveScreen {
    Home,
    Settings,
    SingleGraphPlot,
    MultipleGraphPlot,
    DatabaseModification,
}

impl ToString for ActiveScreen {
    fn to_string(&self) -> String {
        match self {
            ActiveScreen::Home => String::from("Home"),
            ActiveScreen::SingleGraphPlot => String::from("Analyse Single Flow"),
            ActiveScreen::Settings => String::from("Settings"),
            ActiveScreen::MultipleGraphPlot => String::from("Analyse Multiple Flows"),
            ActiveScreen::DatabaseModification => String::from("Modify Database"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    TabSelected(ActiveScreen),
    TabClosed(ActiveScreen),
    ScreenSettings(MessageSettings),
    ScreenSingleFlowPlot(MessagePlotting),
    ScreenMultipleFlowPlot(MessageMultiFlowPlotting),
    ScreenHome(MessageHome),
    ScreenModifyDatabase(MessageModifyDatabase),
}

impl Default for StateContainer {
    fn default() -> Self {
        let settings = Arc::new(RwLock::new(ApplicationSettings::new()));
        Self {
            screen: ActiveScreen::Home,
            screen_settings: ScreenSettings::new(settings.clone()),
            screen_home: ScreenHome::new(settings.clone()),
            screen_plotting: ScreenSingleFlowPlotting::new(settings.clone()),
            screen_multi_flow_plotting: ScreenMultiFlowPlotting::new(settings.clone()),
            screen_modify_database: ScreenModifyDatabase::new(settings.clone()),
            application_settings: settings,
            // theme: Theme::CatppuccinFrappe,
            theme: Theme::GruvboxLight,
        }
    }
}

// Implementations for ICED
impl StateContainer {
    fn update(&mut self, message: Message) {
        print!("{esc}c", esc = 27 as char);
        match message {
            Message::TabSelected(new_screen) => {
                match self.screen {
                    ActiveScreen::DatabaseModification => {
                        self.screen_modify_database.reset();
                    }
                    ActiveScreen::SingleGraphPlot => {
                        self.screen_plotting.reset();
                    }
                    ActiveScreen::MultipleGraphPlot => {
                        self.screen_multi_flow_plotting.reset();
                    }
                    _ => {

                    }
                }
                self.screen = new_screen
            }
            Message::TabClosed(_) => {}
            Message::ScreenSettings(message) => self.screen_settings.update(message),
            Message::ScreenHome(message) => self.screen_home.update(message),
            Message::ScreenSingleFlowPlot(message) => self.screen_plotting.update(message),
            Message::ScreenMultipleFlowPlot(message) => {
                self.screen_multi_flow_plotting.update(message)
            }
            Message::ScreenModifyDatabase(message) => self.screen_modify_database.update(message),
        }
    }

    fn view(&self) -> Element<Message> {
        Tabs::new(Message::TabSelected)
            .tab_icon_position(iced_aw::tabs::Position::Top)
            .tab_bar_position(iced_aw::TabBarPosition::Top)
            .tab_bar_style(tab_bar::primary)
            .on_close(Message::TabClosed)
            // adding tabs to attach
            .push(
                ActiveScreen::Home,
                self.screen_home.tab_label(),
                self.screen_home.view(),
            )
            .push(
                ActiveScreen::SingleGraphPlot,
                self.screen_plotting.tab_label(),
                self.screen_plotting.view(),
            )
            .push(
                ActiveScreen::DatabaseModification,
                self.screen_modify_database.tab_label(),
                self.screen_modify_database.view(),
            )
            .push(
                ActiveScreen::MultipleGraphPlot,
                self.screen_multi_flow_plotting.tab_label(),
                self.screen_multi_flow_plotting.view(),
            )
            .push(
                ActiveScreen::Settings,
                self.screen_settings.tab_label(),
                self.screen_settings.view(),
            )
            .set_active_tab(&self.screen)
            .into()
    }

    pub fn theme(&self) -> Theme {
        self.theme.clone()
    }
}
