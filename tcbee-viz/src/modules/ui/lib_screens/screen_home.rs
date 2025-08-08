// logic managing Home menu of application
// contains screen to select DataSource
// displays additional information

// -- internal imports
use crate::{
    modules::{
        backend::lib_system_io::receive_source_from_path,
        ui::{
            lib_styling::app_style_settings::{
                HOME_LEFT_COL_PORTION, HOME_RIGHT_COL_PORTION, HORIZONTAL_LINE_PRIMARY_HEIGHT,
                HORIZONTAL_LINE_SECONDARY_HEIGHT, PADDING_AROUND_CONTENT, PADDING_BUTTON,
                SPACE_BETWEEN_ELEMENTS, SPACE_BETWEEN_PLOT_ROWS, TEXT_HEADLINE_0_SIZE,
                TEXT_HEADLINE_1_SIZE, TEXT_HEADLINE_2_SIZE,
            },
            lib_widgets::app_widgets::{generate_padded_layout, section},
        },
    },
    ApplicationSettings, DataSource, Message, Screen,
};

// -- external imports
use iced::{
    advanced::Text, alignment, widget::{button, column, row, scrollable, text, Button, Column, Row, Rule, Space}, Alignment, Color, Element, Length
};
use iced_aw::TabLabel;
use rfd::FileDialog;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageHome {
    DataSourceSelected(DataSource),
    OutputPathSet(PathBuf),
    // FIXME also add to settings --> simplify access
    ButtonDatabasePathPressed,
}

#[derive(Clone)]
pub struct ScreenHome {
    application_settings: Arc<RwLock<ApplicationSettings>>,
    pub output_selected: Option<PathBuf>,
}

impl ScreenHome {
    pub fn new(settings_reference: Arc<RwLock<ApplicationSettings>>) -> Self {
        ScreenHome {
            output_selected: None,
            application_settings: settings_reference,
        }
    }

    pub fn set_source(&mut self, new_source: Option<DataSource>) {
        let mut write_settings = self.application_settings.write().unwrap();
        write_settings.datasource = new_source;
    }

    fn display_selection_button(&self) -> Column<'_, MessageHome> {
        let selection_button = button("Select Database")
            .padding(PADDING_BUTTON)
            .on_press(MessageHome::ButtonDatabasePathPressed);
        let wrapper = Column::new()
            .push(selection_button)
            .align_x(Alignment::Center);
        wrapper
    }

    fn display_sidebar(&self) -> Element<'_, MessageHome> {
        let headline = text("Selecting Database").size(TEXT_HEADLINE_0_SIZE);
        let description = text(
            "
This program aims to visualize recorded metrics TCP-Flows for an explorative analysis.\n
Its able to visualize single and multiple flows with their corresponding timeseries information.\n
Modification of the database is supplied via an extendable feature-system.\n
            ",
        );

        let read_settings = self.application_settings.read().unwrap();
        let selected_database = read_settings.database_path.clone();
        let is_debug_display = read_settings.display_debug;
        let maybe_selected_db = match selected_database {
            Some(db) => format!("Selected Database:{:?}", db),
            _ => String::from("No Database Selected"),
        };

        let left_content: Element<'_, MessageHome> = Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .width(Length::FillPortion(HOME_LEFT_COL_PORTION))
            .push(headline)
            .push(Rule::horizontal(HORIZONTAL_LINE_PRIMARY_HEIGHT))
            .push(self.display_selection_button())
            .push(Rule::horizontal(HORIZONTAL_LINE_PRIMARY_HEIGHT))
            .push(text(maybe_selected_db))
            .push(Rule::horizontal(HORIZONTAL_LINE_PRIMARY_HEIGHT))
            .push(description)
            .into();

        if is_debug_display {
            left_content.explain(Color::BLACK)
        } else {
            left_content
        }
    }

    fn display_explanation(&self) -> Element<'_, MessageHome> {
        let read_settings = self.application_settings.read().unwrap();
        let is_display_debug = read_settings.display_debug;
        let headline = text("Usage Of Tool").size(TEXT_HEADLINE_0_SIZE);
        let mut explanation_content = Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS);

        explanation_content = section(explanation_content, "Home", "The starting screen where you can select the database file containing recorded TCP flow data. If the button to open a file is not visible, increase the window size.");
        explanation_content = section(explanation_content, "Plot Single Flow", "Allows you to visualize various metrics for an individual TCP flow over time. Flows are identified by their IP 5-tuple (source/destination IP and port, protocol) and sorted by start time. Multiple metrics can be plotted simultaneously, either overlaid on a single graph or split into separate graphs. Tools for zooming and adjusting plot layout are available.");
        explanation_content = section(explanation_content, "Process", "Provides functionality to calculate derived TCP metrics that are not directly recorded. This is done through plugins (e.g., modules that compute window size). Calculated results can be previewed and stored in the loaded database for later analysis.");
        explanation_content = section(explanation_content, "Multi Flow", "Enables side-by-side comparison of metrics from two TCP flows. Useful for analyzing interactions between concurrent flows, such as bandwidth sharing. The interface and plotting tools are similar to the Plot Single Flow tab but support dual selection.");
        explanation_content = section(explanation_content, "Settings", "Contains configurable options for the application. Some settings may not be fully implemented or relevant for all use cases, but users can explore them to customize their experience.");

        let content: Element<'_, MessageHome> = Column::new()
            .width(Length::FillPortion(HOME_RIGHT_COL_PORTION))
            .push(headline)
            .push(Rule::horizontal(HORIZONTAL_LINE_PRIMARY_HEIGHT))
            .push(Space::with_height(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(scrollable(explanation_content))
            .into();
        if is_display_debug {
            content.explain(Color::BLACK)
        } else {
            content
        }
    }
}

// --- /
// -- / ICED Logic

impl ScreenHome {
    pub fn update(&mut self, message: MessageHome) {
        match message {
            MessageHome::DataSourceSelected(new_source) => {
                let mut write_settings = self.application_settings.write().unwrap();
                write_settings.datasource = Some(new_source);
            }

            MessageHome::OutputPathSet(new_output) => self.output_selected = Some(new_output),

            // FIXME adapt to application_settings struct
            MessageHome::ButtonDatabasePathPressed => {
                // opening file dialog to allow selection of file
                // FIXME maybe async this operation?

                let file_selection = FileDialog::new()
                    .add_filter("*.sqlite or *.duck", &["sqlite","duck"])
                    .set_directory("~/")
                    .pick_file();
                // FIXME improve error handling
                println!("path selected {:?}", &file_selection);
                match file_selection {
                    Some(path) => {
                        // extracting extension from supplied file:
                        let extension_choosen = receive_source_from_path(&path);

                        let mut write_settings = self.application_settings.write().unwrap();
                        write_settings.datasource = extension_choosen;
                        // write_settings.database_path = Some(file_selection);
                        write_settings.set_new_database_connection(path);
                    }
                    _ => {
                        println!("no path was selected, aborting");
                    }
                }
                //
            }
        }
    }
}

impl Screen for ScreenHome {
    type Message = Message;

    fn title(&self) -> String {
        "Home".to_string()
    }

    fn receive_settings(&self) -> &Arc<RwLock<ApplicationSettings>> {
        &self.application_settings
    }

    fn tab_label(&self) -> iced_aw::TabLabel {
        TabLabel::Text(self.title())
    }

    fn content(&self) -> Element<'_, Self::Message> {
        let headline_app = text("TCP-Analysis-Tool").size(40);
        let app_infos =
            text("\nwith love by Evelyn Esther Aurora Stange").size(TEXT_HEADLINE_2_SIZE);
        let sidebar = self.display_sidebar();
        let explanation_field = self.display_explanation();

        let headline_content: Element<'_, MessageHome> = Row::new()
            .height(Length::Shrink)
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .push(headline_app)
            .push(app_infos)
            .into();

        let inner_content: Element<'_, MessageHome> = Row::new()
            .push(sidebar)
            .push(Rule::vertical(SPACE_BETWEEN_PLOT_ROWS * 4.0))
            .push(explanation_field)
            .into();

        let window_content: Element<'_, MessageHome> = generate_padded_layout::<MessageHome>(PADDING_AROUND_CONTENT)
            .push(headline_content)
            .push(inner_content)
            .into();
        // let window_content = generate_one_fourth_layout::<MessageHome>(headline_content, sidebar, explanation_field)
        window_content.map(Message::ScreenHome)
    }
    fn reset(&mut self) {
        
    }
}
