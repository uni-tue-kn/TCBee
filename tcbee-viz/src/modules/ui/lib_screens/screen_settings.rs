// logic managing settings of application
// contains settings-screen build with ICED

// contains logic for Settings-Screen from Application

use iced::widget::{
    checkbox, column, radio, row, slider, text, Button, Column, Container, Row, Rule, Text,
};
use iced::{Center, Color, Fill};
use iced::{Element, Length};
use iced_aw::tab_bar::{StyleFn, TabLabel};
// use rust_ts_storage::TSDBInterface;

use crate::modules::ui::lib_styling::app_style_settings::PADDING_AROUND_CONTENT;
use crate::modules::ui::{
    lib_styling::app_style_settings::{
        HORIZONTAL_LINE_PRIMARY_HEIGHT, HORIZONTAL_LINE_SECONDARY_HEIGHT, SPACE_BETWEEN_ELEMENTS,
        TEXT_ACCENT_1_COLOR, TEXT_HEADLINE_0_SIZE, TEXT_HEADLINE_1_SIZE,
    },
    lib_widgets::app_widgets::generate_padded_layout,
};

use crate::ApplicationSettings;
use crate::{DataSource, Message, Screen};

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
// use debug::{generate_data_set, give_random_number};
// use std::time::{SystemTime, UNIX_EPOCH};

// Denotes messages related to settings tab
#[derive(Debug, Clone, PartialEq)]
pub enum MessageSettings {
    TextSizeChanged(u16),
    DebugVisibilityChanged(bool),
    ReduceDensityOnZoomChanged(bool),
    ReduceDensityOnZoomValue(usize),
    DatabasePathChanged(Option<PathBuf>),
    GraphPointSeriesThresholdChanged(f64),
    DataValueSkipAmountChanged(u32),
}

#[derive(Clone)]
pub struct ScreenSettings {
    application_settings: Arc<RwLock<ApplicationSettings>>,
    // settings: ApplicationSettings
}

// implementing logic for struct

impl ScreenSettings {
    pub fn new(settings_reference: Arc<RwLock<ApplicationSettings>>) -> Self {
        ScreenSettings {
            // settings: ApplicationSettings::new(),
            application_settings: settings_reference,
        }
    }
}

// ---  /
// -- / ICED Logic

impl ScreenSettings {
    pub fn update(&mut self, message: MessageSettings) {
        let mut write_settings = self.application_settings.write().unwrap();
        match message {
            // SettingsMessage::ColorChanged(val) => self.settings.tab_color = val,
            MessageSettings::TextSizeChanged(new_size) => {
                write_settings.text_size = new_size;
            }
            MessageSettings::DebugVisibilityChanged(display_debug) => {
                write_settings.display_debug = display_debug
            }
            MessageSettings::DatabasePathChanged(potential_path) => {
                // FIXME improve
                // checking whether valid path was given or not:
                match potential_path {
                    Some(new_path) => {
                        // updating database to new connection!
                        write_settings.database_path = Some(new_path);
                    }
                    _ => {
                        write_settings.database_path = None;
                    }
                }
            }
            MessageSettings::DataValueSkipAmountChanged(new_amount) => {
                write_settings.datavalue_skip_counter = new_amount;
            }
            MessageSettings::GraphPointSeriesThresholdChanged(new_threshold) => {
                write_settings.graph_pointseries_threshold = new_threshold;
            }
            MessageSettings::ReduceDensityOnZoomChanged(new_val) => {
                write_settings.reduce_point_density_on_zoom = new_val
            }
            MessageSettings::ReduceDensityOnZoomValue(new_val) => {
                write_settings.amount_to_skip_on_zoom = new_val
            }
        }
    }

    fn display_sidebar(&self) -> Element<'_, MessageSettings> {
        let headline = text("Adjust Settings").size(TEXT_HEADLINE_1_SIZE);
        let description = text(
            "
Adjust Settings for the whole application\n
Those are not stored for different sessions however\n
        ",
        );

        let left_content = Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .width(Length::FillPortion(1))
            .push(headline)
            .push(description);

        left_content.into()
    }

    fn display_text_size_slider(&self, current_size: u16) -> Element<MessageSettings> {
        let size_slider = slider(1..=20, current_size, MessageSettings::TextSizeChanged);
        size_slider.into()
    }

    // fn display_point_reduction_slider(&self, current_size: usize) -> Element<MessageSettings> {
    //     let size_slider = slider(20..=4000, current_size, MessageSettings::ReduceDensityOnZoomValue)
    //     .step(1)
    //     ;
    //     size_slider.into()
    // }

    fn display_checkbox_point_reduction_on_zoom(&self, state: bool) -> Element<MessageSettings> {
        let headline = text("Reduce Points When Zooming").size(TEXT_HEADLINE_1_SIZE);
        let description = 
            text("reduce the amount of points displayed when zooming. Might help with performance issues");
        let checkbox =
            checkbox("Reduce Points", state).on_toggle(MessageSettings::ReduceDensityOnZoomChanged);

        let content = Column::new()
            .padding(SPACE_BETWEEN_ELEMENTS)
            .push(headline)
            .push(description)
            .push(checkbox);
        content.into()
    }

    fn display_checkbox_debug(&self, state: bool) -> Element<MessageSettings> {
        let headline = text("Enable Debug View").size(TEXT_HEADLINE_1_SIZE);
        let description =
            text("Draw black border around every element, helps to configure visual components");
        let checkbox = checkbox("Enable Debug Visualization for application", state)
            .on_toggle(MessageSettings::DebugVisibilityChanged);

        let content = Column::new()
            .padding(SPACE_BETWEEN_ELEMENTS)
            .push(headline)
            .push(description)
            .push(checkbox);
        content.into()
    }

    fn display_pointseries_threshold_slider(&self, current_value: f64) -> Element<MessageSettings> {
        let headline = text("Change Point-Series Threshhold").size(TEXT_HEADLINE_1_SIZE);
        let description = text("Set amount of datapoints to skip when displaying data. I.e. 5 will drop value 1,2,3,4 and retain 5");
        let current_val = text(format!("Currently Selected: {:?}", current_value));
        let slider = slider(
            1.0..=20.0,
            current_value,
            MessageSettings::GraphPointSeriesThresholdChanged,
        );
        let content: Element<'_, MessageSettings> = Column::new()
            .padding(SPACE_BETWEEN_ELEMENTS)
            .push(headline)
            .push(description)
            .push(current_val)
            .push(slider)
            .into();

        content
    }

    fn display_point_skipcounter_slider(&self, current_val: u32) -> Element<MessageSettings> {
        let headline = text("Change Points Displayed").size(TEXT_HEADLINE_1_SIZE);
        let description = text(
            "
Adjust the amount of datapoints displayed in graph-view.\n
By adjusting this value every nth datapoint will be skipped and not be displayed.\n
This operation does not change any data-collections, only the values to displayed are modified.\n
Use this in order to decrease the amount of points, likely increasing performance.\n
The default value of 1 does not skip any values.",
        );
        let selected_value = text(format!("Currently Selected: {:?}", current_val));
        let size_slider = slider(
            1..=100,
            current_val,
            MessageSettings::DataValueSkipAmountChanged,
        );
        let content = Column::new()
            // .spacing(SPACE_BETWEEN_ELEMENTS)
            .push(headline)
            .push(description)
            .push(selected_value)
            .push(size_slider);
        content.into()
    }

    fn display_settings(&self) -> Element<'_, MessageSettings> {
        let read_settings = self.application_settings.read().unwrap();
        let current_text_size = read_settings.text_size;
        let current_debug = read_settings.display_debug;
        let current_point_reduction = read_settings.reduce_point_density_on_zoom;
        let current_pointseries_threshold = read_settings.graph_pointseries_threshold;
        let current_skip_counter = read_settings.datavalue_skip_counter;
        let current_database_path = read_settings.database_path.clone();

        let text_size_description = text(format!(
            "Set text-size for application.current size:{:?}",
            current_text_size
        ));
        let text_slider = self.display_text_size_slider(current_text_size);
        let debug_checkbox = self.display_checkbox_debug(current_debug);
        let point_reduction_checkbox =
            self.display_checkbox_point_reduction_on_zoom(current_point_reduction);

        let series_threshold_slider =
            self.display_pointseries_threshold_slider(current_pointseries_threshold);
        let skip_counter_slider = self.display_point_skipcounter_slider(current_skip_counter);

        let content = Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS * 2)
            .width(Length::FillPortion(4))
            .push(text("Settings Application").size(TEXT_HEADLINE_0_SIZE))
            .push(text_size_description)
            .push(text_slider)
            .push(debug_checkbox)
            .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(text("Settings For Plotting").size(TEXT_HEADLINE_0_SIZE))
            .push(series_threshold_slider)
            .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(point_reduction_checkbox)
            .push(skip_counter_slider);
        content.into()
    }
}

impl Screen for ScreenSettings {
    type Message = Message;

    fn title(&self) -> String {
        "Settings".to_string()
    }

    fn receive_settings(&self) -> &Arc<RwLock<ApplicationSettings>> {
        &self.application_settings
    }

    // FIXME -> add icons?
    fn tab_label(&self) -> TabLabel {
        TabLabel::Text(self.title())
    }

    fn content(&self) -> Element<'_, Self::Message> {
        let sidebar = self.display_sidebar();
        let settings = self.display_settings();
        let inner_count = Row::new().push(sidebar).push(settings);

        let window_content: Element<'_, MessageSettings> =
            generate_padded_layout::<MessageSettings>(PADDING_AROUND_CONTENT)
                .push(text("Settings!").size(TEXT_HEADLINE_0_SIZE))
                .push(Rule::horizontal(HORIZONTAL_LINE_PRIMARY_HEIGHT))
                .push(inner_count)
                .into();

        window_content.map(Message::ScreenSettings)
    }

    fn reset(&mut self) {
        
    }
}
