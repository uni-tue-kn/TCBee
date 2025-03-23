// contains logic for database modification
//
//

use iced::{
    widget::{button, pick_list, scrollable, text, Button, Column, Container, Row, Rule, Space},
    Alignment, Element, Length,
};
use iced_aw::TabLabel;
use plotters_iced::ChartWidget;

use crate::{
    modules::{
        backend::{
            database_processor::{
                processor_dummy,
                trait_database_processor::{PreProcessor, ProcessorImplementation},
            },
            struct_tcp_flow_wrapper::TcpFlowWrapper,
        },
        ui::{
            lib_styling::app_style_settings::{
                CHART_HEIGHT, HORIZONTAL_LINE_SECONDARY_HEIGHT, PADDING_AROUND_CONTENT, SPACE_BETWEEN_ELEMENTS, SPACE_BETWEEN_PLOT_ROWS, SPACE_BETWEEN_TEXT, SPLIT_CHART_MAX_HEIGHT, TEXT_HEADLINE_0_SIZE, TEXT_HEADLINE_1_SIZE, TEXT_HEADLINE_2_SIZE
            },
            lib_widgets::{
                app_widgets::{
                    display_empty_screen_no_data, display_flow_selector, generate_padded_layout,
                },
                lib_graphs::{
                    single_chart_processed_plot_data::MessageCreator,
                    struct_flow_series_data::FlowSeriesData,
                    struct_processed_plot_data::ProcessedPlotData,
                    struct_zoom_bounds::{retrieve_max_series_bound, ZoomBound2D},
                },
            },
        },
    },
    ApplicationSettings, Arc, Message, RwLock, Screen,
};

const FLOW_1_SELECTION_PORTION: u16 = 1;
const MODULE_SELECTION_PORTION: u16 = 1;
const WINDOW_GRAPH_PORTION: u16 = 3;

#[derive(Debug, Clone, PartialEq)]
pub enum MessageModifyDatabase {
    ModuleSelected(ProcessorImplementation),
    MouseEvent(iced::mouse::Event, iced::Point),
    FlowSelected(i64),
    PreviewRequested,
    SaveToDatabase,
}

impl MessageCreator for MessageModifyDatabase {
    fn create_mouse_event_message(event: iced::mouse::Event, point: iced::Point) -> Self {
        MessageModifyDatabase::MouseEvent(event, point)
    }
}

pub struct ScreenModifyDatabase {
    application_settings: Arc<RwLock<ApplicationSettings>>,
    selected_model: Option<ProcessorImplementation>,
    selected_flow: TcpFlowWrapper,
    flow_data: Option<ProcessedPlotData>,
    // bundle_of_new_series: Option<FlowSeriesData>,
    render_chart: bool,
    status_message: Option<String>,
}

impl ScreenModifyDatabase {
    pub fn new(settings_reference: Arc<RwLock<ApplicationSettings>>) -> Self {
        ScreenModifyDatabase {
            application_settings: settings_reference,
            selected_model: None,
            selected_flow: TcpFlowWrapper::default(),
            flow_data: None,
            // bundle_of_new_series: None,
            render_chart: false,
            status_message: None,
            // FIXME: populating correctly
        }
    }

    // FIXME: maybe add return type to indicate success / or not

    pub fn receive_settings(&self) -> &Arc<RwLock<ApplicationSettings>> {
        &self.application_settings
    }

    fn clear_flow_data(&mut self) {
        self.flow_data = None;
    }

    fn is_ready_to_process_data(&self) -> bool {
        self.selected_flow.selected_series.is_some() && self.selected_model.is_some()
    }

    /// attempts to receive new vec of series-ids from backend
    fn try_fetching_required_ids(&self) -> Result<Option<Vec<i64>>, String> {
        let read_settings = self.application_settings.read().unwrap();
        if let Some(module_selected) = &self.selected_model {
            if let Some(flow_id) = self.selected_flow.flow_id {
                let instance = module_selected.create_processor();
                let required_series_ids = read_settings
                    .intermediate_interface
                    .receive_series_id_from_string_and_flow_id(
                        flow_id,
                        instance.receive_required_timeseries(),
                    );
                println!("found the following ids to use {:?}", required_series_ids);
                return required_series_ids;
            // && self.selected_flow.flow_id.is_some()
            } else {
                Err("Debug: no flow was selected, aborting fetching".to_string())
            }
        } else {
            Err("Debug: No Module was selected, aborting fetching".to_string())
        }
    }

    fn try_fetching_flow_information(&self) -> Result<ProcessedPlotData, String> {
        let read_settings = self.application_settings.read().unwrap();
        // let backend = &read_settings.intermediate_interface;
        // let max_zoom_for_values  = backend.receive_active_series_max_bounds(self.selected_flow.selected_series.clone());
        let data_received = read_settings
            .intermediate_interface
            .collect_data_to_visualize(
                &self.application_settings.clone(),
                self.selected_flow.clone(),
                SPLIT_CHART_MAX_HEIGHT,
            );
        match data_received {
            Some(data) => Ok(data),
            None => Err("could not receive data about plot from backend ".to_string()),
        }
    }

    fn try_fetching_new_flow_series_from_module(
        &self,
        selected_module: ProcessorImplementation,
        // flow_dat_ref: &ProcessedPlotData,
    ) -> Result<Vec<FlowSeriesData>, String> {
        let maybe_flow_data = self.try_fetching_flow_information();
        match maybe_flow_data {
            Ok(flow_data) => {
                let module_instance = selected_module.create_processor();
                let maybe_new_data =
                    module_instance.create_new_time_series_from_plot_data(&flow_data);
                return maybe_new_data;
            }
            Err(value) => {
                return Err(format!("error receiving flow_data: {:?}", value));
            }
        }
    }

    fn try_preparing_preview_of_new_series(
        &self,
        maybe_new_series: Result<Vec<FlowSeriesData>, String>,
        plot_data: ProcessedPlotData,
    ) -> Result<ProcessedPlotData, String> {
        match maybe_new_series {
            Ok(new_series) => {
                let merged_data = plot_data.merge_with_flow_series(new_series);
                Ok(merged_data)
            }
            Err(value) => Err(format!("Erro when preparing preview: {:?}", value)),
        }
    }

    pub fn update(&mut self, message: MessageModifyDatabase) {
        match message {
            MessageModifyDatabase::FlowSelected(selected_flow) => {
                self.clear_flow_data();
                self.selected_flow.flow_id = Some(selected_flow);
                match self.try_fetching_required_ids() {
                    Ok(values) => {
                        self.status_message = Some("".to_string());
                        self.selected_flow.selected_series = values;
                    }
                    Err(message) => {
                        self.status_message = Some(message);
                    }
                };
            }
            MessageModifyDatabase::ModuleSelected(new_model) => {
                self.clear_flow_data();
                self.selected_model = Some(new_model);
                match self.try_fetching_required_ids() {
                    Ok(values) => {
                        self.selected_flow.selected_series = values;
                    }
                    Err(message) => {
                        self.status_message = Some(message);
                    }
                };
            }
            MessageModifyDatabase::PreviewRequested => {
                if self.is_ready_to_process_data() {
                    // requesting to fetch data
                    let current_module = self
                        .selected_model
                        .clone()
                        .expect("module selected, could not instantiate however");
                    let maybe_plot_data = self.try_fetching_flow_information();
                    match maybe_plot_data {
                        Ok(plot_data) => {
                            let maybe_new_series = self.try_fetching_new_flow_series_from_module(
                                current_module,
                                // &plot_data
                            );
                            let maybe_prepared_plot_data = self
                                .try_preparing_preview_of_new_series(maybe_new_series, plot_data);
                            match maybe_prepared_plot_data {
                                Ok(prepared_plot_data) => {
                                    self.flow_data = Some(prepared_plot_data);
                                    // self.flow_data
                                }
                                Err(error) => {
                                    self.status_message = Some(error);
                                    return;
                                }
                            }
                        }
                        Err(value) => {
                            self.status_message = Some(value);
                            return;
                        }
                    }

                    // done generating values, displaying next
                    self.render_chart = true;
                } else {
                    self.render_chart = false;
                }
            }
            MessageModifyDatabase::SaveToDatabase => {
                //  generating data and saving it to the database
                // saving generated data to database
                if self.is_ready_to_process_data() {
                    let current_module = self
                        .selected_model
                        .clone()
                        .expect("module selected, could not instantiate however");
                    let maybe_new_series =
                        self.try_fetching_new_flow_series_from_module(current_module);
                    match maybe_new_series {
                        Ok(new_data) => {
                            let result = self.try_saving_to_database(&new_data);
                        }
                        Err(error) => {
                            self.status_message = Some(error);
                            return;
                        }
                    }
                }

                // then take and add these information to the database accordingly
            }
            MessageModifyDatabase::MouseEvent(_event, _point) => {}
        }
    }

    fn try_saving_to_database(&mut self, new_data: &Vec<FlowSeriesData>) -> Result<String, String> {
        let read_settings = self.application_settings.read().unwrap();
        let db_backend = &read_settings.intermediate_interface;

        for entry in new_data {
            let result = db_backend.create_new_series_for_flow(&self.selected_flow, entry);
            match result {
                Ok(_) => self.status_message = Some(format!("added flow {:?}", entry.name)),
                Err(error) => {
                    self.status_message = Some(format!(
                        "could not insert data to new timeseries, reasons {:?}",
                        error
                    ))
                }
            }
        }

        Ok("".to_string())
    }
    // VISUALIZATION

    fn display_preview_button(&self) -> Element<'_, MessageModifyDatabase> {
        let button: Button<'_, MessageModifyDatabase> =
            button("Preview").on_press(MessageModifyDatabase::PreviewRequested);
        button.into()
    }

    fn display_save_button(&self) -> Element<'_, MessageModifyDatabase> {
        let button = button("Save").on_press(MessageModifyDatabase::SaveToDatabase);
        button.into()
    }

    fn display_module_picklist(&self) -> Element<'_, MessageModifyDatabase> {
        let module_pick_list = pick_list(
            ProcessorImplementation::ALL,
            self.selected_model.clone(),
            MessageModifyDatabase::ModuleSelected,
        );
        module_pick_list.into()
    }

    fn display_module_selection(&self) -> Element<'_, MessageModifyDatabase> {
        let headline = text("Select Module").size(TEXT_HEADLINE_1_SIZE);
        let pick_list = self.display_module_picklist();
        let (module_description, module_name, module_requirements) = match &self.selected_model {
            Some(module) => {
                let instance = module.create_processor();
                (
                    instance.receive_description(),
                    instance.receive_name(),
                    instance
                        .receive_required_series_formatted(instance.receive_required_timeseries()),
                )
            }
            _ => (
                "Nothing Selected".to_string(),
                "".to_string(),
                "".to_string(),
            ),
        };
        let status_message = self.display_status_message().height(Length::FillPortion(1));

        let module_description = Column::new()
            .push(text("Description").size(TEXT_HEADLINE_1_SIZE))
            .push(scrollable(text(module_description)));

        let module_requirements = Column::new()
            .push(text("Required TimeSeries").size(TEXT_HEADLINE_1_SIZE))
            .push(text(module_requirements));

        let module_information = Column::new()
            .push(text(module_name))
            .push(Space::with_height(SPACE_BETWEEN_ELEMENTS))
            .push(module_description)
            .push(Space::with_height(SPACE_BETWEEN_ELEMENTS))
            .push(module_requirements)
            .height(Length::FillPortion(4));

        let content_column = Column::new()
            .push(status_message)
            .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(Space::with_height(SPACE_BETWEEN_ELEMENTS))
            .push(headline)
            .push(Space::with_height(SPACE_BETWEEN_ELEMENTS))
            .push(pick_list)
            .push(Space::with_height(SPACE_BETWEEN_ELEMENTS))
            .push(module_information)
            .width(Length::FillPortion(MODULE_SELECTION_PORTION));

        content_column.into()
    }

    fn display_status_message(&self) -> Column<'_, MessageModifyDatabase> {
        let headline = text("Status Message:").size(TEXT_HEADLINE_1_SIZE);
        let status_message = match &self.status_message {
            Some(message) => text(message),
            _ => text(""),
        };

        let content = Column::new()
            .push(headline)
            .push(scrollable(status_message));
        content
    }
    /// FIXME: Does not make sense to be refactored I would argue
    fn display_flow_selection_bar(&self) -> Element<'_, MessageModifyDatabase> {
        let read_settings = self.application_settings.read().unwrap();

        let flow_selection = display_flow_selector(
            &read_settings.intermediate_interface,
            &self.selected_flow,
            MessageModifyDatabase::FlowSelected,
        )
        .height(Length::FillPortion(9));

        let preview_button = self.display_preview_button();
        let save_button = self.display_save_button();

        let collection_of_buttons: Row<'_, MessageModifyDatabase> = Row::new()
            // .align_x(Alignment::Center)
            .align_y(Alignment::Center)
            .spacing(SPACE_BETWEEN_TEXT)
            .width(Length::Fill)
            .height(Length::FillPortion(1))
            .push(preview_button)
            .push(save_button);

        let combined_content = Column::new()
            .push(collection_of_buttons)
            .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(flow_selection)
            .width(Length::FillPortion(FLOW_1_SELECTION_PORTION));

        combined_content.into()
    }

    fn display_chart_preview(&self) -> Element<'_, MessageModifyDatabase> {
        if !self.render_chart || !self.flow_data.is_some() {
            Column::new()
                .align_x(Alignment::Center)
                .push(text("No Data available to plot").size(TEXT_HEADLINE_0_SIZE))
                .height(CHART_HEIGHT)
                .width(Length::FillPortion(WINDOW_GRAPH_PORTION))
                .into()
        } else {
            let plot_data = self
                .flow_data
                .as_ref()
                .expect("could not receive flow data, although available");
            let content = Container::new(ChartWidget::new(plot_data));
            content
                .width(Length::FillPortion(WINDOW_GRAPH_PORTION))
                .into()
            // let as_element: Element<'_, MessagePlotting> = content.into()
            // content.into()
        }
    }
}

impl Screen for ScreenModifyDatabase {
    type Message = Message;
    fn title(&self) -> String {
        "Process".to_string()
    }

    fn receive_settings(&self) -> &Arc<RwLock<ApplicationSettings>> {
        &self.receive_settings()
    }
    fn tab_label(&self) -> iced_aw::TabLabel {
        TabLabel::Text(self.title())
    }

    fn content(&self) -> Element<'_, Self::Message> {
        let read_settings = self.application_settings.read().unwrap();
        if read_settings.database_path.is_none() {
            return display_empty_screen_no_data();
        }

        let inner_content: Element<'_, MessageModifyDatabase> = Row::new()
            .push(Rule::vertical(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(self.display_module_selection())
            .push(Rule::vertical(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(self.display_flow_selection_bar())
            .push(Rule::vertical(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            // .push(text("not implemented yet").width(Length::FillPortion(MODULE_SELECTION_PORTION)))
            .push(self.display_chart_preview())
            // .push(text("not implemented yet").width(Length::FillPortion(WINDOW_GRAPH_PORTION)))
            .push(Rule::vertical(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .into();

        let combined_content: Element<'_, MessageModifyDatabase> = generate_padded_layout(PADDING_AROUND_CONTENT)
            .push(text("PROCESS").size(TEXT_HEADLINE_0_SIZE))
            .push(Rule::horizontal(SPACE_BETWEEN_PLOT_ROWS * 4.0))
            .push(inner_content)
            .into();

        combined_content.map(Message::ScreenModifyDatabase)
    }

    fn reset(&mut self) {
        self.clear_flow_data();
        self.selected_flow = TcpFlowWrapper::default();
    }
}
