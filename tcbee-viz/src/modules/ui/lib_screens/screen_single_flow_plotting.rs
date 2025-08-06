// logic managing Home menu of application
// contains screen to select DataSource
// displays additional information

use iced::{
    widget::{
        button, canvas::Cache, checkbox, column, scrollable, slider, text, Checkbox, Column,
        Container, Row, Rule, Space,
    },
    Color, Element, Event, Length, Point,
};
use iced_aw::TabLabel;

// backend implementation
use crate::modules::{
    backend::plot_data_preprocessing::{
        filter_and_prepare_string_from_series, filter_for_string_values, retrieve_n_colors,
        prepare_string_from_flow_series, retrieve_y_bounds_from_collection_of_points,
        retrieve_y_bounds_from_plot_data,
    },
    ui::{
        lib_styling::app_style_settings::{
            DEFAULT_X_MAX, DEFAULT_X_MIN, DEFAULT_Y_MAX, DEFAULT_Y_MIN,
        },
        lib_widgets::{
            app_widgets::{
                display_combined_flow_buttons, display_combined_flow_selection,
                display_current_mouse_position, display_database_metadata,
                display_empty_screen_no_data, display_flow_selector, display_line_series_toggle,
                display_prepared_string, display_series_selector,
                display_split_graph_height_slider, display_split_graph_selector,
                display_zoom_instructions, display_zoom_sliders, generate_legends_for_charts,
                generate_render_button, generate_zoom_reset_button,
            },
            lib_graphs::{
                multiple_charts_flow_series_data::create_multiple_charts, single_chart_processed_plot_data::MessageCreator, struct_flow_series_data::FlowSeriesData, struct_processed_plot_data::ProcessedPlotData, struct_zoom_bounds::{
                    generate_zoom_bounds_from_coordinates_in_data, receive_flow_bounds, retrieve_default_zoom_for_one_flow, retrieve_max_series_bound, ZoomBound, ZoomBound2D
                }
            },
        },
    },
};
use crate::modules::{
    backend::{app_settings::ApplicationSettings, struct_tcp_flow_wrapper::TcpFlowWrapper},
    ui::lib_styling::app_style_settings::SCROLLABLE_TEXT_WINDOWS_SIZE,
};
use crate::DataValue;
use crate::{Message, Screen};

use crate::{
    APP_PADDING, CHART_HEIGHT, HORIZONTAL_LINE_PRIMARY_HEIGHT, HORIZONTAL_LINE_SECONDARY_HEIGHT,
    SPACE_BETWEEN_ELEMENTS, SPACE_BETWEEN_PLOT_ROWS, TEXT_HEADLINE_1_SIZE, TEXT_HEADLINE_COLOR,
};

//  external imports
use plotters::{
    coord::{types::RangedCoordf64, ReverseCoordTranslate},
    prelude::*,
};
use std::{
    cell::RefCell,
    sync::{Arc, RwLock},
};

// --- CONSTANTS --- //

const WINDOW_LEFT_COL_PORTION: u16 = 1;
const WINDOW_RIGHT_COL_PORTION: u16 = 3;

const HEIGHT_INFO_RIGHT_PORTION: u16 = 1;
const HEIGHT_CHART_RIGHT_PORTION: u16 = 9;

#[derive(Debug, Clone, PartialEq)]
pub enum MessagePlotting {
    FlowSelected(i64),
    FlowFeatureSelected(i64),
    FlowFeatureDeSelected(i64),

    SliderZoomLX(f64),
    SliderZoomRX(f64),
    SliderSplitChartHeight(f32),
    // ZoomPosChanged(f64),
    // ZoomRangeChanged(f64),
    GraphGenerationRequested,
    ZoomResetRequested,
    UnselectAllSeries,
    CheckBoxMultiplePlots(bool),
    CheckBoxDrawLineSeries(bool),
    MouseEvent(iced::mouse::Event, iced::Point),
}

impl MessageCreator for MessagePlotting {
    fn create_mouse_event_message(event: iced::mouse::Event, point: iced::Point) -> Self {
        MessagePlotting::MouseEvent(event, point) // Adjust this to match your actual message variant
    }
}
pub struct ScreenSingleFlowPlotting {
    application_settings: Arc<RwLock<ApplicationSettings>>,
    pub tcp_flow: TcpFlowWrapper,
    pub render_chart: bool,
    pub split_chart: bool,
    pub draw_line_series: bool,
    pub pressed_cursor: bool,
    pub processed_plot_data: Option<ProcessedPlotData>,
    // zoom attributes
    pub current_position: Option<(f64, f64)>,
    pub spec: RefCell<Option<Cartesian2d<RangedCoordf64, RangedCoordf64>>>,
    pub first_pressed_position: Option<(f64, f64)>,
    pub second_pressed_position: Option<(f64, f64)>,
    zoom_bounds: Option<ZoomBound2D>,
    pub split_chart_height: f32,
}

impl ScreenSingleFlowPlotting {
    /// initializes new instance, taking reference to application wide ApplicationSettings struct
    pub fn new(settings_reference: Arc<RwLock<ApplicationSettings>>) -> Self {
        ScreenSingleFlowPlotting {
            application_settings: settings_reference,
            tcp_flow: TcpFlowWrapper::default(),
            render_chart: false,
            split_chart: false,
            draw_line_series: false,
            pressed_cursor: false,
            processed_plot_data: None,
            //  zoom attributes
            current_position: None,
            spec: RefCell::new(None),
            first_pressed_position: None,
            second_pressed_position: None,
            zoom_bounds: None,
            split_chart_height: CHART_HEIGHT,
        }
    }
}

// --- /
// -- / ICED Logic

impl ScreenSingleFlowPlotting {
    /// obtains plotting data and saves it to ScreenPlotting.processed_plot_data
    /// also clears cache
    pub fn fetch_and_update_plot_data(&mut self) {
        let read_settings = self.application_settings.read().unwrap();
        let db_interface = &read_settings.intermediate_interface;
        let maybe_plot_data = db_interface.collect_data_to_visualize(
            &self.application_settings,
            self.tcp_flow.clone(),
            // self.zoom_bounds.clone(),
            self.split_chart_height,
        );
        self.processed_plot_data = maybe_plot_data;
        // self.combined_chart_cache.clear();
        if let Some(plotting_data) = &self.processed_plot_data {
            // plotting_data.clear_cache();
            self.spec = plotting_data.retrieve_spec_frame();
        }
    }
    pub fn update_zoom_plot_data_and_cache(&mut self) {
        // self.combined_chart_cache.clear();
        if let Some(plot_data) = &mut self.processed_plot_data {
            plot_data.clear_cache();
            plot_data.update_zoom_bounds(self.zoom_bounds.clone().unwrap_or_default());
            for series in &mut plot_data.point_collection {
                series.update_zoom_bound(self.zoom_bounds.clone().unwrap_or_default());
                series.update_chart_height(self.split_chart_height);
                series.cache.clear();
            }
            self.spec = plot_data.retrieve_spec_frame();
        }
    }

    pub fn maybe_set_state_for_y_bound_generation(&mut self, new_state: bool) {
        if let Some(plot_data) = &mut self.processed_plot_data {
            plot_data.set_state_for_y_bound_generation(new_state);
        }
    }

    pub fn update_zoom_bound_y(&mut self, new_y_bound: &ZoomBound) -> ZoomBound2D {
        let new_bound = ZoomBound2D {
            x: self.zoom_bounds.clone().unwrap_or_default().x,
            y: new_y_bound.clone(),
        };
        self.zoom_bounds = Some(new_bound.clone());
        new_bound
    }

    pub fn update_zoom_bound_x(&mut self, new_x_bound: &ZoomBound) -> ZoomBound2D {
        let new_bound = ZoomBound2D {
            x: new_x_bound.clone(),
            y: self.zoom_bounds.clone().unwrap_or_default().y,
        };
        self.zoom_bounds = Some(new_bound.clone());
        new_bound
    }

    pub fn update(&mut self, message: MessagePlotting) {
        match message {
            MessagePlotting::FlowSelected(reference_id) => {
                // disabling rendering after new selection:
                self.render_chart = false;

                self.tcp_flow.flow_id = Some(reference_id);
                self.tcp_flow.selected_series = None;
                let new_zoom = retrieve_default_zoom_for_one_flow(&self.application_settings, &self.tcp_flow);
                self.zoom_bounds = Some(new_zoom);
            }

            MessagePlotting::FlowFeatureSelected(added_feature_id) => {
                self.tcp_flow.add_new_series(added_feature_id);
                // updating max_zoom for Y-Direction!
                let new_zoom = retrieve_default_zoom_for_one_flow(&self.application_settings, &self.tcp_flow);
                self.zoom_bounds = Some(new_zoom);
                self.fetch_and_update_plot_data();
                // querying data to be displayed, if rendering is enabled, skipping otherwise
            }

            MessagePlotting::FlowFeatureDeSelected(removed_feature_id) => {
                self.tcp_flow.remove_series(&removed_feature_id);
                if self.tcp_flow.selected_series.is_none() {
                    self.render_chart = false;
                }
                let new_zoom = retrieve_default_zoom_for_one_flow(&self.application_settings, &self.tcp_flow);
                self.zoom_bounds = Some(new_zoom);
                self.fetch_and_update_plot_data();
            }

            MessagePlotting::GraphGenerationRequested => {
                if self.tcp_flow.selected_series.is_some() {
                    match self.render_chart {
                        true => self.render_chart = false,
                        false => self.render_chart = true,
                    }
                } else {
                    self.render_chart = false
                }
            }
            MessagePlotting::UnselectAllSeries => {
                self.tcp_flow.selected_series = None;
            }

            // if called we generate the chart - otherwise not.
            // Could be done with a boolean  but this might be unfortunate
            MessagePlotting::CheckBoxMultiplePlots(new_option) => {
                self.split_chart = new_option;
            }
            // FIXME --> Problem: causes reload of graph for each movementn --> maybe slow?
            MessagePlotting::MouseEvent(event, point) => {
                self.set_current_position(point);
                // FIXME: might be slowing down a lot?
                self.update_zoom_plot_data_and_cache();
                match event {
                    iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left) => {
                        self.maybe_set_state_for_y_bound_generation(false);
                        self.set_current_position(point);
                        self.pressed_cursor = false;
                        self.set_cursor_state_and_pos(true);
                    }
                    iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left) => {
                        self.maybe_set_state_for_y_bound_generation(false);
                        self.set_current_position(point);
                        self.set_cursor_state_and_pos(false);
                        let plotting_data =
                            self.processed_plot_data.as_mut().expect("no plotting data");
                        let new_zoom =
                            generate_zoom_bounds_from_coordinates_in_data(&plotting_data);
                        self.zoom_bounds = Some(new_zoom.clone());
                        plotting_data.zoom_bounds = new_zoom;
                        if self.render_chart {
                            // self.fetch_and_update_plot_data();
                            self.update_zoom_plot_data_and_cache();
                        }
                    }
                    iced::mouse::Event::ButtonPressed(iced::mouse::Button::Right) => {
                        // resetting zoom to default!
                        self.maybe_set_state_for_y_bound_generation(false);
                        let new_zoom = retrieve_default_zoom_for_one_flow(
                            &self.application_settings,
                            &self.tcp_flow,
                        );
                        self.zoom_bounds = Some(new_zoom);
                        self.update_zoom_plot_data_and_cache();
                        // self.fetch_and_update_plot_data();
                    }
                    _ => {}
                }
            }
            MessagePlotting::ZoomResetRequested => {
                let new_zoom =
                    retrieve_default_zoom_for_one_flow(&self.application_settings, &self.tcp_flow);
                self.zoom_bounds = Some(new_zoom);
                self.update_zoom_plot_data_and_cache();
            }
            MessagePlotting::SliderZoomLX(lower_bound_x) => {
                let new_x_bound = ZoomBound {
                    lower: lower_bound_x,
                    upper: self.zoom_bounds.clone().unwrap_or_default().x.upper,
                };
                let _ = self.update_zoom_bound_x(&new_x_bound);
                self.maybe_set_state_for_y_bound_generation(true);
                self.update_zoom_plot_data_and_cache();
            }
            MessagePlotting::SliderZoomRX(upper_bound_x) => {
                let new_x_bound = ZoomBound {
                    lower: self.zoom_bounds.clone().unwrap_or_default().x.lower,
                    upper: upper_bound_x,
                };

                let _ = self.update_zoom_bound_x(&new_x_bound);
                self.maybe_set_state_for_y_bound_generation(true);
                self.update_zoom_plot_data_and_cache();
            }
            MessagePlotting::SliderSplitChartHeight(new_height) => {
                self.split_chart_height = new_height;
                self.update_zoom_plot_data_and_cache();
            }

            MessagePlotting::CheckBoxDrawLineSeries(new_selection) => {
                self.draw_line_series = new_selection;
                if let Some(plot_data) = self.processed_plot_data.as_mut() {
                    plot_data.draw_point_series = new_selection;
                }
                self.update_zoom_plot_data_and_cache();
            }
        }
    }

    fn set_current_position(&mut self, new_point: Point) {
        if let Some(spec) = self.spec.borrow().as_ref() {
            self.current_position =
                spec.reverse_translate((new_point.x as i32, new_point.y as i32));
            if let Some(plot_data) = &mut self.processed_plot_data {
                plot_data.current_position = self.current_position;
            }
        }
    }
    /// Assumes that plot_data is available -> otherwise this function could not be called
    /// as the mouse-event is only triggered within the canva
    fn set_cursor_state_and_pos(&mut self, new_cursor_state: bool) {
        let mut_plotdata_ref = self
            .processed_plot_data
            .as_mut()
            .expect("On cursor update: No plot_data found");

        //  started pressing down
        if !self.pressed_cursor && new_cursor_state {
            self.first_pressed_position = self.current_position;
            self.second_pressed_position = None;
            mut_plotdata_ref.first_pressed_position = self.current_position;
            mut_plotdata_ref.second_pressed_position = None;
        }
        // stopped pressing
        if self.pressed_cursor && !new_cursor_state {
            self.second_pressed_position = self.current_position;
            mut_plotdata_ref.second_pressed_position = self.current_position;
        }
        self.pressed_cursor = new_cursor_state;
        mut_plotdata_ref.pressed_cursor = new_cursor_state;
        // updating data in ProcessedPlotData
    }

    /// function to generate chart with collected data
    /// if no data is available and the "render-button" has not been pressed, nothing will be drawn
    /// returns Element<> with parsed chart-view
    /// either returning a single chart or multiple ones in a column layout
    fn generate_chart(&self) -> Element<'_, MessagePlotting> {
        let read_settings = self.application_settings.read().unwrap();
        let is_display_debug = read_settings.display_debug;
        let intermediate_backend = &read_settings.intermediate_interface;
        if !self.render_chart
            || self.tcp_flow.flow_id.is_none()
            || self.tcp_flow.selected_series.is_none()
        {
            let empty: Element<'_, MessagePlotting> = column![text("no flow selected"),].into();
            if is_display_debug {
                return empty.explain(Color::BLACK);
            } else {
                return empty;
            }
        }

        // --- running through pre-processor + creating graph  --- //
        let data_reference =
            ScreenSingleFlowPlotting::receive_plotting_data_reference(&self).unwrap();

        let plot_content = match self.split_chart {
            true => create_multiple_charts(data_reference),
            false => ProcessedPlotData::create_single_chart(data_reference),
        };

        // extracting String-Values to display separately
        let maybe_string_wrappers = filter_and_prepare_string_from_series(data_reference);
        // let mut strings_as_content = Column::new();
        let strings_as_content: Element<'_, MessagePlotting> =
            if let Some(collection_of_wrapper) = maybe_string_wrappers {
                let string_content = display_prepared_string(collection_of_wrapper);
                scrollable(string_content)
                    .width(Length::Fill)
                    .height(SCROLLABLE_TEXT_WINDOWS_SIZE)
                    .into()
            } else {
                Column::new().into()
            };

        let combined_content: Element<'_, MessagePlotting> = Column::new()
            .push(plot_content)
            .push(Space::with_height(SPACE_BETWEEN_ELEMENTS))
            .push(strings_as_content)
            .height(Length::FillPortion(HEIGHT_CHART_RIGHT_PORTION))
            .into();

        if is_display_debug {
            combined_content.explain(Color::BLACK)
        } else {
            combined_content
        }
    }

    pub fn generate_chart_view(&self) -> Element<'_, MessagePlotting> {
        let generate_legends: bool = self.render_chart
            && self.tcp_flow.flow_id.is_some()
            && self.tcp_flow.selected_series.is_some();
        let graph_top_info: Row<'_, MessagePlotting> = Row::new()
            .push(
                display_current_mouse_position(self.current_position).width(Length::FillPortion(5)),
            )
            .push(generate_legends_for_charts(
                generate_legends,
                &self.processed_plot_data,
            ))
            .height(Length::FillPortion(HEIGHT_INFO_RIGHT_PORTION));

        let right_content: Element<'_, MessagePlotting> = Column::new()
            .push(graph_top_info)
            .push(self.generate_chart())
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .width(Length::FillPortion(WINDOW_RIGHT_COL_PORTION))
            .into();
        right_content
        // .into()
    }

    pub fn generate_side_bar(&self) -> Element<'_, MessagePlotting> {
        let read_settings = self.application_settings.read().unwrap();
        let intermediate_backend = read_settings.intermediate_interface.clone();
        let database_info = display_database_metadata(&self.application_settings);

        let combined_flow_selector = display_combined_flow_selection(
            "Flow 1".to_string(),
            &intermediate_backend,
            &self.tcp_flow,
            MessagePlotting::FlowSelected,
            MessagePlotting::FlowFeatureSelected,
            MessagePlotting::FlowFeatureDeSelected,
            MessagePlotting::UnselectAllSeries,
        );

        let combined_buttons = display_combined_flow_buttons(
            MessagePlotting::GraphGenerationRequested,
            MessagePlotting::ZoomResetRequested,
            self.tcp_flow.flow_id.is_some(),
        );

        // let graph_height_selector = self.display_split_graph_height_slider();
        let graph_height_selector = display_split_graph_height_slider(
            MessagePlotting::SliderSplitChartHeight,
            &self.split_chart_height,
            &self.split_chart,
        );
        // let split_selector = self.display_split_graph_selector();
        let split_selector = display_split_graph_selector::<MessagePlotting>(
            self.split_chart,
            MessagePlotting::CheckBoxMultiplePlots,
        );
        let lines_series_selector = display_line_series_toggle::<MessagePlotting>(
            self.draw_line_series,
            MessagePlotting::CheckBoxDrawLineSeries,
        );
        // let zoom_text = self.display_zoom_instructions();
        let zoom_text = display_zoom_instructions(&self.split_chart);
        // let zoom_slider = self.display_zoom_sliders();
        let zoom_slider = display_zoom_sliders(
            &self.application_settings,
            MessagePlotting::SliderZoomLX,
            MessagePlotting::SliderZoomRX,
            &self.zoom_bounds,
            &self.tcp_flow,
        );

        let mut sidebar = Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .push(database_info)
            .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(combined_buttons)
            .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(combined_flow_selector)
            // .push(flow_collection)
            // .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            // .push(series_collection)
            .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
            .push(split_selector)
            .push(lines_series_selector)
            .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT));

        if self.split_chart {
            sidebar = sidebar
                .push(graph_height_selector)
                .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
        }

        if self.tcp_flow.flow_id.is_some() {
            sidebar = sidebar.spacing(10).push(zoom_text).push(zoom_slider)
        }

        sidebar = sidebar
            .width(Length::FillPortion(WINDOW_LEFT_COL_PORTION))
            .spacing(SPACE_BETWEEN_ELEMENTS);

        sidebar.into()
        // );
    }
}

impl Screen for ScreenSingleFlowPlotting {
    type Message = Message;

    fn title(&self) -> String {
        "Plot single Flow".to_string()
    }

    fn receive_settings(&self) -> &Arc<RwLock<ApplicationSettings>> {
        &self.application_settings
    }

    fn tab_label(&self) -> iced_aw::TabLabel {
        TabLabel::Text(self.title())
    }
    fn content(&self) -> Element<'_, Self::Message> {
        let read_settings = self.application_settings.read().unwrap();
        if read_settings.database_path.is_none() {
            return display_empty_screen_no_data();
        }
        let left_content = self.generate_side_bar();
        let right_content = self.generate_chart_view();

        let content: Element<'_, MessagePlotting> = Row::new()
            .push(scrollable(left_content))
            .push(Space::with_width(Length::Fixed(SPACE_BETWEEN_PLOT_ROWS)))
            // .push(scrollable(right_content))jjj
            .push(right_content)
            .padding(APP_PADDING)
            .width(Length::Fill)
            .into();

        content.map(Message::ScreenSingleFlowPlot)
    }

    fn reset(&mut self) {
        self.tcp_flow = TcpFlowWrapper::default();
        self.processed_plot_data = None;
    }
}

impl ScreenSingleFlowPlotting {
    // FIXME might not be needed!
    // returns a guaranteed reference to the saved ProcessedPlotData.
    // If none was found in "settings.storage" it will request the data and store it ther
    // then return a reference
    pub fn receive_plotting_data_reference(&self) -> Option<&ProcessedPlotData> {
        if let Some(ref value) = self.processed_plot_data.as_ref() {
            Some(value)
        } else {
            None
        }
    }
}
