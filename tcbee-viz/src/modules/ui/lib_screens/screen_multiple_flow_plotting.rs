// logic for visualizing two concurrent flows
// ---

use std::cell::RefCell;

use iced::{
    Point,
    widget::{scrollable, text, Column, Row, Rule, Space}, Element, Length
};
use iced_aw::TabLabel;
use plotters::{coord::{types::RangedCoordf64, ReverseCoordTranslate}, prelude::Cartesian2d};

use crate::modules::{
    backend::{
        plot_data_preprocessing::filter_and_prepare_string_from_series, struct_tcp_flow_wrapper::TcpFlowWrapper
    },
    ui::{
        lib_styling::app_style_settings::{
            CHART_HEIGHT, HORIZONTAL_LINE_PRIMARY_HEIGHT, SCROLLABLE_TEXT_WINDOWS_SIZE, SPACE_BETWEEN_ELEMENTS, SPACE_BETWEEN_PLOT_ROWS, TEXT_HEADLINE_0_SIZE
        },
        lib_widgets::{
            app_widgets::{
                display_combined_flow_buttons, display_combined_flow_selection, display_current_mouse_position, display_empty_screen_no_data, display_line_series_toggle, display_prepared_string, display_split_graph_selector, display_zoom_sliders, generate_legends_for_charts, generate_padded_layout
            },
            lib_graphs::{multiple_charts_flow_series_data::create_multiple_charts, single_chart_processed_plot_data::MessageCreator, struct_zoom_bounds::{generate_zoom_bounds_from_coordinates_in_data, retrieve_default_zoom_for_one_flow, retrieve_default_zoom_for_two_flows, retrieve_max_series_bound_of_two_flows, ZoomBound, ZoomBound2D}},
        },
    },
};
use crate::{
    modules::ui::lib_widgets::lib_graphs::struct_processed_plot_data::ProcessedPlotData,
    ApplicationSettings, Arc, Message, RwLock, Screen,
};

const FLOW1_SELECTION_PORTION: u16 = 1;
const FLOW2_SELECTION_PORTION: u16 = 1;
const SIDEBAR_PORTION: u16 = 2;
const WINDOW_GRAPH_PORTION: u16 = 4;
const HEIGHT_CHART_RIGHT_PORTION:u16 = 9;
const HEIGHT_TEXT_RIGHT_PORTION: u16 = 1;
const HEIGHT_FLOW_SELECTION_PORTION: u16 = 6; 
const HEIGHT_GRAPH_SETTINGS_PORTION: u16 = 4; 

#[derive(Debug, Clone, PartialEq)]
pub enum MessageMultiFlowPlotting {
    FlowOneSelected(i64),
    FlowTwoSelected(i64),
    FlowOneFeatureSelected(i64),
    FlowTwoFeatureSelected(i64),
    FlowOneFeatureDeselected(i64),
    FlowTwoFeatureDeselected(i64),

    GraphGenerationRequested,
    SplitChartRequested(bool),
    DrawLineSeriesRequested(bool),
    UnselectAllSeries,
    // zooming
    SliderZoomLX(f64),
    SliderZoomRX(f64),
    ZoomResetRequested,

    MouseEvent(iced::mouse::Event, iced::Point),
}

impl MessageCreator for MessageMultiFlowPlotting {
    fn create_mouse_event_message(event: iced::mouse::Event, point: iced::Point) -> Self {
        MessageMultiFlowPlotting::MouseEvent(event, point)
    }
}

pub struct ScreenMultiFlowPlotting {
    application_settings: Arc<RwLock<ApplicationSettings>>,
    first_tcp_flow: TcpFlowWrapper,
    second_tcp_flow: TcpFlowWrapper,
    render_chart: bool,
    draw_line_series: bool,
    pressed_cursor: bool,
    split_chart_height: f32,
    split_chart: bool,
    // Zoom Related
    zoom_boundaries: Option<ZoomBound2D>,
    plot_data: Option<ProcessedPlotData>,
    spec: RefCell<Option<Cartesian2d<RangedCoordf64, RangedCoordf64>>>,
    current_position: Option<(f64,f64)>,
    first_pressed_position: Option<(f64,f64)>,
    second_pressed_position: Option<(f64,f64)>,
}

impl ScreenMultiFlowPlotting {
    pub fn new(settings_reference: Arc<RwLock<ApplicationSettings>>) -> Self {
        ScreenMultiFlowPlotting {
            application_settings: settings_reference,
            first_tcp_flow: TcpFlowWrapper::default(),
            second_tcp_flow: TcpFlowWrapper::default(),
            render_chart: false,
            draw_line_series: false,
            pressed_cursor: false,
            split_chart: false,
            zoom_boundaries: None,
            split_chart_height: CHART_HEIGHT,
            plot_data: None,
            spec: RefCell::new(None),
            current_position:None,
            first_pressed_position:None,
            second_pressed_position:None,
        }
    }
    /// obtains plotting data and saves it to ScreenPlotting.processed_plot_data
    /// also clears cache
    pub fn fetch_and_update_plot_data(&mut self) {
        println!("fetching information!");
        let read_settings = self.application_settings.read().unwrap();
        let db_interface = &read_settings.intermediate_interface;

        let maybe_flow_1 = db_interface.collect_data_to_visualize(
            &self.application_settings,
            self.first_tcp_flow.clone(),
            // self.zoom_bounds.clone(),
            self.split_chart_height,
        );
        let maybe_flow_2 = db_interface.collect_data_to_visualize(
            &self.application_settings,
            self.second_tcp_flow.clone(),
            // self.zoom_bounds.clone(),
            self.split_chart_height,
        );
        if let Some(flow_2) = maybe_flow_2 {
            if let Some(flow_1) = maybe_flow_1 {
                println!("saving plot data to internal state!");
                let merged_data =  flow_1.merge_with_other_plot_data(&flow_2);
                let new_refcell = merged_data.retrieve_spec_frame();
                self.plot_data = Some(merged_data);
                self.spec = new_refcell;
            }
        }
    }
    pub fn update_zoom_plot_data_and_cache(&mut self) {
        // self.combined_chart_cache.clear();
        if let Some(plot_data) = &mut self.plot_data {
            // plot_data.pointseries_display_threshold = read_settings.graph_pointseries_threshold;
            plot_data.clear_cache();
            plot_data.update_zoom_bounds(self.zoom_boundaries.clone().unwrap_or_default());
            for series in &mut plot_data.point_collection {
                series.update_zoom_bound(self.zoom_boundaries.clone().unwrap_or_default());
                series.update_chart_height(self.split_chart_height);
                series.cache.clear();
            }
            self.spec = plot_data.retrieve_spec_frame();
        }
    }

    pub fn update_zoom_bound_x(&mut self, new_x_bound: &ZoomBound) {
        let new_bound = ZoomBound2D {
            x: new_x_bound.clone(),
            y: self
                .zoom_boundaries
                .clone()
                .expect("no bounds defined, updating impossible?")
                .y,
        };
        self.zoom_boundaries = Some(new_bound);
    }

    pub fn update(&mut self, message: MessageMultiFlowPlotting) {
        match message {
            
            MessageMultiFlowPlotting::FlowOneSelected(id) => {
                self.render_chart = false;
                self.first_tcp_flow.flow_id = Some(id);
                self.zoom_boundaries = Some(retrieve_default_zoom_for_two_flows(&self.application_settings, &self.first_tcp_flow, &self.second_tcp_flow));
            }
            MessageMultiFlowPlotting::FlowTwoSelected(id) => {
                self.render_chart = false;
                self.second_tcp_flow.flow_id = Some(id);
                self.zoom_boundaries = Some(retrieve_default_zoom_for_two_flows(&self.application_settings, &self.first_tcp_flow, &self.second_tcp_flow));
            }
            MessageMultiFlowPlotting::FlowOneFeatureSelected(new_feature) => {
                self.first_tcp_flow.add_new_series(new_feature);
                self.fetch_and_update_plot_data();
                self.zoom_boundaries = Some(retrieve_default_zoom_for_two_flows(&self.application_settings, &self.first_tcp_flow, &self.second_tcp_flow));
            }
 
            MessageMultiFlowPlotting::FlowTwoFeatureSelected(new_feature) => {
                self.second_tcp_flow.add_new_series(new_feature);
                self.fetch_and_update_plot_data();
                self.zoom_boundaries = Some(retrieve_default_zoom_for_two_flows(&self.application_settings, &self.first_tcp_flow, &self.second_tcp_flow));
            }
            MessageMultiFlowPlotting::FlowOneFeatureDeselected(removed_feature) => {
                self.first_tcp_flow.remove_series(&removed_feature);
                if self.first_tcp_flow.selected_series.is_none(){
                    self.render_chart = false;
                }
                self.fetch_and_update_plot_data();
                self.zoom_boundaries = Some(retrieve_default_zoom_for_two_flows(&self.application_settings, &self.first_tcp_flow, &self.second_tcp_flow));
            }
            MessageMultiFlowPlotting::FlowTwoFeatureDeselected(removed_feature) => {
                self.second_tcp_flow.remove_series(&removed_feature);
                if self.second_tcp_flow.selected_series.is_none(){
                    self.render_chart = false;
                }
                self.fetch_and_update_plot_data();
                self.zoom_boundaries = Some(retrieve_default_zoom_for_two_flows(&self.application_settings, &self.first_tcp_flow, &self.second_tcp_flow));
            }
            MessageMultiFlowPlotting::SplitChartRequested(value) => self.split_chart = value,
            MessageMultiFlowPlotting::DrawLineSeriesRequested(value) => {
                self.draw_line_series = value;
                if let Some(plot_data) = self.plot_data.as_mut() {
                    plot_data.draw_point_series = value;
                }
                self.update_zoom_plot_data_and_cache();
            }
            MessageMultiFlowPlotting::SliderZoomLX(lower_bound) => {
                let new_x_bound = ZoomBound {
                    lower: lower_bound,
                    upper: self
                        .zoom_boundaries.clone().unwrap_or_default().x.upper,
                };
                self.update_zoom_bound_x(&new_x_bound);
                self.update_zoom_plot_data_and_cache();
            }
            MessageMultiFlowPlotting::SliderZoomRX(upper_bound) => {
                let x_lower_bound = self.zoom_boundaries.clone().unwrap_or_default().x.lower;
                let new_x_bound = ZoomBound {
                    lower: x_lower_bound,
                    upper: upper_bound,
                };
                self.update_zoom_bound_x(&new_x_bound);
                self.update_zoom_plot_data_and_cache();
            }
            MessageMultiFlowPlotting::GraphGenerationRequested => {
                if self.first_tcp_flow.selected_series.is_some()
                    && self.second_tcp_flow.selected_series.is_some()
                    && self.plot_data.is_some()
                {
                    match self.render_chart {
                        true => self.render_chart = false,
                        false => self.render_chart = true,
                    }
                } else { 
                    self.render_chart = false
                }
            }

            MessageMultiFlowPlotting::ZoomResetRequested => {
                self.zoom_boundaries = Some(retrieve_default_zoom_for_two_flows(&self.application_settings, &self.first_tcp_flow, &self.second_tcp_flow));
                self.update_zoom_plot_data_and_cache();

            }


            MessageMultiFlowPlotting::MouseEvent(event, point) => {
                self.set_current_position(point);
                self.update_zoom_plot_data_and_cache();
                match event {
                    iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left) => { 
                        self.set_current_position(point);
                        self.pressed_cursor = false;
                        self.set_cursor_state_and_pos(true);
                    }
                    iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left) => {
                        self.set_current_position(point);
                        self.set_cursor_state_and_pos(false);
                        // update zoom
                        let data_reference = self.plot_data.as_mut().expect("no plotting data avail");
                        let new_zoom = generate_zoom_bounds_from_coordinates_in_data(&data_reference);
                        self.zoom_boundaries = Some(new_zoom.clone());
                        data_reference.zoom_bounds = new_zoom;
                        if self.render_chart{
                            self.update_zoom_plot_data_and_cache();
                        }
                    }
                    iced::mouse::Event::ButtonPressed(iced::mouse::Button::Right) => {
                        // reset zoom
                        self.zoom_boundaries = Some(retrieve_default_zoom_for_two_flows(&self.application_settings, &self.first_tcp_flow, &self.second_tcp_flow));
                    }

                    _ => {}
                }
            }
            MessageMultiFlowPlotting::UnselectAllSeries => { 
                    self.first_tcp_flow.selected_series = None;
                    self.second_tcp_flow.selected_series = None;
            }
            _ => (),

        }
    }

    fn set_current_position(&mut self, new_point: Point) {
        if let Some(spec) = self.spec.borrow().as_ref() {
            self.current_position =
                spec.reverse_translate((new_point.x as i32, new_point.y as i32));
            // self.combined_chart_cache.clear();
            if let Some(plot_data) = &mut self.plot_data {
                plot_data.current_position = self.current_position;
            }
        }
    }
    /// Assumes that plot_data is available -> otherwise this function could not be called
    /// as the mouse-event is only triggered within the canva
    fn set_cursor_state_and_pos(&mut self, new_cursor_state: bool) {
        let mut_plotdata_ref = self
            .plot_data
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
            // setting end position!
            self.second_pressed_position = self.current_position;
            mut_plotdata_ref.second_pressed_position = self.current_position;
        }
        self.pressed_cursor = new_cursor_state;
        mut_plotdata_ref.pressed_cursor = new_cursor_state;
        // updating data in ProcessedPlotData
    }


    fn display_flows_selection(&self) -> Element<'_, MessageMultiFlowPlotting> {
        let read_settings = self.application_settings.read().unwrap();
        let intermediate_backend = read_settings.intermediate_interface.clone();

        let selector_flow_1 = display_combined_flow_selection(
            "Flow 1".to_string(),
            &intermediate_backend,
            &self.first_tcp_flow,
            MessageMultiFlowPlotting::FlowOneSelected,
            MessageMultiFlowPlotting::FlowOneFeatureSelected,
            MessageMultiFlowPlotting::FlowOneFeatureDeselected,
            MessageMultiFlowPlotting::UnselectAllSeries,
        )
        .width(Length::FillPortion(FLOW1_SELECTION_PORTION));
        let selector_flow_2 = display_combined_flow_selection(
            "Flow 2".to_string(),
            &intermediate_backend,
            &self.second_tcp_flow,
            MessageMultiFlowPlotting::FlowTwoSelected,
            MessageMultiFlowPlotting::FlowTwoFeatureSelected,
            MessageMultiFlowPlotting::FlowTwoFeatureDeselected,
            MessageMultiFlowPlotting::UnselectAllSeries,
        )
        .width(Length::FillPortion(FLOW2_SELECTION_PORTION));
        let content = Row::new()
            .spacing(SPACE_BETWEEN_PLOT_ROWS)
            .push(scrollable(selector_flow_1))
            .push(scrollable(selector_flow_2))
            .height(Length::FillPortion(HEIGHT_FLOW_SELECTION_PORTION));

        content.into()
    }

    fn display_sidebar(&self) -> Element<'_, MessageMultiFlowPlotting> {
        let flow_selection = self.display_flows_selection();
        let interaction_buttons = display_combined_flow_buttons(
            MessageMultiFlowPlotting::GraphGenerationRequested,
            MessageMultiFlowPlotting::ZoomResetRequested,
            self.first_tcp_flow.flow_id.is_some() || self.second_tcp_flow.flow_id.is_some(),
        );
        let split_selector = display_split_graph_selector(
            self.split_chart,
            MessageMultiFlowPlotting::SplitChartRequested,
        );
        let line_series_selector = display_line_series_toggle(
            self.draw_line_series,
            MessageMultiFlowPlotting::DrawLineSeriesRequested,
        );
        let zoom_slider = display_zoom_sliders(
            &self.application_settings,
            MessageMultiFlowPlotting::SliderZoomLX,
            MessageMultiFlowPlotting::SliderZoomRX,
            &self.zoom_boundaries,
            &self.first_tcp_flow,
        );

        let lower_sidebar = Column::new()
            .push(interaction_buttons)
            .push(Rule::horizontal(HORIZONTAL_LINE_PRIMARY_HEIGHT))
            .push(split_selector)
            .push(line_series_selector)
            .push(zoom_slider);

        let content = Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .width(Length::FillPortion(SIDEBAR_PORTION))
            .push(flow_selection)
            .push(scrollable(lower_sidebar).height(Length::FillPortion(HEIGHT_GRAPH_SETTINGS_PORTION)));

        content.into()
    }

    fn generate_chart_view(&self) -> Element<'_,MessageMultiFlowPlotting> { 
        let generate_top_info:bool = self.render_chart && self.first_tcp_flow.selected_series.is_some() && self.second_tcp_flow.selected_series.is_some();
        let maybe_legends = generate_legends_for_charts(generate_top_info, &self.plot_data);
        let mouse_position = display_current_mouse_position(self.current_position);
        let merged_top_info = Row::new()
        .push(mouse_position)
        .push(maybe_legends)
        .width(Length::FillPortion(WINDOW_GRAPH_PORTION));

        let plot_content = self.generate_chart();
        let content: Element<'_, MessageMultiFlowPlotting> = Column::new()
        .push(merged_top_info)
        .push(plot_content)
        .width(Length::FillPortion(WINDOW_GRAPH_PORTION))
        .into();

        content
    }

    fn generate_chart(&self) -> Element<'_, MessageMultiFlowPlotting> {

        let read_settings = self.application_settings.read().unwrap();
        if !self.render_chart || (self.first_tcp_flow.selected_series.is_none() && self.second_tcp_flow.selected_series.is_none()) {
            let empty = Column::new()
            .push(text("No Flows Selected").size(TEXT_HEADLINE_0_SIZE))
            .height(Length::FillPortion(HEIGHT_CHART_RIGHT_PORTION))
            .width(Length::FillPortion(WINDOW_GRAPH_PORTION));
            return empty.into()
        }

        let data_reference = self.plot_data.as_ref().unwrap();
        let plot_content = match self.split_chart{
            true => create_multiple_charts(data_reference),
            false => ProcessedPlotData::create_single_chart(data_reference)
        };

        println!("Debug: attempting generating chart");
        // representing string values
        let maybe_string_wrappers = filter_and_prepare_string_from_series(data_reference);
        let string_as_content: Element<'_, MessageMultiFlowPlotting> = 
        if let Some(collection_of_wrapper) = maybe_string_wrappers { 
            let string_content = display_prepared_string(collection_of_wrapper);
            scrollable(string_content)
            .width(Length::Fill)
            .height(SCROLLABLE_TEXT_WINDOWS_SIZE)
            .into()
        } else { 
            Column::new().into()
        };


        let combined_content = Column::new()
        .push(plot_content)
        .push(Space::with_height(SPACE_BETWEEN_ELEMENTS))
        .push(string_as_content)
        .height(Length::FillPortion(HEIGHT_CHART_RIGHT_PORTION));

        combined_content.into()
    }
}

impl Screen for ScreenMultiFlowPlotting {
    type Message = Message;
    fn title(&self) -> String {
        "Multi Flow".to_string()
    }

    fn receive_settings(&self) -> &Arc<RwLock<ApplicationSettings>> {
        &self.receive_settings()
    }
    fn tab_label(&self) -> iced_aw::TabLabel {
        TabLabel::Text(self.title())
    }

    fn content(&self) -> Element<'_, Self::Message> {
        let read_settings = self.application_settings.read().unwrap();
        if read_settings.datasource.is_none() {
            return display_empty_screen_no_data();
        }
        let content: Element<'_, MessageMultiFlowPlotting> = Row::new()
            .push(self.display_sidebar())
            .push(self.generate_chart_view())
            .into();
        let padded_content: Element<'_, MessageMultiFlowPlotting> = generate_padded_layout(20)
        .push(content).into();

        padded_content.map(Message::ScreenMultipleFlowPlot)
    }

    fn reset(&mut self) {
        self.first_tcp_flow = TcpFlowWrapper::default();
        self.second_tcp_flow = TcpFlowWrapper::default();
        self.plot_data = None;
    }
}
