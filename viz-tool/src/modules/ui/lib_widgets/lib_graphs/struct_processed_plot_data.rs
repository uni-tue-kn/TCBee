// contains logic for ProccessedPlotData struct
//  also containing its related methods

// internal imports
use crate::{
    modules::backend::plot_data_preprocessing::{
        extract_non_empty_string, generate_n_random_colors, prepare_bool, prepare_float,
        prepare_int, skip_every_nth, skip_outside_of_bound,
    },
    modules::ui::{
        lib_styling::app_style_settings::{
            CHART_MARGIN, CHART_MAX_X_LABELS, CHART_MAX_Y_LABELS, CHART_X_LABEL_AREA_SIZE,
            CHART_Y_LABEL_AREA_SIZE, CIRCLE_SIZE, DEFAULT_Y_MAX, DEFAULT_Y_MIN,
            TEXT_ACCENT_1_COLOR, TEXT_ACCENT_2_COLOR,
        },
        lib_widgets::lib_graphs::struct_zoom_bounds::{ZoomBound, ZoomBound2D},
    },
    ApplicationSettings, Arc, DataValue, FlowSeriesData, MessagePlotting, RefCell, RwLock,
    ScreenSingleFlowPlotting,
};

use plotters::{
    coord::types::RangedCoordf64,
    prelude::{Cartesian2d, Circle, FontTransform, Rectangle},
    series::{LineSeries, PointSeries},
    style::{IntoFont, RGBAColor},
};
use std::f64::{MAX, MIN};

use plotters_iced::{Chart, ChartBuilder, ChartWidget, DrawingBackend, Renderer};

use iced::{
    advanced::graphics::core::event,
    mouse::Cursor,
    widget::{
        canvas::{self, Cache, Frame, Geometry},
        Column, Container,
    },
    Element, Point, Size,
};

use super::{single_chart_processed_plot_data::MessageCreator, struct_zoom_bounds::{merge_two_2d_bounds, points_are_close, retrieve_default_zoom_for_one_flow}};

pub struct ProcessedPlotData {
    // denotes name of plot to generate --> i.e. for flow X
    pub name: String,

    // pub time_information: Vec<f64>,
    // FIXME --> maybe a more memory efficient solution available?
    pub point_collection: Vec<FlowSeriesData>,
    pub zoom_bounds: ZoomBound2D,
    // pub zoom_bounds: ZoomBound2D,

    // information for drawing graphs
    pub spec_frame: RefCell<Option<Cartesian2d<RangedCoordf64, RangedCoordf64>>>,
    pub draw_point_series: bool,
    pub chart_cache: Cache,
    pub pressed_cursor: bool,
    pub current_position: Option<(f64, f64)>,
    pub first_pressed_position: Option<(f64, f64)>,
    pub second_pressed_position: Option<(f64, f64)>,
    pub app_settings: Arc<RwLock<ApplicationSettings>>,
}

impl ProcessedPlotData {
    pub fn create_single_chart<Message: 'static + Clone + MessageCreator> (ref_data: &ProcessedPlotData) -> Element<'_, Message> {
        let content: Container<'_, Message> = Container::new(ChartWidget::new(ref_data));
        content.into()
    }

    pub fn merge_with_flow_series(&self, vec_of_series: Vec<FlowSeriesData>) -> ProcessedPlotData {
        let mut new_series: Vec<FlowSeriesData> = self
            .point_collection
            .iter()
            .map(|entry| entry.clone())
            .collect();
        new_series.extend(vec_of_series);
        ProcessedPlotData {
            name: self.name.clone(),
            // FIXME: correct merging data!
            point_collection: new_series,
            zoom_bounds: self.zoom_bounds.clone(),
            spec_frame: self.spec_frame.clone(),
            draw_point_series: self.draw_point_series,
            chart_cache: Cache::new(),
            pressed_cursor: self.pressed_cursor,
            current_position: None,
            first_pressed_position: None,
            second_pressed_position: None,
            app_settings: self.app_settings.clone(),
        }
    }

    pub fn merge_with_other_plot_data(&self, ref_data: &ProcessedPlotData) -> ProcessedPlotData {
        let mut new_series = self.point_collection.clone();
        new_series.extend(ref_data.point_collection.clone());
        let new_bound = merge_two_2d_bounds(&self.zoom_bounds, &ref_data.zoom_bounds);

        ProcessedPlotData {
            name: format!(
                "Comparison of: {:?} and {:?}",
                self.name.clone(),
                ref_data.name
            ),
            point_collection: new_series,
            zoom_bounds: new_bound,
            spec_frame: RefCell::new(None),
            draw_point_series: self.draw_point_series,
            chart_cache: Cache::new(),
            pressed_cursor: self.pressed_cursor,
            current_position: None,
            first_pressed_position: None,
            second_pressed_position: None,
            app_settings: self.app_settings.clone(),
        }
    }

    pub fn update_zoom_bounds(&mut self, new_zoom: ZoomBound2D) {
        // println!(
        // "Debug: updating bounds for Plot-Data \n new: {:?}",
        // new_zoom
        // );
        self.zoom_bounds = new_zoom.clone();
        // also update every FlowSeriesData
        for series in &mut self.point_collection {
            series.update_zoom_bound(new_zoom.clone());
        }
    }

    // // allows updating
    // // FIXME: required for making Drawing Plot independt!
    // pub fn update_plotting_series_style(&mut self, new_decision: bool) {
    //     self.draw_point_series = new_decision;
    // }

    pub fn retrieve_spec_frame(
        &self,
    ) -> RefCell<Option<Cartesian2d<RangedCoordf64, RangedCoordf64>>> {
        self.spec_frame.clone()
    }

    pub fn clear_cache(&self) {
        self.chart_cache.clear();
    }
}
