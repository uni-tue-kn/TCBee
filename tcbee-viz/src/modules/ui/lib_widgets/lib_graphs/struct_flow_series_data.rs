// contains logic for FlowSeriesData
//  and its helping methods
use crate::{DataValue, MessagePlotting};

use crate::modules::ui::lib_widgets::lib_graphs::struct_zoom_bounds::ZoomBound2D;
use iced::Element;
use plotters::prelude::RGBAColor;

use ::iced::{
    widget::{canvas::Cache, Container},
    Color, Length,
};
use plotters_iced::ChartWidget;

#[derive(Debug)]
pub struct FlowSeriesData {
    pub name: String,
    // for saving and identifying in db
    // pub series_id:usize,
    // pub associated_flow_id:usize,
    pub timestamps: Vec<f64>,
    pub min_timestamp: f64,
    pub max_timestamp: f64,
    pub min_val: Option<DataValue>,
    pub max_val: Option<DataValue>,
    pub data_val_type: DataValue,
    // FIXME --> this should be an iterator instead!
    // data_iterator: Box<dyn Iterator<Item = DataPoint>>,
    pub data: Vec<DataValue>,

    pub zoom_bounds: ZoomBound2D,
    pub chart_height: f32,
    // color:Color,
    pub line_color: RGBAColor,
    pub cache: Cache,
}

impl Clone for FlowSeriesData {
    fn clone(&self) -> Self {
        FlowSeriesData {
            name: self.name.clone(),
            timestamps: self.timestamps.clone(),
            min_timestamp: self.min_timestamp,
            max_timestamp: self.max_timestamp,
            min_val: self.min_val.clone(),
            max_val: self.max_val.clone(),
            data_val_type: self.data_val_type.clone(),
            data: self.data.clone(),
            zoom_bounds: self.zoom_bounds.clone(),
            chart_height: self.chart_height,
            line_color: self.line_color,
            cache: Cache::new(),
        }
    }
}

impl FlowSeriesData {
    pub fn update_zoom_bound(&mut self, new_zoom: ZoomBound2D) {
        self.zoom_bounds = new_zoom;
    }
    pub fn update_chart_height(&mut self, new_height: f32) {
        self.chart_height = new_height;
    }
}

impl FlowSeriesData {
    pub fn view<'a, Message: 'static + Clone> (&'a self, is_debug_view: bool) -> Element<'a, Message> {
        let content: Element<'_, Message> = Container::new(ChartWidget::new(self))
            .width(Length::Fill)
            .height(self.chart_height)
            .into();

        if is_debug_view {
            content.explain(Color::BLACK)
        } else {
            content
        }
    }
}
