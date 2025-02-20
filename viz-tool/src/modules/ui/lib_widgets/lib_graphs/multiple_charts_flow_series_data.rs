// Contains logic for generating separated graphs for a given Flow and its attributes
// Primarily uses the FlowSeriesData as plotting point

use crate::modules::{
    backend::plot_data_preprocessing::{
        filter_false_boolean_from_data, prepare_bool, prepare_float, prepare_int,
        retrieve_y_bounds_from_selected_range, skip_every_nth, skip_outside_of_bound,
    },
    ui::{
        lib_styling::app_style_settings::{
            AMOUNT_TO_FILTER_FOR_BOOLEAN_VALUES,
            AMOUNT_TO_FILTER_FOR_BOOLEAN_VALUES_IN_SPLIT_CHART, CHART_MARGIN, CHART_MAX_X_LABELS,
            CHART_SPLIT_MAX_Y_LABELS, CHART_X_LABEL_AREA_SIZE, CHART_Y_LABEL_AREA_SIZE,
            CIRCLE_SIZE,
        },
        lib_widgets::lib_graphs::struct_zoom_bounds::ZoomBound,
    },
};

use crate::{
    Element, FlowSeriesData, MessagePlotting, ProcessedPlotData, ScreenSingleFlowPlotting,
};
use iced::widget::canvas::{Frame, Geometry};
use iced::widget::{scrollable, Column};
use iced::Size;

// -- internal imports
use ts_storage::DataValue;
// -- external imports

use plotters::series::LineSeries;
use plotters::style::{IntoFont, TextStyle};
use plotters::{
    prelude::{Circle, FontTransform},
    series::PointSeries,
};
// implementing Plotters !

use plotters_iced::{Chart, ChartBuilder, DrawingBackend, Renderer};

    pub fn create_multiple_charts<Message: 'static + Clone>(
        processed_data: &ProcessedPlotData,
    ) -> Element<'_, Message> {
        let read_settings = processed_data.app_settings.read().unwrap();
        let debug_view = read_settings.display_debug;

        let content: Column<'_, Message> = processed_data
            .point_collection
            .iter()
            .map(|series_to_visualize| series_to_visualize.view(debug_view))
            .collect();
        scrollable(content).into()
        // content.into()
    }

impl<Message: 'static + Clone> Chart<Message> for FlowSeriesData {
    type State = ();

    // allowing caching of charts
    #[inline]
    fn draw<R: Renderer, F: Fn(&mut Frame)>(
        &self,
        renderer: &R,
        bounds: Size,
        draw_fn: F,
    ) -> Geometry {
        renderer.draw_cache(&self.cache, bounds, draw_fn)
    }

    /// generates graph containing all selected attributes for a given TCPFlow
    /// This method assumes that information i.e the FlowSeriesData and PlottingData is available and contains the necessary information.
    fn build_chart<DB: DrawingBackend>(&self, _: &Self::State, mut builder: ChartBuilder<DB>) {
        // setting boundaries
        let zoom_limits = &self.zoom_bounds;
        let lower_x = zoom_limits.x.lower;
        let upper_x = zoom_limits.x.upper;
        let chart_caption: String = format!("Plotting:{:?}", &self.name.clone());
        let base_chart = builder
            .caption(chart_caption, ("Arial", 20).into_font())
            .margin(CHART_MARGIN)
            .x_label_area_size(CHART_X_LABEL_AREA_SIZE)
            .y_label_area_size(CHART_Y_LABEL_AREA_SIZE);

        println!("trying to create chart for: {:?}", self.name);
        let as_bundle: Vec<(f64, DataValue)> = self
            .timestamps
            .iter()
            .zip(self.data.iter())
            .map(|collection| (collection.0.clone(), collection.1.clone()))
            .collect();
        // pre processing accordingly
        let only_in_bounds = skip_outside_of_bound(&as_bundle, &zoom_limits);

        if only_in_bounds.len().eq(&0) {
            // nothing left to be displayed, aborting
            return;
        }
        match self.data_val_type {
            DataValue::Boolean(_) => {
                // FIXME might be troublesome to understand!
                let zoom_bounds_for_bool = ZoomBound {
                    lower: 2.0,
                    upper: 0.0,
                };
                let no_false_entries = filter_false_boolean_from_data(&only_in_bounds);
                let skipped_entries = skip_every_nth(
                    &no_false_entries,
                    AMOUNT_TO_FILTER_FOR_BOOLEAN_VALUES_IN_SPLIT_CHART,
                );
                let converted_as_float = prepare_bool(&skipped_entries, &zoom_bounds_for_bool);

                let labels_y = 2;
                let mut chart_boolean = base_chart
                    // establishing boundaries for Graph
                    .build_cartesian_2d(
                        lower_x..upper_x,
                        zoom_bounds_for_bool.lower..zoom_bounds_for_bool.upper,
                    )
                    .expect("could not build chart");

                chart_boolean
                    // FIXME add coloring for labels and structure!
                    .configure_mesh()
                    .x_desc("timestamp")
                    .y_labels(CHART_SPLIT_MAX_Y_LABELS)
                    .x_labels(CHART_MAX_X_LABELS)
                    // rotating font
                    .x_label_style(
                        TextStyle::from(("sans-serif", 9).into_font())
                            .transform(FontTransform::Rotate270),
                    ) // Rotate x-axis labels
                    .y_label_style(
                        TextStyle::from(("sans-serif", 9).into_font())
                            .transform(FontTransform::Rotate270),
                    ) // Rotate x-axis labels
                    // .x_label_offset(3000)
                    .x_labels(CHART_MAX_X_LABELS)
                    .y_labels(labels_y)
                    .draw()
                    .expect("could not add descriptions");

                // LineSeries only takes direct information no references!
                let _ = chart_boolean.draw_series(PointSeries::of_element(
                    converted_as_float,
                    CIRCLE_SIZE,
                    self.line_color,
                    &|coords, _, shape| {
                        return Circle::new(coords, CIRCLE_SIZE, shape.filled());
                    },
                ));
                // let _ = chart_boolean
                //     .draw_series(LineSeries::new(converted_as_float, &self.line_color))
                //     .unwrap()
                //     .label("bool");

                // setting axis descriptions
            }
            DataValue::Int(_) => {
                // FIXMe refactor to its own helper function!
                // FIXME improve writing!
                let converted_as_float = prepare_int(&only_in_bounds);
                let chart_y_bounds =
                    retrieve_y_bounds_from_selected_range(&only_in_bounds, &zoom_limits.y);
                println!(
                    "previous bounds, read from zoom: lower {:?}, upper:{:?}",
                    zoom_limits.x.lower, zoom_limits.x.upper
                );
                println!(
                    "new bounds, lower: {:?}, upper:{:?}",
                    chart_y_bounds.lower, chart_y_bounds.upper
                );
                let mut chart_int = base_chart
                    .build_cartesian_2d(
                        lower_x..upper_x,
                        chart_y_bounds.lower..chart_y_bounds.upper,
                    )
                    .expect("could not build chart");

                chart_int
                    .configure_mesh()
                    .x_desc("timestamp")
                    .y_labels(CHART_SPLIT_MAX_Y_LABELS)
                    .x_labels(CHART_MAX_X_LABELS)
                    .y_label_style(
                        TextStyle::from(("sans-serif", 15).into_font())
                            .transform(FontTransform::Rotate90),
                    ) // Rotate x-axis labels
                    // .configure_series_label()
                    .draw()
                    .expect("could not add descriptions");
                let _ = chart_int
                    .draw_series(LineSeries::new(converted_as_float, self.line_color))
                    .unwrap()
                    .label("bool");
            }

            DataValue::Float(_) => {
                let convert_as_float = prepare_float(&only_in_bounds);
                let chart_y_bounds =
                    retrieve_y_bounds_from_selected_range(&only_in_bounds, &zoom_limits.y);

                let mut chart_float = base_chart
                    .build_cartesian_2d(
                        lower_x..upper_x,
                        chart_y_bounds.lower..chart_y_bounds.upper,
                    )
                    .expect("could not build chart");

                chart_float
                    .configure_mesh()
                    .x_desc("timestamp")
                    .y_labels(CHART_SPLIT_MAX_Y_LABELS)
                    .x_labels(CHART_MAX_X_LABELS)
                    .axis_desc_style(("sans-serif", 15))
                    // .configure_series_label()
                    .draw()
                    .expect("could not add descriptions");
                let _ = chart_float
                    .draw_series(LineSeries::new(convert_as_float, self.line_color))
                    .unwrap()
                    .label("Why is this lable never shown xd?");
            }

            DataValue::String(_) => {
                // leaving, as they cannot be drawn!
            }
        }
        // updating spec to enable zooming
    }
}
