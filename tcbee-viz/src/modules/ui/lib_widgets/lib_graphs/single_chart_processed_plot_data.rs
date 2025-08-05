// internal imports
use crate::{
    modules::{
        backend::plot_data_preprocessing::{
            filter_false_boolean_from_data, prepare_bool, prepare_float, prepare_int,
            retrieve_y_bounds_from_plot_data, skip_every_nth, skip_outside_of_bound,
        },
        ui::{
            lib_styling::app_style_settings::{
                AMOUNT_TO_FILTER_FOR_BOOLEAN_VALUES, CHART_MARGIN, CHART_MAX_X_LABELS,
                CHART_MAX_Y_LABELS, CHART_X_LABEL_AREA_SIZE, CHART_Y_LABEL_AREA_SIZE, CIRCLE_SIZE,
                TEXT_ACCENT_1_COLOR, TEXT_ACCENT_2_COLOR,
            },
            lib_widgets::lib_graphs::struct_zoom_bounds::{zoom_range_is_small, ZoomBound2D},
        },
    },
    DataValue, ProcessedPlotData,
};

use plotters::{
    chart::ChartContext,
    coord::types::RangedCoordf64,
    prelude::{Cartesian2d, Circle, FontTransform, Rectangle},
    series::{LineSeries, PointSeries},
    style::{IntoFont, RGBAColor},
};

use plotters_iced::{Chart, ChartBuilder, DrawingBackend, Renderer};

use iced::{
    advanced::graphics::core::event,
    mouse::{self, Cursor},
    widget::canvas::{self, Frame, Geometry},
    Point, Size,
};

impl ProcessedPlotData {
    /// draws vertical line on given timestamp to indicate a String-Value
    fn draw_line_for_string<DB: DrawingBackend>(
        &self,
        chart: &mut ChartContext<'_, DB, Cartesian2d<RangedCoordf64, RangedCoordf64>>,
        timestamp: f64,
        color: RGBAColor,
    ) {
        let chart_y_ranges = chart.plotting_area().get_y_range();

        let vertical_line = LineSeries::new(
            vec![
                (timestamp, chart_y_ranges.start),
                (timestamp, chart_y_ranges.end),
            ],
            &color,
        );

        let _ = chart.draw_series(vertical_line);
    }
}
// Fixme remove bound to ScreenSingleFlowPlotting-Struct
// Should be bound to PlotSeriesData
// Issues with that:
// - requires to signal / return the current "spec-frame" for accessing mouse-location on graph
// - requires values like bools to indicate whether to draw lineseries or not
// impl<Message: 'static + Clone + MessageCreator> Chart<Message> for ProcessedPlotData {
impl<Message: 'static + Clone + MessageCreator> Chart<Message> for ProcessedPlotData {
    type State = ();

    // FIXME maybe add caching values !
    #[inline]
    fn draw<R: Renderer, F: Fn(&mut Frame)>(
        &self,
        renderer: &R,
        bounds: Size,
        draw_fn: F,
    ) -> Geometry {
        renderer.draw_cache(&self.chart_cache, bounds, draw_fn)
    }

    /// generates graph containing all selected attributes for a given TCPFlow
    // Assume that data to plot is available from system
    fn build_chart<DB: DrawingBackend>(&self, _: &Self::State, mut builder: ChartBuilder<DB>) {
        println!("attempting to generate chart");
        let read_settings = self.app_settings.read().unwrap();
        let reduced_point_amount_when_zooming = read_settings.reduce_point_density_on_zoom;
        let reduced_point_skip_value = read_settings.amount_to_skip_on_zoom;
        let range_threshold = read_settings.graph_pointseries_threshold;
        let skip_amount = read_settings.datavalue_skip_counter;

        let zoom_limits = if self.generate_y_bounds {
            let new_zoom_bounds = ZoomBound2D {
                x: self.zoom_bounds.x.clone(),
                y: retrieve_y_bounds_from_plot_data(self, self.zoom_bounds.clone()),
            };
            // self.update_zoom_bounds(new_zoom_bounds.clone());
            new_zoom_bounds
        } else {
            self.zoom_bounds.clone()
        };

        let lower_x = zoom_limits.x.lower;
        let upper_x = zoom_limits.x.upper;

        let lower_y = zoom_limits.y.lower;
        let upper_y = zoom_limits.y.upper;
        let is_small_display_range = zoom_range_is_small(&zoom_limits, range_threshold);

        println!(
            "Debug: timestamp bounds are:\n low:{:?}\n upper:{:?}\n is below treshold: {:?}",
            lower_x, upper_x, is_small_display_range,
        );

        //  --- CREATING BASIC STRUCTURE --- //
        let mut chart = builder
            // creating plot
            .caption("Plotting TCP-Flow", ("Arial", 20).into_font())
            .x_label_area_size(CHART_X_LABEL_AREA_SIZE)
            .y_label_area_size(CHART_Y_LABEL_AREA_SIZE)
            .margin(CHART_MARGIN) // FIXME add constant!
            .build_cartesian_2d(lower_x..upper_x, lower_y..upper_y)
            .expect("failed to build chart");

        // adding axis description
        chart
            .configure_mesh()
            .x_desc("timestamp")
            .x_labels(CHART_MAX_X_LABELS)
            .y_label_style(
                ("sans-serif", 14)
                    .into_font()
                    .color(&TEXT_ACCENT_1_COLOR)
                    .transform(FontTransform::Rotate270),
            )
            .x_label_style(
                ("sans-serif", 14)
                    .into_font()
                    .color(&TEXT_ACCENT_1_COLOR)
                    .transform(FontTransform::Rotate270),
            )
            .y_labels(CHART_MAX_Y_LABELS)
            // ) // Rotate x-axis labels
            // FIXME add correct annotation
            // .y_desc("time series data")
            .draw()
            .unwrap();

        // traversing each attribute selected to construt its plot:
        chart
            .configure_series_labels()
            .draw()
            .expect("failed drawing");

        // -- / Drawing Zoom-Indicator \ --
        // this draws a rectangle around the starting and end-point indicated by the mouse-event
        // visualizes selection to zoom into

        if self.pressed_cursor {
            if let Some((initial_p, current_p)) =
                self.first_pressed_position.zip(self.current_position)
            {
                // drawing a rectangle to show where we are zooming into
                let rectangle = Rectangle::new(
                    [(initial_p.0, initial_p.1), (current_p.0, current_p.1)],
                    &TEXT_ACCENT_2_COLOR,
                );
                let _ = chart.draw_series(std::iter::once(rectangle));
            }
        }
        // reference for multiple plots at once from here:
        // https://towardsdatascience.com/rustic-data-data-visualization-with-plotters-part-1-7a34b6f4a603#2e03
        //  creating line for each attribute selected!

        let data_point_collection = &self.point_collection;
        for series_attribute in data_point_collection {
            println!("drawing: {:?}", series_attribute.name);
            // FIXME --> memory footprint of cloning?
            let as_bundle: Vec<(f64, DataValue)> = series_attribute
                .timestamps
                .iter()
                .zip(series_attribute.data.iter())
                .map(|collection| (collection.0.clone(), collection.1.clone()))
                .collect();
            let series_color = &series_attribute.line_color;

            let reduced_point_amount = if self.pressed_cursor && reduced_point_amount_when_zooming {
                skip_every_nth(&as_bundle, reduced_point_skip_value)
            } else {
                skip_every_nth(&as_bundle, skip_amount as usize)
            };

            let only_in_bounds = skip_outside_of_bound(&reduced_point_amount, &zoom_limits);

            match series_attribute.data_val_type {
                DataValue::Int(_) => {
                    //  creating plot with boolean values!
                    // FIXME refactor to own function!
                    let converted_as_float = prepare_int(&only_in_bounds);
                    println!("Debug: drawing {:?}", series_attribute.name);
                    if self.draw_point_series && is_small_display_range {
                        let _ = chart.draw_series(PointSeries::of_element(
                            converted_as_float, // fixme dynamically set color
                            CIRCLE_SIZE,
                            series_color,
                            &|c, _, st| return Circle::new(c, CIRCLE_SIZE, st.filled()),
                        ));
                    } else {
                        let _ = chart.draw_series(LineSeries::new(
                            converted_as_float, // fixme dynamically set color
                            series_color,
                        ));
                    }
                }
                DataValue::Float(_) => {
                    let converted_as_float = prepare_float(&only_in_bounds);
                    if self.draw_point_series && is_small_display_range {
                        let _ = chart.draw_series(PointSeries::of_element(
                            converted_as_float,
                            CIRCLE_SIZE,
                            series_color,
                            &|coords, _, shape| {
                                return Circle::new(coords, CIRCLE_SIZE, shape.filled());
                            },
                        ));
                    } else {
                        let _ =
                            chart.draw_series(LineSeries::new(converted_as_float, series_color));
                    }
                }
                DataValue::Boolean(_) => {
                    // booleans are always shown in the middle of the zoomed in area!
                    let no_false_entries = filter_false_boolean_from_data(&only_in_bounds);
                    let skipped_entries = match is_small_display_range {
                        true => no_false_entries,
                        false => {
                            skip_every_nth(&no_false_entries, AMOUNT_TO_FILTER_FOR_BOOLEAN_VALUES)
                        }
                    };
                    let converted_as_float = prepare_bool(&skipped_entries, &zoom_limits.y);
                    let _ = chart.draw_series(PointSeries::of_element(
                        converted_as_float,
                        CIRCLE_SIZE,
                        series_color,
                        &|coords, _, shape| {
                            return Circle::new(coords, CIRCLE_SIZE, shape.filled());
                        },
                    ));
                    // let _ = chart.draw_series(LineSeries::new(converted_as_float, series_color));
                }
                DataValue::String(_) => {
                    // drawing a vertical line for each string value --> at a given timestamps
                    for collection in only_in_bounds {
                        if let DataValue::String(_) = collection.1 {
                            self.draw_line_for_string(
                                &mut chart,
                                collection.0,
                                series_color.clone(),
                            );
                        }
                    }
                }
            }
        }

        // updating spec to allow interaction with graph
        *self.spec_frame.borrow_mut() = Some(chart.as_coord_spec().clone())
    }

    // definition of update --> for tracking mouse-movement!
    fn update(
        &self,
        _state: &mut Self::State,
        event: iced::widget::canvas::Event,
        bounds: iced::Rectangle,
        cursor: iced::mouse::Cursor,
    ) -> (iced::event::Status, Option<Message>) {
        if let Cursor::Available(point) = cursor {
            match event {
                canvas::Event::Mouse(evt) if bounds.contains(point) => {
                    let p_origin = bounds.position();
                    let p = point - p_origin;
                    return (
                        event::Status::Captured,
                        // FIXMEREFACTOR --> generalize to function of type ;;
                        // Some(MessagePlotting::MouseEvent(evt, Point::new(p.x, p.y))), // Some(Message::create_mouse_event_message(evt, Point::new(p.x, p.y))),
                        Some(Message::create_mouse_event_message(
                            evt,
                            Point::new(p.x, p.y),
                        )),
                    );
                }
                _ => {}
            }
        }
        (event::Status::Ignored, None)
    }
}

/// constraining MessageType to guarantee availability of Message for MouseEvents
pub trait MessageCreator {
    fn create_mouse_event_message(event: mouse::Event, point: iced::Point) -> Self;
}
