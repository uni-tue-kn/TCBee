// denotes logic for adjusting and modifying datapoints used to visualize
//

use crate::modules::ui::lib_widgets::lib_graphs::{
    struct_flow_series_data::FlowSeriesData,
    struct_processed_plot_data::ProcessedPlotData,
    struct_string_series_wrapper::{view_wrapper, StringSeriesWrapper},
    struct_zoom_bounds::{ZoomBound, ZoomBound2D},
};
use iced::{widget::Column, Color, Element};
use plotters::style::RGBAColor;
use rand::{distr::Uniform, prelude::Distribution};
use rust_ts_storage::DataValue;
use std::f64::{MAX, MIN};

/// for the given datapoints, receive the upper and lower bounds for Y and return them as ZoomBound
/// assumes that the given Vec<> includes the range to find the max/min in
pub fn retrieve_y_bounds_from_selected_range(
    plot_data: &Vec<(f64, DataValue)>,
    current_y_zoom: &ZoomBound,
) -> ZoomBound {
    let mut min: f64 = MAX;
    let mut max: f64 = MIN;
    for collection in plot_data {
        let as_maybe_float = interpret_datavalue_as_float(&collection.1, current_y_zoom);
        // skipping invalid entries
        if as_maybe_float.is_none() {
            continue;
        }
        // maybe the error comes up here?
        let as_float = as_maybe_float.unwrap();
        if as_float < min {
            min = as_float;
        }
        if as_float > max {
            max = as_float;
        }
    }
    ZoomBound {
        lower: min,
        upper: max,
    }
}

pub fn interpret_datavalue_as_float(value: &DataValue, _current_y_zoom: &ZoomBound) -> Option<f64> {
    match value {
        DataValue::Float(val) => Some(*val),
        DataValue::Int(val) => Some(*val as f64),
        DataValue::String(_) => None,
        DataValue::Boolean(_val) => {
            None
            // FIXME might be removed, considering that we would like to display booleans all the time?!

            // if *val {
            // Some((current_y_zoom.upper - current_y_zoom.lower) / 2.0)
            // } else {
            // Some(0.0)
            // }
        }
    }
}

pub fn skip_every_nth(plot_data: &Vec<(f64, DataValue)>, n: usize) -> Vec<(f64, DataValue)> {
    let filtered_data: Vec<(f64, DataValue)> = plot_data
        .iter()
        .enumerate()
        .filter(|(index, _collection)| index % n == 0)
        .map(|(_, collection)| collection.clone())
        .collect();
    filtered_data
}

/// given Zoom-Boundaries for both X and Y filter out points that are outside of those bounds
/// iterates over values and retains values within the boundaries
/// returns copy of filtered datapoints.
pub fn skip_outside_of_bound(
    plot_data: &Vec<(f64, DataValue)>,
    bounds: &ZoomBound2D,
) -> Vec<(f64, DataValue)> {
    // println!("Debug outside_bound_skip -----\nZoomBoundsare: {:?}",bounds);
    // println!("before filtering {:?} amount of points are found",plot_data.len());
    let filtered_by_x: Vec<(f64, DataValue)> = plot_data
        .iter()
        .filter(|collection| collection.0 > bounds.x.lower && collection.0 < bounds.x.upper)
        .map(|val| val.clone())
        .collect();

    // filtering values where y-axis does not match the boundaries
    let filtered_by_y: Vec<(f64, DataValue)> = filtered_by_x
        .iter()
        .filter(|collection| {
            let val_as_float = interpret_datavalue_as_float(&collection.1, &bounds.y);
            if val_as_float.is_some() {
                val_as_float.unwrap() > bounds.y.lower && val_as_float.unwrap() < bounds.y.upper
            } else {
                true
            }
        })
        // cloning resulting points so that we can return them afterwards
        .map(|val| val.clone())
        .collect();
    filtered_by_y
}

pub fn filter_false_boolean_from_data(plot_data: &Vec<(f64, DataValue)>) -> Vec<(f64, DataValue)> {
    let only_true_extracted: Vec<(f64, DataValue)> = plot_data
        .into_iter()
        .filter(|collection| {
            if let DataValue::Boolean(value) = collection.1 {
                value
            } else {
                false
            }
        })
        .map(|collection| (collection.0, collection.1.clone()))
        .collect();
    only_true_extracted
}

/// returns vec containing (timestamp,bool as float)
/// assumes to retrieve DataValue = bool
pub fn prepare_bool(plot_data: &Vec<(f64, DataValue)>, zoom_limits: &ZoomBound) -> Vec<(f64, f64)> {
    let new_data: Vec<(f64, f64)> = plot_data
        .iter()
        .map(|collection| {
            let as_float = if let DataValue::Boolean(bool) = collection.1 {
                match bool {
                    true => {
                        (((zoom_limits.upper - zoom_limits.lower) / 2.0).round()
                            + zoom_limits.lower)
                    }
                    false => zoom_limits.lower,
                }
            } else {
                zoom_limits.lower
            };
            (collection.0, as_float)
        })
        .collect();
    new_data
}

pub fn prepare_float(plot_data: &Vec<(f64, DataValue)>) -> Vec<(f64, f64)> {
    println!("Debug: found float vals, converting");
    plot_data
        .iter()
        .map(|collection| {
            let as_float = if let DataValue::Float(float_value) = collection.1 {
                float_value
            } else {
                0.0
            };
            (collection.0, as_float)
        })
        .collect()
}

pub fn prepare_int(plot_data: &Vec<(f64, DataValue)>) -> Vec<(f64, f64)> {
    // println!("Debug: found int vals, converting");
    plot_data
        .iter()
        .map(|collection| {
            let as_float = if let DataValue::Int(as_int) = collection.1 {
                as_int as f64
            } else {
                0.0
            };
            (collection.0, as_float)
        })
        .collect()
}

pub fn extract_non_empty_string(plot_data: &Vec<(f64, DataValue)>) -> Vec<(f64, String)> {
    let new_data: Vec<(f64, String)> = plot_data
        .iter()
        // filtering None-Values, only retaining collections with Some string
        .filter(|collection| {
            if let DataValue::String(_) = &collection.1 {
                true
            } else {
                false
            }
        })
        // assumption: only String-Values available
        .map(|collection| {
            let as_string = if let DataValue::String(string) = &collection.1 {
                string.clone()
            } else {
                // FIXME could this be improved?
                String::from("no value found")
            };
            (collection.0, as_string)
        })
        .collect();
    new_data
}

pub fn filter_for_string_values(plot_data: &ProcessedPlotData) -> Option<Vec<&FlowSeriesData>> {
    let filtered_time_series: Vec<&FlowSeriesData> = plot_data
        .point_collection
        .iter()
        .filter(|series| match series.data_val_type {
            DataValue::String(_) => true,
            _ => false,
        })
        .collect();
    if filtered_time_series.is_empty() {
        None
    } else {
        Some(filtered_time_series)
    }
}

pub fn prepare_string_from_flow_series(
    data_points: Vec<&FlowSeriesData>,
) -> Vec<StringSeriesWrapper> {
    let as_converted_bundle = data_points
        .into_iter()
        .map(|series| {
            let bundled_vals: Vec<(f64, DataValue)> = series
                .timestamps
                .iter()
                .zip(series.data.iter())
                .map(|collection| {
                    // FIXME: copy instead!
                    // clone will clone the dereference objec,t otherwise the reference
                    (collection.0.clone(), collection.1.clone())
                })
                .collect();
            StringSeriesWrapper {
                name: series.name.clone(),
                formatted_collection: bundled_vals,
            }
        })
        .collect();
    as_converted_bundle
}

pub fn filter_and_prepare_string_from_series(
    plot_data: &ProcessedPlotData,
) -> Option<Vec<StringSeriesWrapper>> {
    let maybe_filtered_flow_series = filter_for_string_values(plot_data);
    if let Some(filtered_flow_series) = maybe_filtered_flow_series {
        Some(prepare_string_from_flow_series(filtered_flow_series))
    } else {
        None
    }
}

// MISC: FIXME: should be moved to another location!
/// FIXME: Acts as placeholder, should be replaced with a less random implementation later
/// returns n random colors of a selection of colors
pub fn generate_n_random_colors(n: usize) -> Vec<RGBAColor> {
    let mut colors: Vec<RGBAColor> = Vec::new();
    let mut rng_thread = rand::rng();

    for _ in 0..n {
        let red_channel: u8 = Uniform::new(30, 255).unwrap().sample(&mut rng_thread);
        let green_channel: u8 = Uniform::new(20, 255).unwrap().sample(&mut rng_thread);
        let blue_channel: u8 = Uniform::new(30, 255).unwrap().sample(&mut rng_thread);
        let new_color = RGBAColor(red_channel, green_channel, blue_channel, 1.0);
        colors.push(new_color);
    }
    colors
}

pub fn convert_rgba_to_iced_color(color: &RGBAColor) -> Color {
    Color::from_rgb8(color.0, color.1, color.2)
}
