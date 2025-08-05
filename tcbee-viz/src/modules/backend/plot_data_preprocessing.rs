// denotes logic for adjusting and modifying datapoints used to visualize
//

use crate::modules::ui::lib_widgets::lib_graphs::{
    struct_flow_series_data::FlowSeriesData,
    struct_processed_plot_data::ProcessedPlotData,
    struct_string_series_wrapper::{view_wrapper, StringSeriesWrapper},
    struct_zoom_bounds::{merge_two_bounds, ZoomBound, ZoomBound2D},
};
use iced::{widget::Column, Color, Element};
use plotters::style::{self, Color as _};
// use plotters::style::{Color, HSLColor, RGBAColor};
use rand::{distr::Uniform, prelude::Distribution};
use ts_storage::DataValue;
use std::{f64::{MAX, MIN}, usize};

pub fn retrieve_y_bounds_from_plot_data(
    plot_data: &ProcessedPlotData,
    zoom_bounds: ZoomBound2D,
) -> ZoomBound {
    let mut maximum_zoom_bounds = ZoomBound {
        lower: MAX,
        upper: MIN,
    };
    for series in &plot_data.point_collection {
        // let y_bounds = retrieve_y_bounds_from_selected_range(ser)
        let as_bundle: Vec<(f64, DataValue)> = series
            .timestamps
            .iter()
            .zip(series.data.iter())
            .map(|collection| (collection.0.clone(), collection.1.clone()))
            .collect();
        let only_in_bounds = skip_outside_of_bound(&as_bundle, &zoom_bounds);
        let amount_of_points = only_in_bounds.len();
        println!("amount of points for this series: {:?}", amount_of_points);
        if amount_of_points == 0 {
            continue;
        }
        let zoom_bounds = retrieve_y_bounds_from_collection_of_points(&only_in_bounds,&zoom_bounds.y);
        maximum_zoom_bounds = merge_two_bounds(&maximum_zoom_bounds, &zoom_bounds);
    }
    if maximum_zoom_bounds.lower == MAX && maximum_zoom_bounds.upper == MIN {
        zoom_bounds.y
    } else {
        maximum_zoom_bounds
    }
}

/// for the given datapoints, receive the upper and lower bounds for Y and return them as ZoomBound
/// assumes that the given Vec<> includes the range to find the max/min in
/// FIXMEMERGE
pub fn retrieve_y_bounds_from_collection_of_points(
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

#[derive(Clone)]
pub enum ColorScheme{
    Random,
    RandomHSL,
    LightTheme,
    DarkTheme,
}

/// returns n random colors of a selection of colors
pub fn retrieve_n_colors(selection:ColorScheme,n: usize) -> Vec<style::RGBAColor> {
    match selection{
        ColorScheme::Random => {
            generate_n_random_colors(n)
        }
        ColorScheme::RandomHSL => {
            generate_random_colors_hsl(0.7, 0.5, n)
        }
        ColorScheme::LightTheme => {
            let mut colors= generate_10_colors_scheme1();
            if n >= colors.len() {
                let mut more_colors = generate_n_random_colors(n-colors.len());
                colors.append(&mut more_colors)
            }
            return colors
        }
        ColorScheme::DarkTheme => {
            let mut colors = generate_12_colors_scheme2();
            if n >= colors.len() {
                let mut more_colors = generate_n_random_colors(n-colors.len());
                colors.append(&mut more_colors);
            }
            return colors
        }
    }
}
pub fn convert_rgba_to_iced_color(color: &style::RGBAColor) -> Color {
    Color::from_rgb8(color.0, color.1, color.2)
}

fn generate_n_random_colors(n:usize) -> Vec<style::RGBAColor> {
    let mut colors: Vec<style::RGBAColor> = Vec::new();
    let mut rng_thread = rand::rng();

    for _ in 0..n {
        let red_channel: u8 = Uniform::new(30, 255).unwrap().sample(&mut rng_thread);
        let green_channel: u8 = Uniform::new(20, 255).unwrap().sample(&mut rng_thread);
        let blue_channel: u8 = Uniform::new(30, 255).unwrap().sample(&mut rng_thread);
        let new_color = style::RGBAColor(red_channel, green_channel, blue_channel, 1.0);
        colors.push(new_color);
    }
    colors
}

fn generate_random_colors_hsl(saturation:f64, lightness:f64, n:usize) -> Vec<style::RGBAColor> {
    let mut colors: Vec<style::RGBAColor> = Vec::new();
    // let huedelta = 360/n;
    for index in 0..n {
        // let hue:f64 = huedelta * (index as f64);
        let hue:f64 = (index as f64) / (n as f64);
        let as_hsl = style::HSLColor(hue,saturation,lightness);
        let as_rgba_color = as_hsl.to_rgba();
        colors.push(as_rgba_color);
    };
    colors
}

fn generate_10_colors_scheme1() -> Vec<style::RGBAColor> {
    // of 10 colors
    vec![
    style::RGBAColor(215,25,28,1.0),
    style::RGBAColor(253,174,97,1.0),
    style::RGBAColor(255,255,191,1.0),
    style::RGBAColor(171,217,233,1.0),
    style::RGBAColor(44,123,182,1.0),
    style::RGBAColor(23, 34, 109,1.0),
    style::RGBAColor(96, 119, 209,1.0),
    style::RGBAColor(191, 197, 255,1.0),
    style::RGBAColor(210, 233, 206,1.0),
    style::RGBAColor(170, 182, 111,1.0)
    ]
}

fn generate_12_colors_scheme2() -> Vec<style::RGBAColor> {
    vec![
    style::RGBAColor(166,206,227,1.0),
    style::RGBAColor(31,120,180,1.0),
    style::RGBAColor(178,223,138,1.0),
    style::RGBAColor(51,160,44,1.0),
    style::RGBAColor(251,154,153,1.0),
    style::RGBAColor(227,26,28,1.0),
    style::RGBAColor(253,191,111,1.0),
    style::RGBAColor(255,127,0,1.0),
    style::RGBAColor(202,178,214,1.0),
    style::RGBAColor(106,61,154,1.0),
    style::RGBAColor(153, 50, 204,1.0),
    style::RGBAColor(177,89,40,1.0),
    ]
}