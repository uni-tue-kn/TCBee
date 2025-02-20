// contains logic and implementation for ZoomBounds and ZoomBounds2D

use std::sync::{Arc, RwLock};

use crate::modules::{
    backend::{app_settings::ApplicationSettings, struct_tcp_flow_wrapper::TcpFlowWrapper},
    ui::lib_styling::app_style_settings::{
        DEFAULT_X_MAX, DEFAULT_X_MIN, DEFAULT_Y_MAX, DEFAULT_Y_MIN,
    },
};

use super::struct_processed_plot_data::ProcessedPlotData;

#[derive(Debug, Clone)]
pub struct ZoomBound {
    pub lower: f64,
    pub upper: f64,
}

impl Default for ZoomBound {
    fn default() -> Self {
        ZoomBound {
            lower: DEFAULT_Y_MIN,
            upper: DEFAULT_Y_MAX,
        }
    }
}
#[derive(Debug, Clone)]
pub struct ZoomBound2D {
    pub x: ZoomBound,
    pub y: ZoomBound,
}

impl Default for ZoomBound2D {
    fn default() -> Self {
        ZoomBound2D {
            x: ZoomBound {
                lower: DEFAULT_X_MIN,
                upper: DEFAULT_X_MAX,
            },
            y: ZoomBound {
                lower: DEFAULT_Y_MIN,
                upper: DEFAULT_Y_MAX,
            },
        }
    }
}

pub fn points_are_close(p0: &(f64, f64), p1: &(f64, f64)) -> bool {
    let delta = (p1.0 - p0.0, p1.1 - p0.1);
    (delta.0 * delta.0 + delta.1 * delta.1).sqrt() <= 2.0
}

pub fn zoom_range_is_small(range: &ZoomBound2D, threshold: f64) -> bool {
    let difference_of_timestamps = range.x.upper - range.x.lower;
    if difference_of_timestamps <= threshold {
        true
    } else {
        false
    }
}

pub fn merge_two_bounds(first_bound: &ZoomBound, second_bound: &ZoomBound) -> ZoomBound {
    ZoomBound {
        lower: match first_bound.lower < second_bound.lower {
            true => first_bound.lower,
            false => second_bound.lower,
        },
        upper: match first_bound.upper > second_bound.upper {
            true => first_bound.upper,
            false => second_bound.upper,
        },
    }
}

pub fn merge_two_2d_bounds(first_bound: &ZoomBound2D, second_bound: &ZoomBound2D) -> ZoomBound2D {
    ZoomBound2D {
        x: merge_two_bounds(&first_bound.x, &second_bound.x),
        y: merge_two_bounds(&first_bound.y, &second_bound.y),
    }
}

pub fn retrieve_max_series_bound(
    app_settings: &Arc<RwLock<ApplicationSettings>>,
    selected_flow: &TcpFlowWrapper,
) -> Option<ZoomBound> {
    let read_settings = app_settings.read().unwrap();
    let backend = &read_settings.intermediate_interface;
    backend.receive_active_series_max_bounds(selected_flow.selected_series.clone())
}

pub fn receive_flow_bounds(
    flow_id: Option<i64>,
    app_settings: &Arc<RwLock<ApplicationSettings>>,
) -> Option<ZoomBound> {
    let read_settings = app_settings.read().unwrap();
    let backend = &read_settings.intermediate_interface;
    let bounds = &backend.receive_active_flow_bounds_x(&flow_id);
    bounds.clone()
}

pub fn retrieve_default_zoom_for_one_flow(
    app_settings: &Arc<RwLock<ApplicationSettings>>,
    selected_flow: &TcpFlowWrapper,
) -> ZoomBound2D {
    let base_bounds = receive_flow_bounds(selected_flow.flow_id, app_settings);
    let default_y_bound = ZoomBound {
        lower: DEFAULT_Y_MIN,
        upper: DEFAULT_Y_MAX,
    };
    match base_bounds {
        Some(boundary) => {
            // updating to default boundary
            ZoomBound2D {
                x: ZoomBound {
                    lower: boundary.lower,
                    upper: boundary.upper,
                },
                y: retrieve_max_series_bound(app_settings, selected_flow)
                    .unwrap_or(default_y_bound),
            }
        }
        _ => {
            // should not occur lol?
            ZoomBound2D {
                x: ZoomBound {
                    lower: DEFAULT_X_MIN,
                    upper: DEFAULT_X_MAX,
                },
                y: retrieve_max_series_bound(app_settings, selected_flow)
                    .unwrap_or(default_y_bound),
            }
        }
    }
}

pub fn retrieve_default_zoom_for_two_flows(
    app_settings: &Arc<RwLock<ApplicationSettings>>,
    first_flow: &TcpFlowWrapper,
    second_flow: &TcpFlowWrapper,
) -> ZoomBound2D { 
    let range_1 = retrieve_default_zoom_for_one_flow(app_settings, first_flow);
    let range_2 =  retrieve_default_zoom_for_one_flow(app_settings,second_flow);
    merge_two_2d_bounds(&range_1, &range_2)
}

pub fn retrieve_max_series_bound_of_two_flows(
    app_settings:&Arc<RwLock<ApplicationSettings>>,
    first_flow:&TcpFlowWrapper,
    second_flow:&TcpFlowWrapper
) -> Option<ZoomBound>{
    let read_settings = app_settings.read().unwrap();
    let backend_connection = &read_settings.intermediate_interface;
    let maybe_first_bounds = backend_connection.receive_active_series_max_bounds(first_flow.selected_series.clone());
    let maybe_second_bounds = backend_connection.receive_active_series_max_bounds(second_flow.selected_series.clone());
    match maybe_first_bounds {
        Some(first_bound) => {
            match maybe_second_bounds {
                Some(second_bound) => {
                    Some(merge_two_bounds(&first_bound,&second_bound))
                }
                None => None
            }
        }
        None => None
    }
}

pub fn generate_zoom_bounds_from_coordinates_in_data(ref_data: &ProcessedPlotData) -> ZoomBound2D {
        if let Some(coord_start) = ref_data 
            .first_pressed_position
            .zip(ref_data.second_pressed_position)
        {
            // obtained new boundaries
            if points_are_close(&coord_start.0, &coord_start.1) {
                println!("points too close, aborting");
                // return self.zoom_bounds.clone().unwrap_or_default();
                return ref_data.zoom_bounds.clone();
            }
            let min_x = coord_start.0 .0.min(coord_start.1 .0);
            let max_x = coord_start.0 .0.max(coord_start.1 .0);
            let min_y = coord_start.0 .1.min(coord_start.1 .1);
            let max_y = coord_start.0 .1.max(coord_start.1 .1);

            let x_bound = ZoomBound {
                lower: min_x,
                upper: max_x,
            };
            let y_bound = ZoomBound {
                lower: min_y,
                upper: max_y,
            };
            ZoomBound2D {
                x: x_bound,
                y: y_bound,
            }
        } else {
            ref_data.zoom_bounds.clone()
        }
    }