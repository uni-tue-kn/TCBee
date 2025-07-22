// dummy implementation
// primarily used to provide means to debug and test
// operation of the module system

use std::i64;

use iced::advanced::svg::Data;
use iced::widget::canvas::Cache;
use ts_storage::DataValue;

// used to generate random data
use rand::distr::{Distribution, Uniform};
use rand::rng;

use crate::modules::{
    backend::database_processor::trait_database_processor::PreProcessor,
    ui::lib_widgets::lib_graphs::{
        struct_flow_series_data::FlowSeriesData, struct_processed_plot_data::ProcessedPlotData,
    },
};

// Calculate upper windows based on SND_UNA + SND_WND
pub struct UpperWindow {
    required_timeseries_as_string: Vec<String>,
}

impl Default for UpperWindow {
    fn default() -> Self {
        UpperWindow {
            required_timeseries_as_string: Vec::from([
                "SND_UNA".to_string(),
                "SND_WND".to_string(),
            ]),
        }
    }
}

impl PreProcessor for UpperWindow {
    fn receive_name(&self) -> String {
        "Upper TCP Window Number".to_string()
    }

    fn receive_description(&self) -> String {
        "
        Calculates the upper bound of the sliding TCP window based on SND_UNA + SND_WND
        "
        .to_string()
    }

    fn create_new_time_series_from_plot_data(
        &self,
        plot_data: &ProcessedPlotData,
    ) -> Result<Vec<FlowSeriesData>, String> {
        // Get required series from data vector
        let series_collection = &plot_data.point_collection;
        let snd_una = series_collection.first().ok_or("No SND_UNA series!")?;
        let snd_wnd = series_collection.get(1).ok_or("No SND_WND series!")?;

        let mut upper_window: Vec<DataValue> = Vec::new();

        let mut min: DataValue;
        let mut max: DataValue;

        if !snd_una.data_val_type.type_equal(&snd_wnd.data_val_type) {
            return Err("Mismatch in TS types!".to_string());
        }

        let ts_type = snd_una.data_val_type.type_to_int();

        match ts_type {
            0 => {
                min = DataValue::Int(i64::MAX);
                max = DataValue::Int(i64::MIN);
            }
            1 => {
                min = DataValue::Float(f64::MAX);
                max = DataValue::Float(f64::MIN);
            }
            _ => {
                return Err("Series invalid type: Are not INT or FLOAT!".to_string());
            }
        }

        for (una, wnd) in snd_una.data.iter().zip(snd_wnd.data.iter()) {
            // TODO: better err message
            let new_val = match ts_type {
                0 => {
                    let DataValue::Int(una_val) = una else {
                        unreachable!()
                    };
                    let DataValue::Int(wnd_val) = wnd else {
                        unreachable!()
                    };

                    let sum = una_val + wnd_val;

                    let DataValue::Int(cur_min) = min else {
                        unreachable!()
                    };
                    let DataValue::Int(cur_max) = max else {
                        unreachable!()
                    };

                    if sum < cur_min {
                        min = DataValue::Int(sum)
                    }

                    if sum > cur_max {
                        max = DataValue::Int(sum)
                    }

                    DataValue::Int(sum)
                }
                1 => {
                    let DataValue::Float(una_val) = una else {
                        unreachable!()
                    };
                    let DataValue::Float(wnd_val) = wnd else {
                        unreachable!()
                    };

                    let sum = una_val + wnd_val;

                    let DataValue::Float(cur_min) = min else {
                        unreachable!()
                    };
                    let DataValue::Float(cur_max) = max else {
                        unreachable!()
                    };

                    if sum < cur_min {
                        min = DataValue::Float(sum)
                    }

                    if sum > cur_max {
                        max = DataValue::Float(sum)
                    }

                    DataValue::Float(sum)
                }
                _ => {
                    unreachable!();
                }
            };

            upper_window.push(new_val);
        }

        let new_flow_series = FlowSeriesData {
            data: upper_window,
            name: "UPPER_WND".to_string(),
            timestamps: snd_una.timestamps.clone(),
            max_timestamp: snd_una.max_timestamp,
            min_timestamp: snd_una.min_timestamp,
            min_val: Some(min.clone()),
            max_val: Some(max),
            data_val_type: min,
            zoom_bounds: snd_una.zoom_bounds.clone(),
            chart_height: snd_una.chart_height,
            line_color: snd_una.line_color,
            cache: Cache::new(),
        };
        Ok(Vec::from([new_flow_series]))
    }

    fn receive_required_timeseries(&self) -> Vec<String> {
        self.required_timeseries_as_string.clone()
    }
}
