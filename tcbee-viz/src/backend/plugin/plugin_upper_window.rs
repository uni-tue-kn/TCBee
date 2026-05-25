use ts_storage::DataValue;

use crate::data::series_data::SeriesData;

use super::trait_plugin::Plugin;

/// Computes UPPER_WND = SND_UNA + SND_WND for each timestamp.
pub struct UpperWindowPlugin {
    required: Vec<String>,
}

impl Default for UpperWindowPlugin {
    fn default() -> Self {
        Self {
            required: vec!["SND_UNA".to_string(), "SND_WND".to_string()],
        }
    }
}

impl Plugin for UpperWindowPlugin {
    fn name(&self) -> &str {
        "Upper TCP Window"
    }

    fn description(&self) -> &str {
        "Calculates the upper bound of the sliding TCP window: UPPER_WND = SND_UNA + SND_WND."
    }

    fn required_series(&self) -> Vec<String> {
        self.required.clone()
    }

    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String> {
        let snd_una = input.first().ok_or("Missing SND_UNA series")?;
        let snd_wnd = input.get(1).ok_or("Missing SND_WND series")?;

        if !snd_una.val_type.type_equal(&snd_wnd.val_type) {
            return Err("SND_UNA and SND_WND have mismatched types".to_string());
        }

        let ts_type = snd_una.val_type.type_to_int();
        if ts_type > 1 {
            return Err("SND_UNA/SND_WND must be Int or Float".to_string());
        }

        let mut raw_data: Vec<(f64, DataValue)> = Vec::new();
        let mut y_min = f64::MAX;
        let mut y_max = f64::MIN;

        for ((t_una, v_una), (_, v_wnd)) in snd_una.raw_data.iter().zip(snd_wnd.raw_data.iter()) {
            let sum = match ts_type {
                0 => {
                    let DataValue::Int(a) = v_una else { continue };
                    let DataValue::Int(b) = v_wnd else { continue };
                    let s = a + b;
                    y_min = y_min.min(s as f64);
                    y_max = y_max.max(s as f64);
                    DataValue::Int(s)
                }
                _ => {
                    let DataValue::Float(a) = v_una else { continue };
                    let DataValue::Float(b) = v_wnd else { continue };
                    let s = a + b;
                    y_min = y_min.min(s);
                    y_max = y_max.max(s);
                    DataValue::Float(s)
                }
            };
            raw_data.push((*t_una, sum));
        }

        if y_min > y_max {
            y_min = 0.0;
            y_max = 1.0;
        }

        let points: Vec<(f64, f64)> = raw_data
            .iter()
            .filter_map(|(t, v)| match v {
                DataValue::Int(i) => Some((*t, *i as f64)),
                DataValue::Float(f) => Some((*t, *f)),
                _ => None,
            })
            .collect();

        let val_type = snd_una.val_type.clone();
        let mut out = SeriesData::new(
            "UPPER_WND".to_string(),
            -1,
            val_type,
            snd_una.global_t_min,
            snd_una.global_t_max,
            y_min,
            y_max,
            egui::Color32::from_rgb(80, 180, 80),
        );
        out.points = points;
        out.raw_data = raw_data;
        Ok(vec![out])
    }
}
