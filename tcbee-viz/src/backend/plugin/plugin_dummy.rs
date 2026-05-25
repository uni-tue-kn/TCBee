use rand::{distr::Uniform, prelude::Distribution, rng};
use ts_storage::DataValue;

use crate::data::series_data::SeriesData;

use super::trait_plugin::Plugin;

pub struct DummyPlugin {
    required: Vec<String>,
}

impl Default for DummyPlugin {
    fn default() -> Self {
        Self {
            required: vec!["ack_num".to_string(), "seq_num".to_string()],
        }
    }
}

impl Plugin for DummyPlugin {
    fn name(&self) -> &str {
        "Dummy Plugin"
    }

    fn description(&self) -> &str {
        "Generates a random constant-line series for every timestamp from the first input series. \
         Useful for testing the plugin system."
    }

    fn required_series(&self) -> Vec<String> {
        self.required.clone()
    }

    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String> {
        let first = input.first().ok_or("No input series provided")?;

        let mut rng_thread = rng();
        let dist = Uniform::new(40_000_000.0, 520_000_000.0).unwrap();

        let raw_data: Vec<(f64, DataValue)> = first
            .raw_data
            .iter()
            .map(|(t, _)| (*t, DataValue::Float(dist.sample(&mut rng_thread))))
            .collect();

        let points: Vec<(f64, f64)> = raw_data
            .iter()
            .filter_map(|(t, v)| {
                if let DataValue::Float(f) = v {
                    Some((*t, *f))
                } else {
                    None
                }
            })
            .collect();

        let mut out = SeriesData::new(
            "tst_rndm".to_string(),
            -1,
            DataValue::Float(0.0),
            first.global_t_min,
            first.global_t_max,
            30.0,
            520_000_000.0,
            egui::Color32::from_rgb(200, 80, 80),
        );
        out.points = points;
        out.raw_data = raw_data;
        Ok(vec![out])
    }
}
