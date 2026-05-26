use egui::Color32;
use ts_storage::DataValue;

/// A single time series with its currently-loaded window of data points.
/// `points` only contains data for the visible time window; the full dataset lives in the DB.
pub struct SeriesData {
    pub name: String,
    pub series_id: i64,
    /// Type discriminant (e.g. `DataValue::Float(0.0)`, `DataValue::Int(0)`, …).
    pub val_type: DataValue,
    /// (timestamp, value as f64) for the current visible window.
    pub points: Vec<(f64, f64)>,
    /// String-type entries are kept separately and shown as annotations.
    pub string_points: Vec<(f64, String)>,
    /// Raw (timestamp, DataValue) — only populated for plugin inputs, not during plotting.
    pub raw_data: Vec<(f64, DataValue)>,
    /// Global extents from the database.
    pub global_t_min: f64,
    pub global_t_max: f64,
    pub global_y_min: f64,
    pub global_y_max: f64,
    pub color: Color32,
    /// The time range that is currently loaded in `points` / `string_points`.
    pub loaded_range: Option<(f64, f64)>,
    /// Minimum time distance used when loading the current points.
    pub loaded_sample_interval: f64,
}

impl SeriesData {
    pub fn new(
        name: String,
        series_id: i64,
        val_type: DataValue,
        global_t_min: f64,
        global_t_max: f64,
        global_y_min: f64,
        global_y_max: f64,
        color: Color32,
    ) -> Self {
        Self {
            name,
            series_id,
            val_type,
            points: Vec::new(),
            string_points: Vec::new(),
            raw_data: Vec::new(),
            global_t_min,
            global_t_max,
            global_y_min,
            global_y_max,
            color,
            loaded_range: None,
            loaded_sample_interval: 0.0,
        }
    }

    pub fn is_string_type(&self) -> bool {
        matches!(self.val_type, DataValue::String(_))
    }

    pub fn is_boolean_type(&self) -> bool {
        matches!(self.val_type, DataValue::Boolean(_))
    }
}
