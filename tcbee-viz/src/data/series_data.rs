use egui::Color32;
use ts_storage::{DataValue, SeriesInfo, ValueKind};

use crate::backend::binding::series_label;

/// A single time series with its currently-loaded window of data points.
/// `points` only contains data for the visible time window; the full dataset lives in the DB.
pub struct SeriesData {
    pub name: String,
    pub series_id: i64,
    /// Catalog row of a series loaded from the database; `None` for plugin outputs.
    pub info: Option<SeriesInfo>,
    /// Kind of the values (`Int`, `Float`, `Bool`, `String`).
    pub val_type: ValueKind,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        series_id: i64,
        val_type: ValueKind,
        global_t_min: f64,
        global_t_max: f64,
        global_y_min: f64,
        global_y_max: f64,
        color: Color32,
    ) -> Self {
        Self {
            name,
            series_id,
            info: None,
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

    /// A series of the database, named by its label (`name · source · dir`). The value range
    /// comes from the catalog.
    pub fn from_info(
        info: &SeriesInfo,
        global_t_min: f64,
        global_t_max: f64,
        color: Color32,
    ) -> Self {
        let (y_min, y_max) = info.v_min.zip(info.v_max).unwrap_or((0.0, 1.0));
        let mut sd = Self::new(
            series_label(info),
            info.id,
            info.value_type.value_kind(),
            global_t_min,
            global_t_max,
            y_min,
            y_max,
            color,
        );
        sd.info = Some(info.clone());
        sd
    }

    pub fn is_string_type(&self) -> bool {
        self.val_type == ValueKind::String
    }

    pub fn is_boolean_type(&self) -> bool {
        self.val_type == ValueKind::Bool
    }
}
