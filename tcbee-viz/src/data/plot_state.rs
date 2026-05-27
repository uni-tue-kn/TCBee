use ts_storage::TimeSeries;

use crate::{
    backend::db::{format_flow, DbBackend},
    data::{
        preprocessing::{compute_sample_interval, compute_skip_step, downsample, generate_colors},
        series_data::SeriesData,
    },
    settings::AppSettings,
};

/// Per-tab state for a single flow's plot: selected series, loaded data, and zoom bookkeeping.
pub struct PlotState {
    pub flow_id: Option<i64>,
    pub selected_series_ids: Vec<i64>,
    pub series: Vec<SeriesData>,
    /// Available series metadata + point count for the currently selected flow.
    pub available_series: Vec<(TimeSeries, i64)>,
    /// Current visible X bounds (mirrors egui_plot's view).
    pub x_min: f64,
    pub x_max: f64,
    /// Full extent of the flow — used for reset.
    pub data_x_min: f64,
    pub data_x_max: f64,
    /// Display each series in its own subplot.
    pub split_view: bool,
    /// Set to true inside the plot closure when the view has moved enough to reload.
    pub pending_reload: bool,
    /// Human-readable label for the flow (e.g. for legends).
    pub flow_label: String,
}

impl Default for PlotState {
    fn default() -> Self {
        Self {
            flow_id: None,
            selected_series_ids: Vec::new(),
            series: Vec::new(),
            available_series: Vec::new(),
            x_min: 0.0,
            x_max: 1.0,
            data_x_min: 0.0,
            data_x_max: 1.0,
            split_view: false,
            pending_reload: false,
            flow_label: String::new(),
        }
    }
}

impl PlotState {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Called when the user picks a new flow. Loads metadata and clears series selections.
    pub fn select_flow(&mut self, db: &DbBackend, flow_id: i64) {
        self.flow_id = Some(flow_id);
        self.selected_series_ids.clear();
        self.series.clear();
        self.available_series.clear();
        self.flow_label.clear();
        self.pending_reload = false;
        self.x_min = 0.0;
        self.x_max = 1.0;
        self.data_x_min = 0.0;
        self.data_x_max = 1.0;

        if let Some(flow) = db.get_flow_by_id(flow_id) {
            self.flow_label = format_flow(&flow);
            self.available_series = db
                .list_series_for_flow(&flow)
                .into_iter()
                .map(|ts| {
                    let count = db.get_point_count(ts.id);
                    (ts, count)
                })
                .collect();
        }
        if let Some((t_min, t_max)) = db.get_flow_x_bounds(flow_id) {
            self.data_x_min = t_min;
            self.data_x_max = t_max;
            self.x_min = t_min;
            self.x_max = t_max;
        }
    }

    /// Toggle a series on/off. Assigns a color when added.
    pub fn toggle_series(&mut self, db: &DbBackend, series_id: i64, settings: &AppSettings) {
        if let Some(pos) = self
            .selected_series_ids
            .iter()
            .position(|&id| id == series_id)
        {
            self.selected_series_ids.remove(pos);
            self.series.retain(|s| s.series_id != series_id);
        } else {
            self.selected_series_ids.push(series_id);
            // Assign the next color in the palette
            let color_idx = self.series.len();
            let colors = generate_colors(color_idx + 1);
            let color = *colors.last().unwrap_or(&egui::Color32::WHITE);

            if let Some(ts) = db.get_series_by_id(series_id) {
                let (y_min, y_max) = db.get_series_y_bounds(&[series_id]).unwrap_or((0.0, 1.0));
                let mut sd = SeriesData::new(
                    ts.name.clone(),
                    series_id,
                    ts.ts_type.clone(),
                    self.data_x_min,
                    self.data_x_max,
                    y_min,
                    y_max,
                    color,
                );
                let x_min = self.x_min;
                let x_max = self.x_max;
                load_series_window(db, &mut sd, x_min, x_max, settings, None);
                self.series.push(sd);
            }
        }
    }

    /// Returns the combined y extent across all loaded series.
    pub fn y_bounds(&self) -> (f64, f64) {
        let y_min = self
            .series
            .iter()
            .map(|s| s.global_y_min)
            .fold(f64::MAX, f64::min);
        let y_max = self
            .series
            .iter()
            .map(|s| s.global_y_max)
            .fold(f64::MIN, f64::max);
        if y_min > y_max {
            (0.0, 1.0)
        } else {
            (y_min, y_max)
        }
    }

    /// Returns true when the visible window has shifted more than 10% of the loaded span.
    pub fn needs_reload(&self, new_x_min: f64, new_x_max: f64) -> bool {
        if self.series.is_empty() {
            return false;
        }
        let Some((fetch_min, fetch_max)) =
            fetch_range_for_visible(new_x_min, new_x_max, self.data_x_min, self.data_x_max)
        else {
            return false;
        };

        match self.series.first().and_then(|s| s.loaded_range) {
            None => true,
            Some((loaded_min, loaded_max)) => {
                let loaded_span = loaded_max - loaded_min;
                if loaded_span == 0.0 {
                    return true;
                }
                let shift_lo = (loaded_min - fetch_min).abs() / loaded_span;
                let shift_hi = (loaded_max - fetch_max).abs() / loaded_span;
                shift_lo > 0.10 || shift_hi > 0.10
            }
        }
    }

    /// Fetch data for all series in the given visible range + 20% margin.
    pub fn reload_visible_data(
        &mut self,
        db: &DbBackend,
        settings: &AppSettings,
        plot_width_px: Option<f32>,
    ) {
        let Some((fetch_min, fetch_max)) =
            fetch_range_for_visible(self.x_min, self.x_max, self.data_x_min, self.data_x_max)
        else {
            return;
        };

        for sd in &mut self.series {
            fetch_range(db, sd, fetch_min, fetch_max, settings, plot_width_px);
        }
    }

    pub fn reload_if_sampling_changed(
        &mut self,
        db: &DbBackend,
        settings: &AppSettings,
        plot_width_px: f32,
    ) {
        let Some((fetch_min, fetch_max)) = self.series.first().and_then(|s| s.loaded_range) else {
            return;
        };
        let interval = compute_sample_interval(
            fetch_min,
            fetch_max,
            Some(plot_width_px),
            settings.time_granularity_ms,
            settings.adaptive_downsample,
            settings.pointseries_threshold,
        );
        let stale = self.series.iter().any(|s| {
            if s.loaded_range != Some((fetch_min, fetch_max)) {
                return true;
            }
            let old = s.loaded_sample_interval;
            (old - interval).abs() > interval.max(old).max(1.0e-9) * 0.10
        });
        if stale {
            for sd in &mut self.series {
                fetch_range(db, sd, fetch_min, fetch_max, settings, Some(plot_width_px));
            }
        }
    }
}

/// Load data for a series, applying a 20% margin around the visible window.
pub fn load_series_window(
    db: &DbBackend,
    sd: &mut SeriesData,
    x_min: f64,
    x_max: f64,
    settings: &AppSettings,
    plot_width_px: Option<f32>,
) {
    if let Some((fetch_min, fetch_max)) =
        fetch_range_for_visible(x_min, x_max, sd.global_t_min, sd.global_t_max)
    {
        fetch_range(db, sd, fetch_min, fetch_max, settings, plot_width_px);
    }
}

fn fetch_range_for_visible(
    x_min: f64,
    x_max: f64,
    data_x_min: f64,
    data_x_max: f64,
) -> Option<(f64, f64)> {
    if !x_min.is_finite()
        || !x_max.is_finite()
        || !data_x_min.is_finite()
        || !data_x_max.is_finite()
    {
        return None;
    }

    let visible_min = x_min.min(x_max);
    let visible_max = x_min.max(x_max);
    let data_min = data_x_min.min(data_x_max);
    let data_max = data_x_min.max(data_x_max);
    let span = (visible_max - visible_min).abs();
    let margin = span * 0.20;

    let fetch_min = (visible_min - margin).max(data_min);
    let fetch_max = (visible_max + margin).min(data_max);
    (fetch_min <= fetch_max).then_some((fetch_min, fetch_max))
}

/// Fetch a specific range from the DB and store into `sd.points` / `sd.string_points`.
pub fn fetch_range(
    db: &DbBackend,
    sd: &mut SeriesData,
    fetch_min: f64,
    fetch_max: f64,
    settings: &AppSettings,
    plot_width_px: Option<f32>,
) {
    let sample_interval = compute_sample_interval(
        fetch_min,
        fetch_max,
        plot_width_px,
        settings.time_granularity_ms,
        settings.adaptive_downsample,
        settings.pointseries_threshold,
    );
    if sd.is_string_type() {
        sd.string_points =
            db.load_range_strings_sampled(sd.series_id, fetch_min, fetch_max, sample_interval);
    } else if sd.is_boolean_type() {
        sd.points =
            db.load_range_bool_events_sampled(sd.series_id, fetch_min, fetch_max, sample_interval);
    } else {
        let raw = db.load_range_sampled(sd.series_id, fetch_min, fetch_max, sample_interval);
        let step = compute_skip_step(raw.len(), settings.skip_every_nth);
        sd.points = downsample(raw, step);
    }
    sd.loaded_range = Some((fetch_min, fetch_max));
    sd.loaded_sample_interval = sample_interval;
}
