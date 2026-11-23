use ts_storage::{Gaps, SeriesInfo, ValueKind};

use crate::{
    backend::db::{flow_x_bounds, format_flow, DbBackend},
    data::{
        preprocessing::{
            bucket_min_max, compute_sample_interval, compute_skip_step, downsample, expand_steps,
            unused_color, MAX_RENDER_POINTS,
        },
        series_data::SeriesData,
    },
    settings::AppSettings,
};

/// Per-tab state for a single flow's plot: selected series, loaded data, and zoom bookkeeping.
pub struct PlotState {
    pub flow_id: Option<i64>,
    pub selected_series_ids: Vec<i64>,
    pub series: Vec<SeriesData>,
    /// Catalog rows (with point counts) of the currently selected flow.
    pub available_series: Vec<SeriesInfo>,
    /// Current visible X bounds (mirrors egui_plot's view).
    pub x_min: f64,
    pub x_max: f64,
    /// Full extent of the flow — used for reset.
    pub data_x_min: f64,
    pub data_x_max: f64,
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
            self.flow_label = format_flow(flow);
            // Counts and bounds come from the catalog rows.
            self.available_series = db.list_series_for_flow(flow_id);
        }
        if let Some((t_min, t_max)) = flow_x_bounds(&self.available_series) {
            self.data_x_min = t_min;
            self.data_x_max = t_max;
            self.x_min = t_min;
            self.x_max = t_max;
        }
    }

    /// Toggle a series on/off. Assigns a color when added.
    pub fn toggle_series(&mut self, db: &DbBackend, series_id: i64, settings: &AppSettings) {
        if self.selected_series_ids.contains(&series_id) {
            self.deselect_series(&[series_id]);
        } else {
            self.select_series(db, &[series_id], settings);
        }
    }

    /// Add the series of `ids` that are not selected yet, each with the next palette color.
    pub fn select_series(&mut self, db: &DbBackend, ids: &[i64], settings: &AppSettings) {
        for &series_id in ids {
            if self.selected_series_ids.contains(&series_id) {
                continue;
            }
            self.selected_series_ids.push(series_id);
            // A colour no shown series has: counting would reuse one after a deselect
            let used: Vec<egui::Color32> = self.series.iter().map(|s| s.color).collect();
            let color = unused_color(&used);

            if let Some(info) = self.available_series.iter().find(|s| s.id == series_id) {
                let mut sd = SeriesData::from_info(info, self.data_x_min, self.data_x_max, color);
                let x_min = self.x_min;
                let x_max = self.x_max;
                load_series_window(db, &mut sd, x_min, x_max, settings, None);
                self.series.push(sd);
            }
        }
    }

    /// Remove the series of `ids` from the selection.
    pub fn deselect_series(&mut self, ids: &[i64]) {
        self.selected_series_ids.retain(|id| !ids.contains(id));
        self.series.retain(|s| !ids.contains(&s.series_id));
    }

    /// Reads the gaps of the series that have none yet. Plugin outputs have no hook_seq.
    pub fn load_gaps(&mut self, db: &DbBackend) {
        for sd in self.series.iter_mut().filter(|s| s.gaps.is_none()) {
            sd.gaps = Some(match &sd.info {
                Some(info) => db.seq_gaps(info),
                None => Gaps::Unavailable,
            });
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

        // Every series counts: a plot may show none of the series that happen to come first
        self.series.iter().any(|s| match s.loaded_range {
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
        })
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
        let Some((fetch_min, fetch_max)) = self.series.iter().find_map(|s| s.loaded_range) else {
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
    let Some(info) = &sd.info else { return };
    sd.step = db.is_step_series(info);
    if sd.step && sd.val_type != ValueKind::String {
        // Every change matters: no interval sampling or skipping, at most a bucketing that
        // keeps each bucket's levels, and the value at the window start carried in
        // The value carried in from before the window is kept out of the bucketing, so
        // the buckets cover the window only
        let mut points = db.load_range_steps(info, fetch_min, fetch_max);
        let carried = (points.first().is_some_and(|p| p.0 < fetch_min)).then(|| points.remove(0));
        let mut changes = bucket_min_max(points, MAX_RENDER_POINTS / 2);
        if let Some(p) = carried {
            changes.insert(0, p);
        }
        let end = db.flow_end(info.flow_id).map(|t| t.min(fetch_max));
        sd.points = expand_steps(&changes, end);
    } else if sd.val_type == ValueKind::String {
        sd.string_points =
            db.load_range_strings_sampled(info, fetch_min, fetch_max, sample_interval);
    } else if sd.val_type == ValueKind::Bool {
        sd.points = db.load_range_bool_events_sampled(info, fetch_min, fetch_max, sample_interval);
    } else {
        let raw = db.load_range_sampled(info, fetch_min, fetch_max, sample_interval);
        let step = compute_skip_step(raw.len(), settings.skip_every_nth);
        sd.points = downsample(raw, step);
    }
    sd.loaded_range = Some((fetch_min, fetch_max));
    sd.loaded_sample_interval = sample_interval;
}

#[cfg(test)]
mod tests {
    use ts_storage::{ColType, Dir, SeriesInfo, SeriesKind};

    use super::*;

    fn info(id: i64) -> SeriesInfo {
        SeriesInfo {
            id,
            flow_id: 1,
            kind: SeriesKind::Raw,
            source: "sock".to_string(),
            dir: Dir::Send,
            name: format!("m{id}"),
            value_type: ColType::U32,
            tbl: Some("ev_sock".to_string()),
            col: Some(format!("m{id}")),
            n: 10,
            t_min: Some(0),
            t_max: Some(9),
            v_min: Some(0.0),
            v_max: Some(1.0),
        }
    }

    fn state() -> PlotState {
        PlotState {
            flow_id: Some(1),
            available_series: (1..=4).map(info).collect(),
            ..PlotState::default()
        }
    }

    fn selected(state: &PlotState) -> (Vec<i64>, Vec<i64>) {
        let loaded = state.series.iter().map(|s| s.series_id).collect();
        (state.selected_series_ids.clone(), loaded)
    }

    #[test]
    fn selecting_many_keeps_the_selected_ones() {
        let (db, settings) = (DbBackend::default(), AppSettings::default());
        let mut state = state();
        state.toggle_series(&db, 2, &settings);
        // Unlike toggling, selecting a selected series keeps it
        state.select_series(&db, &[1, 2, 3], &settings);
        assert_eq!(selected(&state), (vec![2, 1, 3], vec![2, 1, 3]));
        state.deselect_series(&[2, 4]);
        assert_eq!(selected(&state), (vec![1, 3], vec![1, 3]));
        state.toggle_series(&db, 1, &settings);
        assert_eq!(selected(&state), (vec![3], vec![3]));
    }

    #[test]
    fn new_series_get_a_color_not_shown() {
        let (db, settings) = (DbBackend::default(), AppSettings::default());
        let mut state = state();
        state.select_series(&db, &[1, 2, 3], &settings);
        state.deselect_series(&[1]);
        state.select_series(&db, &[4], &settings);
        let colors: Vec<_> = state.series.iter().map(|s| s.color).collect();
        assert!((0..colors.len()).all(|i| !colors[i + 1..].contains(&colors[i])));
    }

    fn loaded(state: &mut PlotState, ranges: &[Option<(f64, f64)>]) {
        state.data_x_max = 100.0;
        state.series = ranges
            .iter()
            .zip(1..)
            .map(|(&range, id)| {
                let mut sd = SeriesData::from_info(&info(id), 0.0, 100.0, egui::Color32::WHITE);
                sd.loaded_range = range;
                sd
            })
            .collect();
    }

    #[test]
    fn reload_looks_at_every_series() {
        let mut state = state();
        // Visible 40..60 fetches 36..64
        loaded(&mut state, &[Some((36.0, 64.0)), Some((36.0, 64.0))]);
        assert!(!state.needs_reload(40.0, 60.0));
        loaded(&mut state, &[Some((36.0, 64.0)), Some((0.0, 100.0))]);
        assert!(state.needs_reload(40.0, 60.0));
        loaded(&mut state, &[Some((36.0, 64.0)), None]);
        assert!(state.needs_reload(40.0, 60.0));
    }
}
