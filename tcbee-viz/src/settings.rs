/// Application-wide settings. Passed as plain references to each tab — no Arc/RwLock needed.
#[derive(Clone)]
pub struct AppSettings {
    pub text_size: f32,
    /// Draw every Nth data point (1 = draw all).
    pub skip_every_nth: usize,
    pub reduce_density_on_zoom: bool,
    /// When reduce_density_on_zoom is active, use this skip factor.
    pub zoom_skip_amount: usize,
    /// When the display range has fewer than this many pixels per point, switch to point series.
    pub pointseries_threshold: f64,
    pub dark_mode: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            text_size: 14.0,
            skip_every_nth: 1,
            reduce_density_on_zoom: false,
            zoom_skip_amount: 5,
            pointseries_threshold: 5.0,
            dark_mode: false,
        }
    }
}
