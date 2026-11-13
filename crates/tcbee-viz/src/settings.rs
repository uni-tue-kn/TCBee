/// Application-wide settings. Passed as plain references to each tab — no Arc/RwLock needed.
#[derive(Clone)]
pub struct AppSettings {
    pub text_size: f32,
    /// Draw every Nth data point (1 = draw all).
    pub skip_every_nth: usize,
    /// Keep at most one point per this many milliseconds (0 = no fixed time granularity).
    pub time_granularity_ms: f64,
    /// Derive a minimum sample interval from the current plot width.
    pub adaptive_downsample: bool,
    /// Target minimum horizontal spacing between rendered points.
    pub pointseries_threshold: f64,
    pub dark_mode: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            text_size: 14.0,
            skip_every_nth: 1,
            time_granularity_ms: 0.0,
            adaptive_downsample: true,
            pointseries_threshold: 2.0,
            dark_mode: false,
        }
    }
}
