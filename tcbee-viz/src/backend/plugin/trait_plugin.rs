use crate::data::series_data::SeriesData;

use super::{plugin_dummy::DummyPlugin, plugin_upper_window::UpperWindowPlugin};

pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    /// Names of the time series the plugin needs as inputs.
    fn required_series(&self) -> Vec<String>;
    /// Compute new series from the provided input series.
    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String>;
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PluginKind {
    Dummy,
    UpperWindow,
}

impl PluginKind {
    pub const ALL: &'static [Self] = &[Self::Dummy, Self::UpperWindow];

    pub fn label(&self) -> &str {
        match self {
            Self::Dummy => "Dummy Plugin",
            Self::UpperWindow => "Upper TCP Window",
        }
    }

    pub fn create(&self) -> Box<dyn Plugin> {
        match self {
            Self::Dummy => Box::new(DummyPlugin::default()),
            Self::UpperWindow => Box::new(UpperWindowPlugin::default()),
        }
    }
}
