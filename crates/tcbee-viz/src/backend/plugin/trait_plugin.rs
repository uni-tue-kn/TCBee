use crate::data::series_data::SeriesData;

use super::{
    plugin_dummy::DummyPlugin,
    plugin_tcp_derived::{
        BytesInFlightPlugin, DuplicateAckPlugin, LossEpisodePlugin, RetransmissionPlugin,
        SenderLimitationPlugin, UsableSendWindowPlugin,
    },
    plugin_upper_window::UpperWindowPlugin,
};

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
    BytesInFlight,
    UsableSendWindow,
    DuplicateAck,
    Retransmission,
    SenderLimitation,
    LossEpisode,
}

impl PluginKind {
    pub const ALL: &'static [Self] = &[
        Self::Dummy,
        Self::UpperWindow,
        Self::BytesInFlight,
        Self::UsableSendWindow,
        Self::DuplicateAck,
        Self::Retransmission,
        Self::SenderLimitation,
        Self::LossEpisode,
    ];

    pub fn label(&self) -> &str {
        match self {
            Self::Dummy => "Dummy Plugin",
            Self::UpperWindow => "Upper TCP Window",
            Self::BytesInFlight => "Bytes In Flight",
            Self::UsableSendWindow => "Usable Send Window",
            Self::DuplicateAck => "Duplicate ACK Detector",
            Self::Retransmission => "Retransmission Detector",
            Self::SenderLimitation => "Sender Limitation",
            Self::LossEpisode => "Loss Episode Detector",
        }
    }

    pub fn create(&self) -> Box<dyn Plugin> {
        match self {
            Self::Dummy => Box::new(DummyPlugin::default()),
            Self::UpperWindow => Box::new(UpperWindowPlugin::default()),
            Self::BytesInFlight => Box::new(BytesInFlightPlugin::default()),
            Self::UsableSendWindow => Box::new(UsableSendWindowPlugin::default()),
            Self::DuplicateAck => Box::new(DuplicateAckPlugin::default()),
            Self::Retransmission => Box::new(RetransmissionPlugin::default()),
            Self::SenderLimitation => Box::new(SenderLimitationPlugin::default()),
            Self::LossEpisode => Box::new(LossEpisodePlugin::default()),
        }
    }
}
