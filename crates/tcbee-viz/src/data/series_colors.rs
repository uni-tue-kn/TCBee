//! Colours the user picked for series, in place of the automatic ones. They follow the
//! series to another flow like the plot groups and hold for the session.

use std::collections::HashMap;

use egui::Color32;

use crate::data::{
    plot_groups::{FlowSlot, SeriesKey},
    series_data::SeriesData,
};

#[derive(Clone, Debug, Default)]
pub struct SeriesColors(HashMap<SeriesKey, Color32>);

impl SeriesColors {
    pub fn set(&mut self, key: SeriesKey, color: Color32) {
        self.0.insert(key, color);
    }

    /// Gives the series of `slot` the colours picked for them.
    pub fn apply(&self, slot: FlowSlot, series: &mut [SeriesData]) {
        for sd in series {
            if let Some(color) = self.0.get(&SeriesKey::of(slot, sd)) {
                sd.color = *color;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picked_colors_replace_the_automatic_ones() {
        let sd = |name: &str| {
            SeriesData::new(
                name.into(),
                1,
                ts_storage::ValueKind::Float,
                0.0,
                1.0,
                0.0,
                1.0,
                Color32::WHITE,
            )
        };
        let mut series = vec![sd("cwnd"), sd("rtt")];
        let mut colors = SeriesColors::default();
        colors.set(SeriesKey::of(FlowSlot::A, &series[0]), Color32::RED);
        colors.apply(FlowSlot::B, &mut series);
        assert_eq!(series[0].color, Color32::WHITE);
        colors.apply(FlowSlot::A, &mut series);
        assert_eq!(
            (series[0].color, series[1].color),
            (Color32::RED, Color32::WHITE)
        );
    }
}
