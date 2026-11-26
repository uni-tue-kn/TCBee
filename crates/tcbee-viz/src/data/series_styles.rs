//! Colours and line widths the user picked for series, in place of the automatic ones. They
//! follow the series to another flow like the plot groups and hold for the session.

use std::collections::HashMap;

use egui::Color32;

use crate::data::{
    plot_groups::{FlowSlot, SeriesKey},
    series_data::{SeriesData, DEFAULT_LINE_WIDTH},
};

/// Range of the line width a user can pick (px).
pub const LINE_WIDTH_RANGE: std::ops::RangeInclusive<f32> = 0.5..=4.0;

#[derive(Clone, Debug, Default)]
pub struct SeriesStyles {
    colors: HashMap<SeriesKey, Color32>,
    line_widths: HashMap<SeriesKey, f32>,
}

impl SeriesStyles {
    pub fn set_color(&mut self, key: SeriesKey, color: Color32) {
        self.colors.insert(key, color);
    }

    pub fn set_line_width(&mut self, key: SeriesKey, width: f32) {
        let width = width.clamp(*LINE_WIDTH_RANGE.start(), *LINE_WIDTH_RANGE.end());
        self.line_widths.insert(key, width);
    }

    /// The line width picked for `key`, or the default one.
    pub fn line_width(&self, key: &SeriesKey) -> f32 {
        self.line_widths
            .get(key)
            .copied()
            .unwrap_or(DEFAULT_LINE_WIDTH)
    }

    /// Gives the series of `slot` the colours and line widths picked for them.
    pub fn apply(&self, slot: FlowSlot, series: &mut [SeriesData]) {
        for sd in series {
            let key = SeriesKey::of(slot, sd);
            if let Some(color) = self.colors.get(&key) {
                sd.color = *color;
            }
            sd.line_width = self.line_width(&key);
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
        let mut styles = SeriesStyles::default();
        styles.set_color(SeriesKey::of(FlowSlot::A, &series[0]), Color32::RED);
        styles.apply(FlowSlot::B, &mut series);
        assert_eq!(series[0].color, Color32::WHITE);
        styles.apply(FlowSlot::A, &mut series);
        assert_eq!(
            (series[0].color, series[1].color),
            (Color32::RED, Color32::WHITE)
        );
    }

    #[test]
    fn picked_line_widths_are_clamped_and_follow_the_slot() {
        let mut series = vec![SeriesData::new(
            "cwnd".into(),
            1,
            ts_storage::ValueKind::Float,
            0.0,
            1.0,
            0.0,
            1.0,
            Color32::WHITE,
        )];
        let key = SeriesKey::of(FlowSlot::A, &series[0]);
        let mut styles = SeriesStyles::default();
        styles.set_line_width(key.clone(), 10.0);
        assert_eq!(styles.line_width(&key), *LINE_WIDTH_RANGE.end());
        styles.apply(FlowSlot::B, &mut series);
        assert_eq!(series[0].line_width, DEFAULT_LINE_WIDTH);
        styles.apply(FlowSlot::A, &mut series);
        assert_eq!(series[0].line_width, *LINE_WIDTH_RANGE.end());
    }
}
