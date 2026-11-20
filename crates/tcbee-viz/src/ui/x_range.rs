//! The X range of the flow plots in seconds since the axis origin, as the axis shows it.

use egui::{RichText, Ui};

use crate::ui::theme;

const NS_PER_S: f64 = 1e9;

/// The times in ns the editor works with: the axis origin, the data and the visible window
pub struct Bounds {
    pub origin: f64,
    pub data: (f64, f64),
    pub visible: (f64, f64),
}

/// Start, end and length of the X range in seconds since the axis origin, with presets. It
/// follows the visible window of the plot except while the user edits it.
#[derive(Default)]
pub struct XRangeEditor {
    start: f64,
    end: f64,
    /// A field had focus or was dragged in the last frame
    editing: bool,
}

impl XRangeEditor {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Show the editor, disabled without `bounds`. Returns the range in ns to show when the
    /// user finished an edit or picked a preset.
    pub fn show(
        &mut self,
        ui: &mut Ui,
        id_salt: &str,
        bounds: Option<Bounds>,
    ) -> Option<(f64, f64)> {
        let mut apply = None;
        egui::CollapsingHeader::new("X range")
            .id_salt(id_salt)
            .default_open(true)
            .show(ui, |ui| match bounds {
                Some(bounds) => apply = self.show_fields(ui, id_salt, &bounds),
                None => {
                    ui.label(
                        RichText::new("Select a flow first.")
                            .small()
                            .color(theme::muted_text(ui.visuals().dark_mode)),
                    );
                }
            });
        apply
    }

    fn show_fields(&mut self, ui: &mut Ui, id_salt: &str, bounds: &Bounds) -> Option<(f64, f64)> {
        let dark_mode = ui.visuals().dark_mode;
        let span = ns_to_s(bounds.data.1, bounds.origin).max(0.0);
        let visible = (
            ns_to_s(bounds.visible.0, bounds.origin),
            ns_to_s(bounds.visible.1, bounds.origin),
        );
        // A view panned off the data keeps the last range
        if let Some(range) = clamp_range(visible.0, visible.1, span).filter(|_| !self.editing) {
            (self.start, self.end) = range;
        }

        let mut length = self.end - self.start;
        let speed = (span * 0.001).max(1e-6);
        let mut finished = false;
        let mut editing = false;
        egui::Grid::new((id_salt, "fields"))
            .num_columns(3)
            .spacing([8.0, 2.0])
            .show(ui, |ui| {
                for label in ["Start", "End", "Length"] {
                    ui.label(
                        RichText::new(label)
                            .small()
                            .color(theme::muted_text(dark_mode)),
                    );
                }
                ui.end_row();
                let start = ui.add(seconds_field(&mut self.start, span, speed));
                let end = ui.add(seconds_field(&mut self.end, span, speed));
                let len = ui.add(seconds_field(&mut length, span, speed));
                if len.changed() {
                    (self.start, self.end) = with_length(self.start, length, span);
                }
                for r in [&start, &end, &len] {
                    editing |= r.has_focus() || r.dragged();
                    finished |= r.lost_focus() || r.drag_stopped();
                }
                ui.end_row();
            });
        self.editing = editing;

        let mut apply = None;
        let valid = clamp_range(self.start, self.end, span);
        if valid.is_none() {
            ui.colored_label(ui.visuals().error_fg_color, "Start must be before End");
        } else if finished {
            apply = valid;
        }

        ui.horizontal_wrapped(|ui| {
            for (label, preset) in [
                ("Full", Preset::Full),
                ("First 10 s", Preset::First(10.0)),
                ("Last 10 s", Preset::Last(10.0)),
            ] {
                // Data without a duration has no range to show
                let range = preset_range(preset, span);
                let button = ui.add_enabled(span > 0.0, egui::Button::new(label).small());
                if button.clicked() {
                    (self.start, self.end) = range;
                    self.editing = false;
                    apply = Some(range);
                }
            }
        });

        apply.map(|(start, end)| (s_to_ns(start, bounds.origin), s_to_ns(end, bounds.origin)))
    }
}

/// A quick choice of X range
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Preset {
    Full,
    /// The first seconds of the data
    First(f64),
    /// The last seconds of the data
    Last(f64),
}

/// A field for seconds within the data
fn seconds_field(value: &mut f64, span: f64, speed: f64) -> egui::DragValue<'_> {
    egui::DragValue::new(value)
        .range(0.0..=span)
        .speed(speed)
        // Sub-ms windows are common, so short ranges get up to µs
        .min_decimals(3)
        .max_decimals(6)
        .suffix(" s")
}

/// Seconds since `origin_ns` of the time `ns`
pub fn ns_to_s(ns: f64, origin_ns: f64) -> f64 {
    (ns - origin_ns) / NS_PER_S
}

/// The time `s` seconds after `origin_ns`
pub fn s_to_ns(s: f64, origin_ns: f64) -> f64 {
    origin_ns + s * NS_PER_S
}

/// The range from `start` to `end` in seconds, clamped to the data from 0 to `span`, None if it
/// is empty
pub fn clamp_range(start: f64, end: f64, span: f64) -> Option<(f64, f64)> {
    let (start, end) = (start.clamp(0.0, span), end.clamp(0.0, span));
    (start < end).then_some((start, end))
}

/// The range of `preset` in data `span` seconds long
pub fn preset_range(preset: Preset, span: f64) -> (f64, f64) {
    match preset {
        Preset::Full => (0.0, span),
        Preset::First(s) => (0.0, s.min(span)),
        Preset::Last(s) => ((span - s).max(0.0), span),
    }
}

/// The range that starts at `start` and lasts `length` seconds, ending at the data's end at
/// the latest
pub fn with_length(start: f64, length: f64, span: f64) -> (f64, f64) {
    (start, (start + length.max(0.0)).min(span))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_round_trip_through_ns() {
        let origin = 1_234_567_890_123_456.0;
        assert_eq!(ns_to_s(origin + 2.5e9, origin), 2.5);
        assert!(
            (s_to_ns(ns_to_s(origin + 1_000.0, origin), origin) - (origin + 1_000.0)).abs() < 1.0
        );
    }

    #[test]
    fn ranges_stay_inside_the_data() {
        assert_eq!(clamp_range(-1.0, 3.0, 10.0), Some((0.0, 3.0)));
        assert_eq!(clamp_range(2.0, 20.0, 10.0), Some((2.0, 10.0)));
        assert_eq!(clamp_range(3.0, 3.0, 10.0), None);
        assert_eq!(clamp_range(5.0, 2.0, 10.0), None);

        assert_eq!(preset_range(Preset::Full, 30.0), (0.0, 30.0));
        assert_eq!(preset_range(Preset::First(10.0), 30.0), (0.0, 10.0));
        assert_eq!(preset_range(Preset::Last(10.0), 30.0), (20.0, 30.0));
        // Shorter data than the preset
        assert_eq!(preset_range(Preset::First(10.0), 4.0), (0.0, 4.0));
        assert_eq!(preset_range(Preset::Last(10.0), 4.0), (0.0, 4.0));

        assert_eq!(with_length(2.0, 3.0, 10.0), (2.0, 5.0));
        assert_eq!(with_length(8.0, 5.0, 10.0), (8.0, 10.0));
    }
}
