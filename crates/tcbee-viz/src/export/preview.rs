//! The export window: the figure as it will be saved, next to its labels and a draft of its
//! style. Edits change only this figure until the user makes the draft style the default.

use std::sync::Arc;

use super::{
    collect, figure::Figure, not_exported, write, ExportPanel, Format, Sources, Status, View,
};
use crate::{backend::db::DbBackend, plot_style::PlotStyle, ui::style_editor};

/// Width on screen of one inch of the figure, in points.
const SCREEN_PER_INCH: f32 = 96.0;
/// Widest preview on screen, in points.
const MAX_WIDTH: f32 = 800.0;
/// Time slices of the previewed data, enough for the widest preview on a HiDPI screen
const PREVIEW_COLUMNS: usize = 1600;

/// The series of each panel in plot order, to tell when the plots changed.
fn series_ids(sources: &Sources, panels: &[ExportPanel]) -> Vec<Vec<(i64, String)>> {
    super::panel_series(sources, panels)
        .into_iter()
        .map(|panel| {
            panel
                .into_iter()
                .map(|(prefix, sd, info)| (info.flow_id, format!("{prefix}{}", sd.name)))
                .collect()
        })
        .collect()
}

pub struct Preview {
    /// The data at preview resolution; saving reads it again at the file's
    figure: Figure,
    /// The series of `figure`, to notice when the tab plots others
    series: Vec<Vec<(i64, String)>>,
    /// The plots of the figure, read again when saving
    panels: Vec<ExportPanel>,
    origin: f64,
    x_range: (f64, f64),
    view: View,
    file_stem: String,
    pub(super) draft: PlotStyle,
    /// The y-axis label and legend labels as the user set them for this figure
    texts: Texts,
    image: FigureImage,
    /// The figure was handed to the settings preview
    remembered: bool,
    status: Status,
}

/// The figure rendered with `style` at `px_per_inch`, as a texture called `name`.
fn texture(
    ctx: &egui::Context,
    name: &str,
    figure: &Figure,
    style: &PlotStyle,
    px_per_inch: f32,
) -> Rendered {
    super::rasterize(figure, style, px_per_inch)
        .map(|img| ctx.load_texture(name, img, egui::TextureOptions::LINEAR))
}

fn last_figure_id() -> egui::Id {
    egui::Id::new("export_last_figure")
}

/// Keeps `figure` as the last one opened for export, for the preview in the settings.
fn remember_figure(ctx: &egui::Context, figure: &Figure) {
    ctx.data_mut(|d| d.insert_temp(last_figure_id(), Arc::new(figure.clone())));
}

/// Texts of one figure that the user can replace: they hold for this export only. One
/// y-axis label and one list of legend labels per panel.
struct Texts {
    y_labels: Vec<String>,
    labels: Vec<Vec<String>>,
}

impl Texts {
    fn of(figure: &Figure) -> Texts {
        Texts {
            y_labels: figure.panels.iter().map(|p| p.y_label.clone()).collect(),
            labels: figure
                .panels
                .iter()
                .map(|p| p.series.iter().map(|f| f.label.clone()).collect())
                .collect(),
        }
    }

    fn apply(&self, figure: &mut Figure) {
        for ((panel, y_label), labels) in figure
            .panels
            .iter_mut()
            .zip(&self.y_labels)
            .zip(&self.labels)
        {
            panel.y_label.clone_from(y_label);
            for (f, label) in panel.series.iter_mut().zip(labels) {
                f.label.clone_from(label);
            }
        }
    }

    /// Text fields for the labels; returns whether any changed.
    fn edit(&mut self, ui: &mut egui::Ui, figure: &Figure) -> bool {
        let mut changed = false;
        let several = figure.panels.len() > 1;
        egui::Grid::new("figure_texts")
            .num_columns(2)
            .spacing([40.0, 8.0])
            .show(ui, |ui| {
                let panels = figure
                    .panels
                    .iter()
                    .zip(&mut self.y_labels)
                    .zip(&mut self.labels);
                for (n, ((panel, y_label), labels)) in panels.enumerate() {
                    ui.label(if several {
                        format!("Plot {}, y-axis label:", n + 1)
                    } else {
                        "Y-axis label:".to_string()
                    });
                    changed |= ui
                        .add(egui::TextEdit::singleline(y_label).hint_text("none"))
                        .changed();
                    ui.end_row();
                    for (i, (label, f)) in labels.iter_mut().zip(&panel.series).enumerate() {
                        ui.label(if i == 0 { "Legend labels:" } else { "" });
                        ui.horizontal(|ui| {
                            if let Some(c) = crate::plot_style::parse_hex(&f.color) {
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(14.0, 3.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().rect_filled(rect, 0.0, c);
                            }
                            changed |= ui.text_edit_singleline(label).changed();
                        });
                        ui.end_row();
                    }
                }
            });
        changed
    }
}

/// A figure rendered for the screen, kept until its figure, style or size changes.
#[derive(Default)]
struct FigureImage {
    /// The style, figure address and pixels per inch of `texture`
    key: Option<(PlotStyle, usize, f32)>,
    texture: Option<Rendered>,
}

impl FigureImage {
    /// Shows `figure` in `style`, at most `max_width` points wide; returns the shown width.
    fn show(
        &mut self,
        ui: &mut egui::Ui,
        name: &str,
        figure: &Figure,
        style: &PlotStyle,
        max_width: f32,
    ) -> f32 {
        let width = (style.width_in * SCREEN_PER_INCH).min(max_width);
        let px_per_inch = width / style.width_in * ui.ctx().pixels_per_point();
        let address = std::ptr::from_ref(figure) as usize;
        let fresh = self
            .key
            .as_ref()
            .is_some_and(|(s, a, px)| s == style && *a == address && *px == px_per_inch);
        if !fresh {
            self.texture = Some(texture(ui.ctx(), name, figure, style, px_per_inch));
            self.key = Some((style.clone(), address, px_per_inch));
        }
        match &self.texture {
            Some(Ok(texture)) => {
                let size = texture.size_vec2() / ui.ctx().pixels_per_point();
                ui.add(egui::Image::new((texture.id(), size)));
            }
            Some(Err(e)) => {
                ui.colored_label(egui::Color32::RED, format!("Preview failed: {e}"));
            }
            None => {}
        }
        width
    }
}

/// The style preview of the settings: the figure last opened for export, else a sample.
#[derive(Default)]
pub struct StylePreview {
    image: FigureImage,
    /// Keeps the shown figure alive, so its address stays its own
    figure: Option<Arc<Figure>>,
}

impl StylePreview {
    pub fn show(&mut self, ui: &mut egui::Ui, style: &PlotStyle) {
        let figure = ui
            .ctx()
            .data(|d| d.get_temp::<Arc<Figure>>(last_figure_id()))
            .or_else(|| self.figure.clone())
            .unwrap_or_else(|| Arc::new(Figure::sample()));
        let max_width = MAX_WIDTH.min(ui.available_width());
        self.image
            .show(ui, "style_preview", &figure, style, max_width);
        self.figure = Some(figure);
    }
}

/// A rendered figure, or why rendering failed.
type Rendered = Result<egui::TextureHandle, String>;

/// What the window asks of its tab.
pub enum Action {
    None,
    Close,
    /// A figure was saved, or saving failed
    Saved(Result<String, String>),
}

impl Preview {
    pub fn new(
        db: &DbBackend,
        (sources, panels): (&Sources, &[ExportPanel]),
        origin: f64,
        (x_range, view): ((f64, f64), View),
        style: &PlotStyle,
        file_stem: &str,
    ) -> Preview {
        let figure = collect(
            db,
            (sources, panels),
            origin,
            (x_range, view),
            PREVIEW_COLUMNS,
        );
        Preview {
            texts: Texts::of(&figure),
            figure,
            series: series_ids(sources, panels),
            panels: panels.to_vec(),
            origin,
            x_range,
            view,
            file_stem: file_stem.to_string(),
            draft: style.clone(),
            image: FigureImage::default(),
            remembered: false,
            status: None,
        }
    }

    /// Whether `panels` of `sources` still plot the series of the figure. A plot zoomed in y
    /// keeps the figure as it was opened.
    pub fn shows(&self, sources: &Sources, panels: &[ExportPanel]) -> bool {
        self.series == series_ids(sources, panels)
    }

    /// The window; `sources` are the tab's plotted flows, read again when saving.
    pub fn show(&mut self, ctx: &egui::Context, db: &DbBackend, sources: &Sources) -> Action {
        let mut open = true;
        let mut action = Action::None;
        egui::Window::new("Export figure")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_pos(ctx.screen_rect().center() - egui::vec2(500.0, 250.0))
            .show(ctx, |ui| {
                ui.horizontal_top(|ui| {
                    ui.vertical(|ui| self.show_image(ui, sources));
                    ui.separator();
                    ui.vertical(|ui| {
                        if self.texts.edit(ui, &self.figure) {
                            self.texts.apply(&mut self.figure);
                            self.image = FigureImage::default();
                        }
                        ui.separator();
                        style_editor::show(ui, &mut self.draft);
                        ui.separator();
                        action = self.buttons(ui, db, sources);
                    });
                });
            });
        if open {
            action
        } else {
            Action::Close
        }
    }

    fn show_image(&mut self, ui: &mut egui::Ui, sources: &Sources) {
        if !self.remembered {
            remember_figure(ui.ctx(), &self.figure);
            self.remembered = true;
        }
        let width = self
            .image
            .show(ui, "export_preview", &self.figure, &self.draft, MAX_WIDTH);
        ui.label(
            egui::RichText::new(format!(
                "{:.1} × {:.1} in, shown at {:.0} %",
                self.draft.width_in,
                self.draft.height_in * self.figure.panels.len().max(1) as f32,
                width / (self.draft.width_in * SCREEN_PER_INCH) * 100.0
            ))
            .small(),
        );
        let skipped = not_exported(sources);
        if !skipped.is_empty() {
            ui.label(
                egui::RichText::new(format!("Not in the figure: {}", skipped.join(", "))).small(),
            );
        }
    }

    fn buttons(&mut self, ui: &mut egui::Ui, db: &DbBackend, sources: &Sources) -> Action {
        let mut action = Action::None;
        ui.horizontal(|ui| {
            if ui.button("Save figure…").clicked() {
                if let Some(result) = self.save(db, sources) {
                    self.status = Some(result.clone());
                    action = Action::Saved(result);
                }
            }
            if ui
                .button("Use as default style")
                .on_hover_text("Keep this style for later exports, in Settings → Figure export")
                .clicked()
            {
                self.status = Some(
                    super::save_default_style(ui.ctx(), &self.draft)
                        .map(|path| format!("the style to {path}")),
                );
            }
        });
        match &self.status {
            Some(Ok(msg)) => {
                ui.label(egui::RichText::new(format!("Saved {msg}")).small());
            }
            Some(Err(e)) => {
                ui.colored_label(egui::Color32::RED, e);
            }
            None => {}
        }
        action
    }

    /// Asks where to save and writes the figure at the file's resolution; `None` if cancelled.
    fn save(&self, db: &DbBackend, sources: &Sources) -> Status {
        let path = rfd::FileDialog::new()
            .add_filter("PDF", &["pdf"])
            .add_filter("PNG", &["png"])
            .set_file_name(format!("{}.pdf", self.file_stem))
            .save_file()?;
        let path = if path.extension().is_none() {
            path.with_extension("pdf")
        } else {
            path
        };
        let Some(format) = Format::of(&path) else {
            return Some(Err("the file name must end in .pdf or .png".into()));
        };
        let mut fig = collect(
            db,
            (sources, &self.panels),
            self.origin,
            (self.x_range, self.view),
            format.columns(&self.draft),
        );
        self.texts.apply(&mut fig);
        Some(write(&fig, &self.draft, &path).map(|()| path.display().to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts_replace_the_y_label_and_legend_labels() {
        let mut figure = Figure::sample();
        let mut texts = Texts::of(&figure);
        assert_eq!(texts.y_labels, vec!["snd_cwnd"]);
        texts.y_labels[0] = "Cwnd (segments)".into();
        texts.labels[0][1] = "CUBIC".into();
        texts.apply(&mut figure);
        let panel = &figure.panels[0];
        assert_eq!(panel.y_label, "Cwnd (segments)");
        assert_eq!(panel.series[0].label, "flow 1");
        assert_eq!(panel.series[1].label, "CUBIC");
    }
}
