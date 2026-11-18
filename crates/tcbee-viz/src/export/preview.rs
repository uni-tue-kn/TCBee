//! The export window: the figure as it will be saved, next to a draft of its style. Edits
//! change only the draft until the user saves the figure or makes the draft the default.

use super::{collect, figure::Figure, not_exported, write, Format, Sources, Status, View};
use crate::{backend::db::DbBackend, plot_style::PlotStyle, ui::style_editor};

/// Width on screen of one inch of the figure, in points.
const SCREEN_PER_INCH: f32 = 96.0;
/// Widest preview on screen, in points.
const MAX_WIDTH: f32 = 800.0;

pub struct Preview {
    /// The data at preview resolution; saving reads it again at the file's
    figure: Figure,
    origin: f64,
    x_range: (f64, f64),
    view: View,
    file_stem: String,
    pub(super) draft: PlotStyle,
    /// The rendered figure and the style and scale it was rendered with
    image: Option<(PlotStyle, f32, Result<egui::TextureHandle, String>)>,
    status: Status,
}

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
        sources: &Sources,
        origin: f64,
        (x_range, view): ((f64, f64), View),
        style: &PlotStyle,
        file_stem: &str,
    ) -> Preview {
        let columns = (MAX_WIDTH * 2.0) as usize;
        Preview {
            figure: collect(db, sources, origin, (x_range, view), style, columns),
            origin,
            x_range,
            view,
            file_stem: file_stem.to_string(),
            draft: style.clone(),
            image: None,
            status: None,
        }
    }

    /// The figure with the colours of the draft, as it will be saved.
    fn styled_figure(&self, db: &DbBackend, sources: &Sources, columns: usize) -> Figure {
        collect(
            db,
            sources,
            self.origin,
            (self.x_range, self.view),
            &self.draft,
            columns,
        )
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
                    ui.vertical(|ui| self.show_image(ui, db, sources));
                    ui.separator();
                    ui.vertical(|ui| {
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

    fn show_image(&mut self, ui: &mut egui::Ui, db: &DbBackend, sources: &Sources) {
        let width = (self.draft.width_in * SCREEN_PER_INCH).min(MAX_WIDTH);
        let scale = width / (self.draft.width_in * 72.0) * ui.ctx().pixels_per_point();
        let stale = self
            .image
            .as_ref()
            .is_none_or(|(style, s, _)| *style != self.draft || *s != scale);
        if stale {
            // Colours are picked while collecting, so a palette switch reads the data again
            if self.image.as_ref().is_some_and(|(style, _, _)| {
                style.use_palette != self.draft.use_palette || style.palette != self.draft.palette
            }) {
                self.figure = self.styled_figure(db, sources, (MAX_WIDTH * 2.0) as usize);
            }
            let texture = super::rasterize(&self.figure, &self.draft, scale).map(|img| {
                ui.ctx()
                    .load_texture("export_preview", img, egui::TextureOptions::LINEAR)
            });
            self.image = Some((self.draft.clone(), scale, texture));
        }
        match &self.image {
            Some((_, _, Ok(texture))) => {
                let size = texture.size_vec2() / ui.ctx().pixels_per_point();
                ui.add(egui::Image::new((texture.id(), size)));
                ui.label(
                    egui::RichText::new(format!(
                        "{:.1} × {:.1} in, shown at {:.0} %",
                        self.draft.width_in,
                        self.draft.height_in,
                        width / (self.draft.width_in * SCREEN_PER_INCH) * 100.0
                    ))
                    .small(),
                );
            }
            Some((_, _, Err(e))) => {
                ui.colored_label(egui::Color32::RED, format!("Preview failed: {e}"));
            }
            None => {}
        }
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
        let fig = self.styled_figure(db, sources, format.columns(&self.draft));
        Some(write(&fig, &self.draft, &path).map(|()| path.display().to_string()))
    }
}
