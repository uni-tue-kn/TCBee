//! Export of the current plot as a styled PDF or PNG figure.

pub mod figure;

use std::path::Path;
use std::sync::{Arc, OnceLock};

use resvg::{tiny_skia, usvg};
use ts_storage::Gaps;

use crate::{
    backend::db::DbBackend,
    data::{plot_state::PlotState, preprocessing::expand_steps},
    plot_style::PlotStyle,
};
use figure::{Figure, FigureSeries};

/// Columns per inch of a PDF figure, for thinning its data.
const PDF_COLUMNS_PER_INCH: f32 = 300.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Pdf,
    Png,
}

impl Format {
    /// The format of a file name's extension.
    pub fn of(path: &Path) -> Option<Format> {
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "pdf" => Some(Format::Pdf),
            "png" => Some(Format::Png),
            _ => None,
        }
    }

    /// Time slices to keep the extremes of, so the data matches the figure's resolution.
    pub fn columns(self, style: &PlotStyle) -> usize {
        let per_inch = match self {
            Format::Pdf => PDF_COLUMNS_PER_INCH,
            Format::Png => style.png_dpi as f32,
        };
        (style.width_in * per_inch).ceil().max(1.0) as usize
    }
}

/// The plotted flows of a tab: each with the prefix of its legend labels.
pub type Sources<'a> = [(&'a PlotState, &'a str)];

/// The figure of the numeric series of `sources` in the time range `x_range` (ns), read from
/// the database at the figure's resolution. Times become seconds since `origin` (ns), as on
/// the plot axis. `y_range` `None` fits the data.
pub fn collect(
    db: &DbBackend,
    sources: &Sources,
    origin: f64,
    x_range: (f64, f64),
    y_range: Option<(f64, f64)>,
    columns: usize,
) -> Figure {
    let (t0, t1) = x_range;
    let secs = |t: f64| (t - origin) / 1e9;
    let mut series = Vec::new();
    let mut names = Vec::new();
    for (state, prefix) in sources {
        for sd in state.series.iter().filter(|s| !s.is_string_type()) {
            let Some(info) = &sd.info else { continue };
            let points = if sd.step {
                let end = db.flow_end(info.flow_id).map(|t| t.min(t1));
                expand_steps(&db.load_range_steps(info, t0, t1), end)
            } else {
                db.load_range_envelope(info, t0, t1, columns)
            };
            let gaps = match &sd.gaps {
                Some(Gaps::Known(gaps)) => gaps
                    .iter()
                    .filter(|g| g.end_ns as f64 >= t0 && g.start_ns as f64 <= t1)
                    .map(|g| (secs(g.start_ns as f64), secs(g.end_ns as f64)))
                    .collect(),
                _ => Vec::new(),
            };
            names.push(info.name.clone());
            series.push(FigureSeries {
                label: format!("{prefix}{}", sd.name),
                points: points.into_iter().map(|(t, v)| (secs(t), v)).collect(),
                gaps,
                step: sd.step,
            });
        }
    }
    let y_range = y_range.unwrap_or_else(|| fit(&series));
    names.dedup();
    Figure {
        x_label: "Time (s)".into(),
        // One metric names the axis; several are told apart by the legend.
        y_label: if names.len() == 1 {
            names.remove(0)
        } else {
            String::new()
        },
        x_range: (secs(t0), secs(t1)),
        y_range,
        series,
    }
}

/// The value range of all points with 5 % padding.
fn fit(series: &[FigureSeries]) -> (f64, f64) {
    let (lo, hi) = series
        .iter()
        .flat_map(|s| &s.points)
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), p| {
            (lo.min(p.1), hi.max(p.1))
        });
    if !lo.is_finite() || !hi.is_finite() {
        return (0.0, 1.0);
    }
    let pad = ((hi - lo) * 0.05).max(hi.abs() * 0.05).max(1e-9);
    (lo - pad, hi + pad)
}

/// System fonts, loaded on the first export, with a sans-serif family that exists.
fn fonts() -> Result<Arc<usvg::fontdb::Database>, String> {
    static FONTS: OnceLock<Arc<usvg::fontdb::Database>> = OnceLock::new();
    let db = FONTS.get_or_init(|| {
        let mut db = usvg::fontdb::Database::new();
        db.load_system_fonts();
        let has = |name: &str| {
            db.faces()
                .any(|f| f.families.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)))
        };
        if let Some(sans) = [
            "DejaVu Sans",
            "Liberation Sans",
            "Noto Sans",
            "Arial",
            "Helvetica",
        ]
        .into_iter()
        .find(|n| has(n))
        {
            db.set_sans_serif_family(sans);
        }
        Arc::new(db)
    });
    if db.is_empty() {
        return Err("no fonts found on this system".into());
    }
    Ok(db.clone())
}

/// Renders `fig` with `style` to `path`, as PDF or PNG by its extension.
pub fn write(fig: &Figure, style: &PlotStyle, path: &Path) -> Result<(), String> {
    let format = Format::of(path).ok_or("the file name must end in .pdf or .png")?;
    let svg = figure::svg(fig, style);
    let options = usvg::Options {
        fontdb: fonts()?,
        ..usvg::Options::default()
    };
    let tree = usvg::Tree::from_str(&svg, &options).map_err(|e| e.to_string())?;
    let bytes = match format {
        Format::Pdf => svg2pdf::to_pdf(
            &tree,
            svg2pdf::ConversionOptions::default(),
            svg2pdf::PageOptions::default(),
        )
        .map_err(|e| e.to_string())?,
        Format::Png => {
            // The SVG is sized in points
            let scale = style.png_dpi as f32 / 72.0;
            let size = tree
                .size()
                .to_int_size()
                .scale_by(scale)
                .ok_or("figure too small")?;
            let mut pixmap =
                tiny_skia::Pixmap::new(size.width(), size.height()).ok_or("figure too large")?;
            resvg::render(
                &tree,
                tiny_skia::Transform::from_scale(scale, scale),
                &mut pixmap.as_mut(),
            );
            pixmap.encode_png().map_err(|e| e.to_string())?
        }
    };
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// A file name for a figure of `flow_id` and `metrics`: `flow<id>_<metric>[_<metric>].pdf`.
pub fn default_file_name(flow_id: Option<i64>, metrics: &[&str]) -> String {
    let mut name = flow_id.map_or("flows".to_string(), |id| format!("flow{id}"));
    for m in metrics.iter().take(3) {
        name.push('_');
        name.extend(m.chars().map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        }));
    }
    name + ".pdf"
}

/// The visible part of a plot: x range (ns) and, for a single plot, its y range.
#[derive(Clone, Copy, Default)]
pub struct View {
    pub x: Option<(f64, f64)>,
    pub y: Option<(f64, f64)>,
}

/// The result of the last export of a tab: the written file or the error.
pub type Status = Option<Result<String, String>>;

/// Asks where to save, renders the figure and returns the outcome; `None` if cancelled.
pub fn export(
    db: &DbBackend,
    sources: &Sources,
    origin: f64,
    view: View,
    style: &PlotStyle,
    file_name: &str,
) -> Status {
    let path = rfd::FileDialog::new()
        .add_filter("PDF", &["pdf"])
        .add_filter("PNG", &["png"])
        .set_file_name(file_name)
        .save_file()?;
    let path = match Format::of(&path) {
        Some(_) => path,
        None => path.with_extension("pdf"),
    };
    let format = Format::of(&path)?;
    let Some(x) = view.x else {
        return Some(Err("nothing is plotted".into()));
    };
    let fig = collect(db, sources, origin, x, view.y, format.columns(style));
    Some(write(&fig, style, &path).map(|()| path.display().to_string()))
}

/// The button that starts an export, and the outcome of the last one.
pub fn controls(ui: &mut egui::Ui, status: &Status) -> bool {
    let clicked = ui
        .button("Export figure…")
        .on_hover_text("Save the visible plot as PDF or PNG, styled as in Settings → Figure export")
        .clicked();
    match status {
        Some(Ok(path)) => {
            ui.label(egui::RichText::new(format!("Saved {path}")).small());
        }
        Some(Err(e)) => {
            ui.colored_label(egui::Color32::RED, format!("Export failed: {e}"));
        }
        None => {}
    }
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fig() -> Figure {
        Figure {
            x_label: "Time (s)".into(),
            y_label: "SND_CWND".into(),
            x_range: (0.0, 2.0),
            y_range: (0.0, 10.0),
            series: vec![FigureSeries {
                label: "cwnd".into(),
                points: vec![(0.0, 1.0), (1.0, 8.0), (2.0, 4.0)],
                gaps: vec![(0.5, 0.6)],
                step: false,
            }],
        }
    }

    #[test]
    fn writes_pdf_and_png() {
        let dir = tempfile::tempdir().unwrap();
        let style = PlotStyle::default();
        let pdf = dir.path().join("f.pdf");
        write(&fig(), &style, &pdf).unwrap();
        assert!(std::fs::read(&pdf).unwrap().starts_with(b"%PDF"));
        let png = dir.path().join("f.PNG");
        write(&fig(), &style, &png).unwrap();
        let bytes = std::fs::read(&png).unwrap();
        assert!(bytes.starts_with(b"\x89PNG"));
        assert!(write(&fig(), &style, &dir.path().join("f.svg")).is_err());
    }

    #[test]
    fn file_names_and_columns() {
        assert_eq!(
            default_file_name(Some(3), &["SND_CWND", "srtt us"]),
            "flow3_snd_cwnd_srtt_us.pdf"
        );
        let style = PlotStyle::default();
        assert_eq!(Format::Png.columns(&style), 1050);
        assert_eq!(Format::Pdf.columns(&style), 1050);
    }

    #[test]
    fn fit_pads_the_value_range() {
        let (lo, hi) = fit(&fig().series);
        assert!(lo < 1.0 && hi > 8.0);
        assert_eq!(fit(&[]), (0.0, 1.0));
    }
}
