//! Export of the current plot as a styled PDF or PNG figure.

pub mod figure;
pub mod script;

use std::path::Path;
use std::sync::{Arc, OnceLock};

use resvg::{tiny_skia, usvg};
use ts_storage::{Gaps, SeriesInfo};

use crate::{
    backend::db::DbBackend,
    data::{
        plot_state::PlotState,
        preprocessing::{expand_steps, Envelope},
        series_data::SeriesData,
    },
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

/// The exported series of `sources` in plot order, with their legend prefix: the numeric
/// series of the database.
fn exported<'a>(
    sources: &'a Sources<'a>,
) -> impl Iterator<Item = (&'a str, &'a SeriesData, &'a SeriesInfo)> + 'a {
    sources.iter().flat_map(|(state, prefix)| {
        state
            .series
            .iter()
            .filter(|s| !s.is_string_type())
            .filter_map(move |s| Some((*prefix, s, s.info.as_ref()?)))
    })
}

/// The colour of the `i`-th exported series `sd`, in the figure and the data script alike:
/// its colour in the viewer, or the style's palette if the style asks for it.
fn series_color(style: &PlotStyle, i: usize, sd: &SeriesData) -> String {
    if style.use_palette {
        style.palette_color(i).to_string()
    } else {
        crate::plot_style::to_hex(sd.color)
    }
}

/// The plotted series that cannot be exported: plugin outputs, which are not in the
/// database, and text series.
fn not_exported(sources: &Sources) -> Vec<String> {
    sources
        .iter()
        .flat_map(|(state, prefix)| state.series.iter().map(move |s| (prefix, s)))
        .filter(|(_, s)| s.info.is_none() || s.is_string_type())
        .map(|(prefix, s)| format!("{prefix}{}", s.name))
        .collect()
}

/// The figure of the numeric series of `sources` in the time range `x_range` (ns), read from
/// the database at the figure's resolution. Times become seconds since `origin` (ns), as on
/// the plot axis. `y_range` `None` fits the data.
pub fn collect(
    db: &DbBackend,
    sources: &Sources,
    origin: f64,
    x_range: (f64, f64),
    y_range: Option<(f64, f64)>,
    style: &PlotStyle,
    columns: usize,
) -> Figure {
    let (t0, t1) = x_range;
    let secs = |t: f64| (t - origin) / 1e9;
    let mut series = Vec::new();
    let mut names = Vec::new();
    for (prefix, sd, info) in exported(sources) {
        let points = if sd.step {
            let end = db.flow_end(info.flow_id).map(|t| t.min(t1));
            let steps = expand_steps(&db.load_range_steps(info, t0, t1), end);
            // The first, lowest, highest and last point of each column keep the levels
            let mut env = Envelope::new(t0, t1, columns);
            steps.into_iter().for_each(|(t, v)| env.push(t, v));
            env.finish()
        } else {
            db.load_range_envelope(info, t0, t1, columns)
        };
        let gaps = match &sd.gaps {
            Some(Gaps::Known(gaps)) => Some(
                gaps.iter()
                    .filter(|g| g.overlaps(t0, t1))
                    .map(|g| (secs(g.start_ns as f64), secs(g.end_ns as f64)))
                    .collect(),
            ),
            _ => None,
        };
        names.push(info.name.clone());
        series.push(FigureSeries {
            label: format!("{prefix}{}", sd.name),
            color: series_color(style, series.len(), sd),
            points: points.into_iter().map(|(t, v)| (secs(t), v)).collect(),
            gaps,
            step: sd.step,
        });
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

/// A file name without extension for an export of `flow_id` and its first three `metrics`:
/// `flow<id>_<metric>[_<metric>]`.
pub fn default_file_stem(flow_id: Option<i64>, metrics: &[&str]) -> String {
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
    name
}

/// The visible part of a plot: x range (ns) and, for a single plot, its y range.
#[derive(Clone, Copy, Default)]
pub struct View {
    pub x: Option<(f64, f64)>,
    pub y: Option<(f64, f64)>,
}

/// The result of the last export of a tab: the written file or the error.
pub type Status = Option<Result<String, String>>;

/// Runs an export of the plotted `sources`: asks where to save and returns the outcome, `None`
/// if cancelled. `file_stem` names the file by default.
pub fn run(
    request: Request,
    db: &DbBackend,
    sources: &Sources,
    origin: f64,
    view: View,
    style: &PlotStyle,
    file_stem: &str,
) -> Status {
    if exported(sources).next().is_none() {
        return Some(Err("no numeric metric of the database is plotted".into()));
    }
    if view.x.is_none() {
        return Some(Err("the plot has not been drawn yet".into()));
    }
    let status = match request {
        Request::Figure => export_figure(
            db,
            sources,
            origin,
            view,
            style,
            &format!("{file_stem}.pdf"),
        ),
        Request::Script => script::export(
            db.path(),
            sources,
            origin,
            view,
            style,
            &format!("{file_stem}.py"),
        ),
    }?;
    let skipped = not_exported(sources);
    Some(status.map(|path| {
        if skipped.is_empty() {
            path
        } else {
            format!("{path} (without {})", skipped.join(", "))
        }
    }))
}

/// Asks where to save, renders the figure and returns the outcome; `None` if cancelled.
fn export_figure(
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
    let path = if path.extension().is_none() {
        path.with_extension("pdf")
    } else {
        path
    };
    let Some(format) = Format::of(&path) else {
        return Some(Err("the file name must end in .pdf or .png".into()));
    };
    let Some(x) = view.x else {
        return Some(Err("nothing is plotted".into()));
    };
    let fig = collect(db, sources, origin, x, view.y, style, format.columns(style));
    Some(write(&fig, style, &path).map(|()| path.display().to_string()))
}

/// What the user asked to export.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Figure,
    Script,
}

/// The export buttons and the outcome of the last export.
pub fn controls(ui: &mut egui::Ui, status: &Status) -> Option<Request> {
    let mut request = None;
    ui.horizontal(|ui| {
        if ui
            .button("Export figure…")
            .on_hover_text(
                "Save the visible plot as PDF or PNG, styled as in Settings → Figure export",
            )
            .clicked()
        {
            request = Some(Request::Figure);
        }
        if ui
            .button("Export data script…")
            .on_hover_text(
                "Save a Python script that loads the plotted data and gaps with the tcbee \
                 package, to plot with the library of your choice",
            )
            .clicked()
        {
            request = Some(Request::Script);
        }
    });
    match status {
        Some(Ok(path)) => {
            ui.label(egui::RichText::new(format!("Saved {path}")).small());
        }
        Some(Err(e)) => {
            ui.colored_label(egui::Color32::RED, format!("Export failed: {e}"));
        }
        None => {}
    }
    request
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
                color: "#0072b2".into(),
                points: vec![(0.0, 1.0), (1.0, 8.0), (2.0, 4.0)],
                gaps: Some(vec![(0.5, 0.6)]),
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
            default_file_stem(Some(3), &["SND_CWND", "srtt us"]),
            "flow3_snd_cwnd_srtt_us"
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

#[cfg(test)]
mod selection_tests {
    use ts_storage::{ColType, Dir, SeriesKind, ValueKind};

    use super::*;

    fn info(id: i64, name: &str, value_type: ColType) -> SeriesInfo {
        SeriesInfo {
            id,
            flow_id: 1,
            kind: SeriesKind::Raw,
            source: "sock".into(),
            dir: Dir::Send,
            name: name.into(),
            value_type,
            tbl: Some("ev_sock".into()),
            col: Some(name.into()),
            n: 1,
            t_min: Some(0),
            t_max: Some(1),
            v_min: None,
            v_max: None,
        }
    }

    #[test]
    fn text_and_plugin_series_are_not_exported_and_colours_match() {
        let mut state = PlotState::default();
        let black = egui::Color32::BLACK;
        state.series = vec![
            SeriesData::from_info(&info(1, "event", ColType::Text), 0.0, 1.0, black),
            SeriesData::from_info(&info(2, "snd_cwnd", ColType::U32), 0.0, 1.0, black),
            SeriesData::new(
                "plugin".into(),
                3,
                ValueKind::Float,
                0.0,
                1.0,
                0.0,
                1.0,
                black,
            ),
        ];
        let sources = [(&state, "A:")];
        let names: Vec<&str> = exported(&sources)
            .map(|(_, s, _)| s.name.as_str())
            .collect();
        assert_eq!(names, vec![state.series[1].name.as_str()]);
        assert_eq!(not_exported(&sources).len(), 2);
        let mut style = PlotStyle::default();
        let script = script::series(&sources, &style);
        assert_eq!(script.len(), 1);
        assert_eq!(script[0].direction, "send");
        // The viewer's colour, or the palette's first one, as in the figure
        assert_eq!(script[0].color, "#000000");
        style.use_palette = true;
        assert_eq!(
            script::series(&sources, &style)[0].color,
            style.palette_color(0)
        );
    }
}
