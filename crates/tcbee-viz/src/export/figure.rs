//! A figure as SVG, styled by a [`PlotStyle`]. Lengths are in points (1/72 in), the unit of
//! the style and of the PDF page.

use std::fmt::Write;

use crate::plot_style::{LegendPosition, PlotStyle};

/// One line of a figure. `x` is in seconds.
pub struct FigureSeries {
    pub label: String,
    pub points: Vec<(f64, f64)>,
    /// Spans `(start, end)` in seconds where events are missing; `None` if unknown
    pub gaps: Option<Vec<(f64, f64)>>,
    /// Drawn as steps (on-change series) rather than straight segments
    pub step: bool,
}

pub struct Figure {
    pub x_label: String,
    pub y_label: String,
    pub x_range: (f64, f64),
    pub y_range: (f64, f64),
    pub series: Vec<FigureSeries>,
}

/// Approximate width of a character relative to the font size, for the layout.
const CHAR_WIDTH: f64 = 0.55;
const TICK_LEN: f64 = 3.0;
const GRID_COLOR: &str = "#d9d9d9";

/// About `target` round tick values (1, 2 or 5 times a power of ten) within `[lo, hi]`.
pub fn ticks(lo: f64, hi: f64, target: usize) -> Vec<f64> {
    if !lo.is_finite() || !hi.is_finite() || hi <= lo {
        return vec![lo];
    }
    let raw = (hi - lo) / target.max(1) as f64;
    let mag = 10f64.powf(raw.log10().floor());
    let step = [1.0, 2.0, 5.0, 10.0]
        .into_iter()
        .map(|m| m * mag)
        .find(|s| *s >= raw)
        .unwrap_or(10.0 * mag);
    let first = (lo / step).ceil() as i64;
    let last = (hi / step).floor() as i64;
    (first..=last).map(|k| k as f64 * step).collect()
}

/// A tick label: SI prefixes from 10^4 on, otherwise as few decimals as the tick step needs.
pub fn tick_label(v: f64, step: f64) -> String {
    // Enough decimals to tell ticks `step` apart, also when zoomed in on large values
    let decimals = |step: f64| {
        if step > 0.0 {
            (-step.log10().floor()).clamp(0.0, 12.0) as usize
        } else {
            0
        }
    };
    let a = v.abs();
    for (from, div, suffix) in [
        (1e12, 1e12, "T"),
        (1e9, 1e9, "G"),
        (1e6, 1e6, "M"),
        (1e4, 1e3, "k"),
    ] {
        if a >= from {
            let d = decimals(step / div);
            return trim(format!("{:.d$}", v / div)) + suffix;
        }
    }
    let d = decimals(step);
    let s = format!("{v:.d$}");
    if s.trim_start_matches('-')
        .chars()
        .all(|c| c == '0' || c == '.')
    {
        "0".into()
    } else {
        s
    }
}

fn trim(s: String) -> String {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The figure as an SVG document of `style.width_in` × `style.height_in`.
pub fn svg(fig: &Figure, style: &PlotStyle) -> String {
    let w = f64::from(style.width_in) * 72.0;
    let h = f64::from(style.height_in) * 72.0;
    let fs = f64::from(style.font_size_pt);
    let lw = f64::from(style.line_width_pt);
    let (x0, x1) = fig.x_range;
    let (y0, y1) = fig.y_range;
    let x_ticks = ticks(x0, x1, 5);
    let y_ticks = ticks(y0, y1, 5);
    let x_step = x_ticks
        .get(1)
        .zip(x_ticks.first())
        .map_or(0.0, |(b, a)| b - a);
    let y_step = y_ticks
        .get(1)
        .zip(y_ticks.first())
        .map_or(0.0, |(b, a)| b - a);
    let y_labels: Vec<String> = y_ticks.iter().map(|v| tick_label(*v, y_step)).collect();
    let widest = y_labels
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(1) as f64;

    // Plot area
    let y_label_space = if fig.y_label.is_empty() {
        0.0
    } else {
        fs * 1.4
    };
    let left = fs * 0.4 + y_label_space + widest * fs * CHAR_WIDTH + TICK_LEN + 2.0;
    let x_label_space = if fig.x_label.is_empty() {
        0.0
    } else {
        fs * 1.3
    };
    let bottom = TICK_LEN + 2.0 + fs * 1.1 + x_label_space + fs * 0.3;
    // Room for half of the last x tick label, which is centred on the right edge
    let last_x_label = x_ticks
        .last()
        .map_or(0, |x| tick_label(*x, x_step).chars().count());
    let right = (last_x_label as f64 * fs * CHAR_WIDTH / 2.0).max(fs * 0.9);
    let top = fs * 0.6;
    let (pl, pr, pt, pb) = (left, w - right, top, h - bottom);
    let sx = |x: f64| pl + (x - x0) / (x1 - x0).max(f64::MIN_POSITIVE) * (pr - pl);
    let sy = |y: f64| pb - (y - y0) / (y1 - y0).max(f64::MIN_POSITIVE) * (pb - pt);

    let family = escape(&style.font_family);
    let mut s = String::new();
    let _ = write!(
        s,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w}pt" height="{h}pt" viewBox="0 0 {w} {h}" font-family="{family}, sans-serif" font-size="{fs}">"#
    );
    let _ = write!(
        s,
        r#"<defs><clipPath id="area"><rect x="{pl}" y="{pt}" width="{}" height="{}"/></clipPath></defs>"#,
        pr - pl,
        pb - pt
    );
    let _ = write!(s, r#"<rect width="{w}" height="{h}" fill="white"/>"#);

    if style.grid {
        let _ = write!(s, r#"<g stroke="{GRID_COLOR}" stroke-width="0.4">"#);
        for x in &x_ticks {
            let _ = write!(
                s,
                r#"<line x1="{0}" y1="{pt}" x2="{0}" y2="{pb}"/>"#,
                sx(*x)
            );
        }
        for y in &y_ticks {
            let _ = write!(
                s,
                r#"<line x1="{pl}" y1="{0}" x2="{pr}" y2="{0}"/>"#,
                sy(*y)
            );
        }
        s.push_str("</g>");
    }

    s.push_str(r#"<g clip-path="url(#area)">"#);
    if style.show_gaps {
        let _ = write!(
            s,
            r#"<g fill="{}" fill-opacity="{}">"#,
            escape(&style.gap_color),
            style.gap_opacity
        );
        for (a, b) in fig.series.iter().flat_map(|f| f.gaps.iter().flatten()) {
            // At least a hairline, so a gap between two close events stays visible
            let (xa, xb) = (sx(*a), sx(*b));
            let width = (xb - xa).max(0.5);
            let _ = write!(
                s,
                r#"<rect x="{}" y="{pt}" width="{width}" height="{}"/>"#,
                xa - (width - (xb - xa)) / 2.0,
                pb - pt
            );
        }
        s.push_str("</g>");
    }
    for (i, f) in fig.series.iter().enumerate() {
        let mut d = String::new();
        let mut prev: Option<(f64, f64)> = None;
        for &(x, y) in &f.points {
            let (px, py) = (sx(x), sy(y));
            match prev {
                None => {
                    let _ = write!(d, "M{px:.2} {py:.2}");
                }
                Some((_, prev_y)) if f.step => {
                    let _ = write!(d, "L{px:.2} {prev_y:.2}L{px:.2} {py:.2}");
                }
                Some(_) => {
                    let _ = write!(d, "L{px:.2} {py:.2}");
                }
            }
            prev = Some((px, py));
        }
        let _ = write!(
            s,
            r#"<path d="{d}" fill="none" stroke="{}" stroke-width="{lw}" stroke-linejoin="round" stroke-linecap="round"/>"#,
            escape(style.palette_color(i))
        );
    }
    s.push_str("</g>");

    // Frame, ticks and labels
    let _ = write!(
        s,
        r#"<rect x="{pl}" y="{pt}" width="{}" height="{}" fill="none" stroke="black" stroke-width="0.6"/>"#,
        pr - pl,
        pb - pt
    );
    s.push_str(r#"<g stroke="black" stroke-width="0.6">"#);
    for x in &x_ticks {
        let _ = write!(
            s,
            r#"<line x1="{0}" y1="{pb}" x2="{0}" y2="{1}"/>"#,
            sx(*x),
            pb + TICK_LEN
        );
    }
    for y in &y_ticks {
        let _ = write!(
            s,
            r#"<line x1="{0}" y1="{1}" x2="{pl}" y2="{1}"/>"#,
            pl - TICK_LEN,
            sy(*y)
        );
    }
    s.push_str("</g>");
    for x in &x_ticks {
        let _ = write!(
            s,
            r#"<text x="{}" y="{}" text-anchor="middle">{}</text>"#,
            sx(*x),
            pb + TICK_LEN + 1.0 + fs,
            escape(&tick_label(*x, x_step))
        );
    }
    for (y, label) in y_ticks.iter().zip(&y_labels) {
        let _ = write!(
            s,
            r#"<text x="{}" y="{}" text-anchor="end">{}</text>"#,
            pl - TICK_LEN - 2.0,
            sy(*y) + fs * 0.35,
            escape(label)
        );
    }
    if !fig.x_label.is_empty() {
        let _ = write!(
            s,
            r#"<text x="{}" y="{}" text-anchor="middle">{}</text>"#,
            (pl + pr) / 2.0,
            h - fs * 0.4,
            escape(&fig.x_label)
        );
    }
    if !fig.y_label.is_empty() {
        let (x, y) = (fs * 1.1, (pt + pb) / 2.0);
        let _ = write!(
            s,
            r#"<text x="{x}" y="{y}" text-anchor="middle" transform="rotate(-90 {x} {y})">{}</text>"#,
            escape(&fig.y_label)
        );
    }
    legend(&mut s, fig, style, (pl, pr, pt, pb));
    s.push_str("</svg>");
    s
}

/// The legend entry of a series; it tells when the gaps of a shown series are unknown, so a
/// run without hook_seq does not look loss-free.
fn legend_label(f: &FigureSeries, style: &PlotStyle) -> String {
    if style.show_gaps && f.gaps.is_none() {
        format!("{} (gaps n/a)", f.label)
    } else {
        f.label.clone()
    }
}

fn legend(s: &mut String, fig: &Figure, style: &PlotStyle, (pl, pr, pt, pb): (f64, f64, f64, f64)) {
    if style.legend == LegendPosition::None || fig.series.is_empty() {
        return;
    }
    let fs = f64::from(style.font_size_pt);
    let row = fs * 1.25;
    let sample = fs * 1.6;
    let labels: Vec<String> = fig.series.iter().map(|f| legend_label(f, style)).collect();
    let longest = labels.iter().map(|l| l.chars().count()).max().unwrap_or(0) as f64;
    let bw = sample + fs * 0.9 + longest * fs * CHAR_WIDTH + fs * 0.4;
    let bh = row * fig.series.len() as f64 + fs * 0.4;
    let pad = fs * 0.4;
    let (bx, by) = match style.legend {
        LegendPosition::UpperLeft => (pl + pad, pt + pad),
        LegendPosition::UpperRight | LegendPosition::None => (pr - pad - bw, pt + pad),
        LegendPosition::LowerLeft => (pl + pad, pb - pad - bh),
        LegendPosition::LowerRight => (pr - pad - bw, pb - pad - bh),
    };
    let _ = write!(
        s,
        r##"<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" fill="white" fill-opacity="0.85" stroke="#bfbfbf" stroke-width="0.4"/>"##
    );
    for (i, label) in labels.iter().enumerate() {
        let cy = by + fs * 0.2 + row * (i as f64 + 0.5);
        let _ = write!(
            s,
            r#"<line x1="{}" y1="{cy}" x2="{}" y2="{cy}" stroke="{}" stroke-width="{}"/>"#,
            bx + fs * 0.4,
            bx + fs * 0.4 + sample,
            escape(style.palette_color(i)),
            style.line_width_pt
        );
        let _ = write!(
            s,
            r#"<text x="{}" y="{}">{}</text>"#,
            bx + fs * 0.4 + sample + fs * 0.5,
            cy + fs * 0.35,
            escape(label)
        );
    }
}

/// Per column of `columns` equal time slices of `[x0, x1]`: the first, lowest, highest and
/// last point, in time order. Keeps every peak of a series at the resolution of the figure
/// while bounding the number of points. Feed points in time order with [`Envelope::push`].
pub struct Envelope {
    x0: f64,
    width: f64,
    columns: usize,
    current: Option<(usize, [(f64, f64); 4])>,
    out: Vec<(f64, f64)>,
}

impl Envelope {
    pub fn new(x0: f64, x1: f64, columns: usize) -> Self {
        let columns = columns.max(1);
        Self {
            x0,
            width: (x1 - x0) / columns as f64,
            columns,
            current: None,
            out: Vec::new(),
        }
    }

    pub fn push(&mut self, x: f64, y: f64) {
        let col = if self.width > 0.0 {
            (((x - self.x0) / self.width).floor().max(0.0) as usize).min(self.columns - 1)
        } else {
            0
        };
        match &mut self.current {
            Some((c, [_, lo, hi, last])) if *c == col => {
                if y < lo.1 {
                    *lo = (x, y);
                }
                if y > hi.1 {
                    *hi = (x, y);
                }
                *last = (x, y);
            }
            _ => {
                self.flush();
                self.current = Some((col, [(x, y); 4]));
            }
        }
    }

    fn flush(&mut self) {
        if let Some((_, mut pts)) = self.current.take() {
            pts.sort_by(|a, b| a.0.total_cmp(&b.0));
            for p in pts {
                if self.out.last() != Some(&p) {
                    self.out.push(p);
                }
            }
        }
    }

    pub fn finish(mut self) -> Vec<(f64, f64)> {
        self.flush();
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_are_round() {
        assert_eq!(ticks(0.0, 10.0, 5), vec![0.0, 2.0, 4.0, 6.0, 8.0, 10.0]);
        let t = ticks(0.13, 0.61, 5);
        let want = [0.2, 0.3, 0.4, 0.5, 0.6];
        assert_eq!(t.len(), want.len());
        assert!(t.iter().zip(want).all(|(a, b)| (a - b).abs() < 1e-12));
        assert_eq!(ticks(3.0, 3.0, 5), vec![3.0]);
    }

    #[test]
    fn tick_labels() {
        assert_eq!(tick_label(0.30000000000000004, 0.1), "0.3");
        assert_eq!(tick_label(2.0, 2.0), "2");
        assert_eq!(tick_label(25_000.0, 5000.0), "25k");
        assert_eq!(tick_label(1.5e9, 5e8), "1.5G");
        assert_eq!(tick_label(-0.0, 0.5), "0");
        // Zoomed in on large values: still distinct
        assert_eq!(tick_label(4_294_967_100.0, 100.0), "4.2949671G");
        assert_eq!(tick_label(4_294_967_200.0, 100.0), "4.2949672G");
        assert_eq!(tick_label(10_002.0, 2.0), "10.002k");
    }

    #[test]
    fn envelope_keeps_extremes_per_column() {
        let mut e = Envelope::new(0.0, 2.0, 2);
        for (x, y) in [(0.0, 1.0), (0.2, 5.0), (0.4, -1.0), (0.6, 2.0), (1.5, 3.0)] {
            e.push(x, y);
        }
        assert_eq!(
            e.finish(),
            vec![(0.0, 1.0), (0.2, 5.0), (0.4, -1.0), (0.6, 2.0), (1.5, 3.0)]
        );
        let mut e = Envelope::new(0.0, 1.0, 1);
        for i in 0..1000 {
            e.push(i as f64 / 1000.0, (i % 7) as f64);
        }
        assert!(e.finish().len() <= 4);
    }

    #[test]
    fn svg_has_series_gaps_labels_and_escapes() {
        let fig = Figure {
            x_label: "Time (s)".into(),
            y_label: "cwnd <segments>".into(),
            x_range: (0.0, 1.0),
            y_range: (0.0, 10.0),
            series: vec![FigureSeries {
                label: "a & b".into(),
                points: vec![(0.0, 1.0), (1.0, 9.0)],
                gaps: Some(vec![(0.4, 0.5)]),
                step: false,
            }],
        };
        let s = svg(&fig, &PlotStyle::default());
        assert!(s.starts_with("<svg") && s.ends_with("</svg>"));
        assert!(s.contains("cwnd &lt;segments&gt;") && s.contains("a &amp; b"));
        assert!(s.contains(r#"fill-opacity="0.3""#));
        assert!(s.contains(r##"stroke="#0072b2""##));
        let no_gaps = PlotStyle {
            show_gaps: false,
            ..PlotStyle::default()
        };
        assert!(!svg(&fig, &no_gaps).contains("fill-opacity=\"0.3\""));
        let unknown = Figure {
            series: vec![FigureSeries {
                gaps: None,
                ..fig.series.into_iter().next().unwrap()
            }],
            ..fig
        };
        assert!(svg(&unknown, &PlotStyle::default()).contains("a &amp; b (gaps n/a)"));
        assert!(!svg(&unknown, &no_gaps).contains("gaps n/a"));
    }
}
