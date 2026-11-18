//! Export of the current plot as a Python script that loads its data with the tcbee package.
//! The script holds no plotting code: users plot with the library they like. Its text is
//! `assets/view_template.py`; this module only fills in the values.

use std::fmt::Write;
use std::path::Path;

use super::{Sources, View};
use crate::plot_style::PlotStyle;

const TEMPLATE: &str = include_str!("../../assets/view_template.py");

/// One plotted series, as the tcbee package selects it.
#[derive(Debug, PartialEq)]
pub struct ScriptSeries {
    pub flow_id: i64,
    pub source: String,
    pub name: String,
    pub direction: &'static str,
    pub label: String,
    pub color: String,
}

/// A Python string literal.
fn py_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The script for `series` of the database `db`, in the range `[start_ns, end_ns)`.
pub fn render(
    db: &str,
    (start_ns, end_ns): (i64, i64),
    origin_ns: i64,
    y_range: Option<(f64, f64)>,
    series: &[ScriptSeries],
) -> String {
    let mut rows = String::new();
    for s in series {
        let _ = writeln!(
            rows,
            "    ({}, {}, {}, {}, {}, {}),",
            s.flow_id,
            py_str(&s.source),
            py_str(&s.name),
            py_str(s.direction),
            py_str(&s.label),
            py_str(&s.color)
        );
    }
    let y = y_range.map_or("None".to_string(), |(lo, hi)| format!("({lo:?}, {hi:?})"));
    // Strings last, so a placeholder inside them stays as it is
    TEMPLATE
        .replace("{{START_NS}}", &start_ns.to_string())
        .replace("{{END_NS}}", &end_ns.to_string())
        .replace("{{ORIGIN_NS}}", &origin_ns.to_string())
        .replace("{{YLIM}}", &y)
        .replace("{{SERIES}}", &rows)
        .replace("{{DB}}", &py_str(db))
}

/// The series of `sources` that the tcbee package can read, coloured as in the figure.
pub fn series(sources: &Sources, style: &PlotStyle) -> Vec<ScriptSeries> {
    let mut out = Vec::new();
    for (prefix, sd, info) in super::exported(sources) {
        out.push(ScriptSeries {
            flow_id: info.flow_id,
            source: info.source.clone(),
            name: info.name.clone(),
            direction: ["none", "send", "recv"][usize::from(info.dir.code()).min(2)],
            label: format!("{prefix}{}", sd.name),
            color: super::series_color(style, out.len(), sd),
        });
    }
    out
}

/// Asks where to save and writes the script; `None` if cancelled.
pub fn export(
    db_path: Option<&Path>,
    sources: &Sources,
    origin: f64,
    view: View,
    style: &PlotStyle,
    file_name: &str,
) -> super::Status {
    let (Some(db_path), Some((x0, x1))) = (db_path, view.x) else {
        return Some(Err("no database is open".into()));
    };
    let path = rfd::FileDialog::new()
        .add_filter("Python", &["py"])
        .set_file_name(file_name)
        .save_file()?;
    let db = std::path::absolute(db_path).unwrap_or_else(|_| db_path.to_path_buf());
    // The script's range is half-open, the visible one inclusive
    let range = (x0.floor() as i64, x1.ceil() as i64 + 1);
    let text = render(
        &db.to_string_lossy(),
        range,
        origin.round() as i64,
        view.y,
        &series(sources, style),
    );
    Some(
        std::fs::write(&path, text)
            .map(|()| path.display().to_string())
            .map_err(|e| format!("{}: {e}", path.display())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_in_the_template() {
        let s = render(
            "/data/run \"1\".db",
            (10, 21),
            5,
            Some((0.0, 1.5)),
            &[ScriptSeries {
                flow_id: 3,
                source: "sock".into(),
                name: "snd_cwnd".into(),
                direction: "send",
                label: "A:snd_cwnd".into(),
                color: "#0072b2".into(),
            }],
        );
        assert!(!s.contains("{{"), "unfilled placeholder in\n{s}");
        assert!(s.contains(r#"DB = "/data/run \"1\".db""#));
        assert!(s.contains("START_NS, END_NS = 10, 21"));
        assert!(s.contains("ORIGIN_NS = 5"));
        assert!(s.contains("YLIM = (0.0, 1.5)"));
        assert!(s.contains(r##"    (3, "sock", "snd_cwnd", "send", "A:snd_cwnd", "#0072b2"),"##));
        assert!(!s.contains("import matplotlib\n"));
        assert!(render("x", (0, 1), 0, None, &[]).contains("YLIM = None"));
    }

    #[test]
    fn python_strings_escape_quotes_and_controls() {
        assert_eq!(py_str("a\\b\"c\n"), r#""a\\b\"c\u000a""#);
    }
}
