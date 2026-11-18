//! Style of exported figures, kept in `$XDG_CONFIG_HOME/tcbee/viz.toml` (default
//! `~/.config/tcbee/viz.toml`) under `[plot]`, so users can edit it by hand and keep it with
//! their paper. A missing file gives the defaults; an unreadable one is reported and ignored.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where an exported figure puts its legend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegendPosition {
    None,
    /// In a row above the plot area, so it never covers data
    Above,
    UpperLeft,
    UpperRight,
    LowerLeft,
    LowerRight,
}

impl LegendPosition {
    pub const ALL: [LegendPosition; 6] = [
        LegendPosition::Above,
        LegendPosition::UpperRight,
        LegendPosition::UpperLeft,
        LegendPosition::LowerRight,
        LegendPosition::LowerLeft,
        LegendPosition::None,
    ];

    pub fn label(self) -> &'static str {
        match self {
            LegendPosition::None => "none",
            LegendPosition::Above => "above the plot",
            LegendPosition::UpperLeft => "upper left",
            LegendPosition::UpperRight => "upper right",
            LegendPosition::LowerLeft => "lower left",
            LegendPosition::LowerRight => "lower right",
        }
    }
}

/// Look of exported figures. Sizes are in inches and points, as in LaTeX documents.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlotStyle {
    pub width_in: f32,
    pub height_in: f32,
    /// Font family name; a missing family falls back to a sans-serif font.
    pub font_family: String,
    pub font_size_pt: f32,
    pub line_width_pt: f32,
    pub grid: bool,
    pub legend: LegendPosition,
    /// Colour series by `palette` instead of their colours in the viewer
    pub use_palette: bool,
    /// Line colours as `#rrggbb`, used in series order when `use_palette` is set.
    pub palette: Vec<String>,
    /// Shade hook_seq gaps in the colour of their series, as the viewer does
    pub gaps_in_series_color: bool,
    /// Colour of the shaded hook_seq gaps, `#rrggbb`, if not in the series colour
    pub gap_color: String,
    /// Opacity of the shaded gaps
    pub gap_opacity: f32,
    pub show_gaps: bool,
    /// Resolution of PNG exports.
    pub png_dpi: u32,
}

impl Default for PlotStyle {
    fn default() -> Self {
        Self {
            width_in: 3.5,
            height_in: 2.2,
            font_family: "sans-serif".into(),
            font_size_pt: 8.0,
            line_width_pt: 1.0,
            grid: true,
            legend: LegendPosition::Above,
            use_palette: false,
            // Okabe-Ito, distinguishable with colour vision deficiencies
            palette: [
                "#0072b2", "#e69f00", "#009e73", "#d55e00", "#cc79a7", "#56b4e9", "#f0e442",
                "#000000",
            ]
            .map(String::from)
            .to_vec(),
            gaps_in_series_color: true,
            gap_color: "#808080".into(),
            gap_opacity: 0.25,
            show_gaps: true,
            png_dpi: 300,
        }
    }
}

/// Figure size presets: (label, width, height) in inches.
pub const SIZE_PRESETS: [(&str, f32, f32); 3] = [
    ("Single column", 3.5, 2.2),
    ("Double column", 7.0, 2.6),
    ("Slide 16:9", 8.0, 4.5),
];

#[derive(Default, Serialize, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    plot: PlotStyle,
}

/// `$XDG_CONFIG_HOME/tcbee/viz.toml`, else `$HOME/.config/tcbee/viz.toml`.
pub fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("tcbee").join("viz.toml"))
}

impl PlotStyle {
    /// The style in `path`; defaults if the file does not exist.
    pub fn load_from(path: &Path) -> Result<PlotStyle, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str::<ConfigFile>(&text)
                .map(|c| c.plot)
                .map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PlotStyle::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let text = toml::to_string_pretty(&ConfigFile { plot: self.clone() })
            .map_err(|e| e.to_string())?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The style of the user's config file; defaults (and a logged error) if it is unreadable.
    pub fn load() -> PlotStyle {
        let Some(path) = config_path() else {
            return PlotStyle::default();
        };
        PlotStyle::load_from(&path).unwrap_or_else(|e| {
            eprintln!("tcbee-viz: ignoring the plot style: {e}");
            PlotStyle::default()
        })
    }

    /// The `#rrggbb` colour of the `i`-th series, repeating the palette.
    pub fn palette_color(&self, i: usize) -> &str {
        match self.palette.len() {
            0 => "#000000",
            n => &self.palette[i % n],
        }
    }
}

/// `#rrggbb` to a colour.
pub fn parse_hex(s: &str) -> Option<egui::Color32> {
    let h = s.strip_prefix('#')?;
    if h.len() != 6 {
        return None;
    }
    let v = u32::from_str_radix(h, 16).ok()?;
    Some(egui::Color32::from_rgb(
        (v >> 16) as u8,
        (v >> 8) as u8,
        v as u8,
    ))
}

/// A colour as `#rrggbb`.
pub fn to_hex(c: egui::Color32) -> String {
    format!("#{:02x}{:02x}{:02x}", c.r(), c.g(), c.b())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_gives_defaults_and_saved_style_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tcbee").join("viz.toml");
        assert_eq!(PlotStyle::load_from(&path), Ok(PlotStyle::default()));
        let style = PlotStyle {
            font_size_pt: 9.0,
            legend: LegendPosition::LowerLeft,
            ..PlotStyle::default()
        };
        style.save_to(&path).unwrap();
        assert_eq!(PlotStyle::load_from(&path), Ok(style));
    }

    #[test]
    fn partial_file_fills_in_defaults_and_bad_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("viz.toml");
        std::fs::write(&path, "[plot]\nwidth_in = 7.0\n").unwrap();
        let style = PlotStyle::load_from(&path).unwrap();
        assert_eq!(style.width_in, 7.0);
        assert_eq!(style.font_size_pt, PlotStyle::default().font_size_pt);
        std::fs::write(&path, "[plot]\nwidth_in = \"wide\"\n").unwrap();
        assert!(PlotStyle::load_from(&path).is_err());
    }

    #[test]
    fn hex_colours() {
        let c = parse_hex("#0072b2").unwrap();
        assert_eq!(to_hex(c), "#0072b2");
        assert_eq!(parse_hex("0072b2"), None);
        let style = PlotStyle::default();
        assert_eq!(style.palette_color(8), style.palette_color(0));
    }
}
