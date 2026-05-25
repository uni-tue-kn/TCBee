use egui::Color32;
use rand::{rng, Rng};

/// Return `n` visually-distinct colors.
pub fn generate_colors(n: usize) -> Vec<Color32> {
    if n == 0 {
        return Vec::new();
    }
    let offset: f64 = rng().random();
    (0..n)
        .map(|i| {
            let hue = ((i as f64 / n as f64) + offset) % 1.0;
            let (r, g, b) = hsl_to_rgb(hue, 0.70, 0.50);
            Color32::from_rgb(r, g, b)
        })
        .collect()
}

/// Standard HSL → RGB conversion. All inputs in [0, 1].
fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h * 6.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r, g, b) = if h < 1.0 / 6.0 {
        (c, x, 0.0)
    } else if h < 2.0 / 6.0 {
        (x, c, 0.0)
    } else if h < 3.0 / 6.0 {
        (0.0, c, x)
    } else if h < 4.0 / 6.0 {
        (0.0, x, c)
    } else if h < 5.0 / 6.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };
    (
        ((r + m) * 255.0).round() as u8,
        ((g + m) * 255.0).round() as u8,
        ((b + m) * 255.0).round() as u8,
    )
}

/// Compute how many points to skip so that at most `max_render` points are passed to egui_plot.
pub fn compute_skip_step(point_count: usize, base_skip: usize) -> usize {
    const MAX_RENDER: usize = 2000;
    if point_count <= MAX_RENDER {
        base_skip.max(1)
    } else {
        (point_count / MAX_RENDER).max(base_skip).max(1)
    }
}

/// Downsample `points` by keeping one out of every `step` entries.
pub fn downsample(points: Vec<(f64, f64)>, step: usize) -> Vec<(f64, f64)> {
    if step <= 1 {
        return points;
    }
    points.into_iter().step_by(step).collect()
}
