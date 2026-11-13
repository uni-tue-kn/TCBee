use egui::Color32;

pub const MAX_RENDER_POINTS: usize = 2000;
const DISTINCT_PALETTE: [Color32; 20] = [
    Color32::from_rgb(31, 119, 180),
    Color32::from_rgb(214, 39, 40),
    Color32::from_rgb(44, 160, 44),
    Color32::from_rgb(255, 127, 14),
    Color32::from_rgb(148, 103, 189),
    Color32::from_rgb(23, 190, 207),
    Color32::from_rgb(227, 119, 194),
    Color32::from_rgb(188, 189, 34),
    Color32::from_rgb(140, 86, 75),
    Color32::from_rgb(127, 127, 127),
    Color32::from_rgb(57, 59, 121),
    Color32::from_rgb(82, 84, 163),
    Color32::from_rgb(156, 158, 222),
    Color32::from_rgb(99, 121, 57),
    Color32::from_rgb(140, 162, 82),
    Color32::from_rgb(181, 207, 107),
    Color32::from_rgb(140, 109, 49),
    Color32::from_rgb(189, 158, 57),
    Color32::from_rgb(231, 186, 82),
    Color32::from_rgb(173, 73, 74),
];

/// Return `n` visually-distinct colors.
pub fn generate_colors(n: usize) -> Vec<Color32> {
    (0..n)
        .map(|i| {
            DISTINCT_PALETTE
                .get(i)
                .copied()
                .unwrap_or_else(|| generated_color(i))
        })
        .collect()
}

fn generated_color(index: usize) -> Color32 {
    let hue = ((index - DISTINCT_PALETTE.len()) as f64 * 0.618_033_988_75) % 1.0;
    let (r, g, b) = hsl_to_rgb(hue, 0.72, 0.46);
    Color32::from_rgb(r, g, b)
}

/// Standard HSL -> RGB conversion. All inputs in [0, 1].
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
    if point_count <= MAX_RENDER_POINTS {
        base_skip.max(1)
    } else {
        (point_count / MAX_RENDER_POINTS).max(base_skip).max(1)
    }
}

/// Compute the minimum time distance between displayed points.
pub fn compute_sample_interval(
    fetch_min: f64,
    fetch_max: f64,
    plot_width_px: Option<f32>,
    time_granularity_ms: f64,
    adaptive_downsample: bool,
    min_pixels_per_point: f64,
) -> f64 {
    let manual = (time_granularity_ms / 1000.0).max(0.0);
    let adaptive = if adaptive_downsample {
        plot_width_px
            .filter(|w| *w > 0.0)
            .map(|w| {
                let target_points = ((w as f64) / min_pixels_per_point.max(0.5))
                    .floor()
                    .clamp(50.0, MAX_RENDER_POINTS as f64);
                ((fetch_max - fetch_min) / target_points).max(0.0)
            })
            .unwrap_or(0.0)
    } else {
        0.0
    };
    manual.max(adaptive)
}

/// Downsample `points` by keeping one out of every `step` entries.
pub fn downsample(points: Vec<(f64, f64)>, step: usize) -> Vec<(f64, f64)> {
    if step <= 1 {
        return points;
    }
    points.into_iter().step_by(step).collect()
}

/// Thins a step series to at most `max_points` by time buckets, keeping in every bucket its
/// first and last point and the points with the lowest and highest value, so every level the
/// series reaches stays visible.
pub fn bucket_min_max(points: Vec<(f64, f64)>, max_points: usize) -> Vec<(f64, f64)> {
    let buckets = max_points / 4;
    if points.len() <= max_points || buckets == 0 {
        return points;
    }
    let t0 = points[0].0;
    let span = points[points.len() - 1].0 - t0;
    if span.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
        return points;
    }
    let bucket_of = |t: f64| (((t - t0) / span * buckets as f64) as usize).min(buckets - 1);
    let mut out = Vec::with_capacity(max_points);
    let mut start = 0;
    while start < points.len() {
        let b = bucket_of(points[start].0);
        let mut end = start + 1;
        while end < points.len() && bucket_of(points[end].0) == b {
            end += 1;
        }
        let bucket = &points[start..end];
        let lowest = (0..bucket.len()).min_by(|&i, &j| bucket[i].1.total_cmp(&bucket[j].1));
        let highest = (0..bucket.len()).max_by(|&i, &j| bucket[i].1.total_cmp(&bucket[j].1));
        let mut keep = vec![0, bucket.len() - 1];
        keep.extend(lowest);
        keep.extend(highest);
        keep.sort_unstable();
        keep.dedup();
        out.extend(keep.into_iter().map(|i| bucket[i]));
        start = end;
    }
    out
}

/// Draws a step series: before every change the previous value is held up to the change's
/// time, and the last value is held until `end`.
pub fn expand_steps(points: &[(f64, f64)], end: Option<f64>) -> Vec<(f64, f64)> {
    let mut out = Vec::with_capacity(points.len() * 2 + 1);
    for (i, &(t, y)) in points.iter().enumerate() {
        if i > 0 {
            out.push((t, points[i - 1].1));
        }
        out.push((t, y));
    }
    if let (Some(&(t_last, y_last)), Some(end)) = (points.last(), end) {
        if end > t_last {
            out.push((end, y_last));
        }
    }
    out
}

/// Trim only leading points that are far outside the following steady-state values.
pub fn remove_leading_outliers(pts: &[(f64, f64)]) -> &[(f64, f64)] {
    let drop_count = leading_outlier_count(pts);
    pts.get(drop_count..).unwrap_or(&[])
}

fn leading_outlier_count(pts: &[(f64, f64)]) -> usize {
    if pts.len() < 8 {
        return 0;
    }

    let candidate_len = pts.len().div_ceil(10).clamp(3, 50).min(pts.len() / 2);
    let tail = &pts[candidate_len..];
    if tail.len() < 5 {
        return 0;
    }

    let mut tail_values: Vec<f64> = tail
        .iter()
        .map(|(_, y)| *y)
        .filter(|y| y.is_finite())
        .collect();
    if tail_values.len() < 5 {
        return 0;
    }
    tail_values.sort_by(f64::total_cmp);

    let q1 = percentile(&tail_values, 0.25);
    let q3 = percentile(&tail_values, 0.75);
    let tail_min = *tail_values.first().unwrap();
    let tail_max = *tail_values.last().unwrap();
    let iqr = q3 - q1;
    let tail_range = tail_max - tail_min;
    let scale = iqr.max(tail_range * 0.25).max(1.0);
    let lower = q1 - scale * 6.0;
    let upper = q3 + scale * 6.0;

    pts.iter()
        .take(candidate_len)
        .take_while(|(_, y)| y.is_finite() && (*y < lower || *y > upper))
        .count()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::{bucket_min_max, expand_steps, remove_leading_outliers};

    #[test]
    fn steps_hold_the_previous_value() {
        let pts = [(1.0, 10.0), (3.0, 5.0), (4.0, 7.0)];
        assert_eq!(
            expand_steps(&pts, Some(6.0)),
            vec![
                (1.0, 10.0),
                (3.0, 10.0),
                (3.0, 5.0),
                (4.0, 5.0),
                (4.0, 7.0),
                (6.0, 7.0)
            ]
        );
        assert_eq!(expand_steps(&pts, Some(2.0)).last(), Some(&(4.0, 7.0)));
        assert!(expand_steps(&[], Some(1.0)).is_empty());
    }

    #[test]
    fn bucketing_keeps_every_level() {
        // 10 000 changes, one deep dip in the middle and the first and last point
        let mut pts: Vec<(f64, f64)> = (0..10_000)
            .map(|i| (i as f64, 100.0 + (i % 3) as f64))
            .collect();
        pts[5_001].1 = 1.0;
        let thin = bucket_min_max(pts.clone(), 400);
        assert!(thin.len() <= 400);
        assert_eq!(thin.first(), pts.first());
        assert_eq!(thin.last(), pts.last());
        assert!(thin.contains(&(5_001.0, 1.0)));
        assert!(thin.windows(2).all(|w| w[0].0 <= w[1].0));
        assert_eq!(bucket_min_max(pts[..10].to_vec(), 400), pts[..10].to_vec());
    }

    #[test]
    fn removes_large_leading_spikes() {
        let pts = vec![
            (0.0, 2_000_000.0),
            (1.0, 1_900_000.0),
            (2.0, 10.0),
            (3.0, 11.0),
            (4.0, 12.0),
            (5.0, 11.0),
            (6.0, 13.0),
            (7.0, 12.0),
            (8.0, 12.0),
            (9.0, 13.0),
        ];

        assert_eq!(remove_leading_outliers(&pts)[0], (2.0, 10.0));
    }

    #[test]
    fn keeps_normal_ramp() {
        let pts: Vec<_> = (0..20).map(|i| (i as f64, 10.0 + i as f64)).collect();

        assert_eq!(remove_leading_outliers(&pts), pts.as_slice());
    }
}
