//! The parts of a series to draw when its pauses should show: the line breaks where no
//! records came for a while, and a value that holds until the next record is drawn faint
//! across the pause.

/// Alpha of a value held across a pause
pub const HELD_ALPHA: f32 = 0.4;
/// Radius of a lone point per px of line width
pub const POINT_RADIUS_PER_WIDTH: f32 = 4.0 / 3.0;

/// A pause between two loaded points this many times longer than usual breaks the line
const GAP_FACTOR: f64 = 20.0;

/// The pause between two loaded points from which on they are not joined: `GAP_FACTOR` times
/// the sampling interval or the median distance of the points, whichever is larger. The median
/// covers points that are thinned out by count instead of by time.
pub fn gap_threshold(points: &[(f64, f64)], sample_interval: f64) -> f64 {
    let mut distances: Vec<f64> = points.windows(2).map(|w| w[1].0 - w[0].0).collect();
    let median = if distances.is_empty() {
        0.0
    } else {
        let mid = distances.len() / 2;
        *distances
            .select_nth_unstable_by(mid, |a, b| a.total_cmp(b))
            .1
    };
    GAP_FACTOR * sample_interval.max(median)
}

/// A part of a plotted series
#[derive(Debug, PartialEq)]
pub struct Segment {
    pub points: Vec<[f64; 2]>,
    /// A value held over a pause without records, drawn faint
    pub held: bool,
}

/// Splits a series where two points are more than `gap` apart. With `step`, each value holds
/// until the next point, as for counters and states, instead of a straight line between them,
/// and a pause does not break the line: the value is held across it in a segment of its own.
pub fn segments(points: &[(f64, f64)], gap: f64, step: bool) -> Vec<Segment> {
    let open = |points| Segment {
        points,
        held: false,
    };
    let mut out: Vec<Segment> = Vec::new();
    let mut previous: Option<(f64, f64)> = None;
    for &(t, v) in points {
        match previous {
            Some((pt, pv)) if t - pt <= gap => {
                let segment = out.last_mut().expect("a segment is open");
                if step && v != pv {
                    segment.points.push([t, pv]);
                }
                segment.points.push([t, v]);
            }
            Some((pt, pv)) if step => {
                out.push(Segment {
                    points: vec![[pt, pv], [t, pv]],
                    held: true,
                });
                out.push(open(if v != pv {
                    vec![[t, pv], [t, v]]
                } else {
                    vec![[t, v]]
                }));
            }
            _ => out.push(open(vec![[t, v]])),
        }
        previous = Some((t, v));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_break_at_gaps() {
        let points = [
            (0.0, 1.0),
            (1.0, 2.0),
            (2.0, 2.0),
            (10.0, 5.0),
            (11.0, 3.0),
            (30.0, 4.0),
        ];
        let lines: Vec<Vec<[f64; 2]>> = segments(&points, 2.0, false)
            .into_iter()
            .map(|s| s.points)
            .collect();
        assert_eq!(
            lines,
            vec![
                vec![[0.0, 1.0], [1.0, 2.0], [2.0, 2.0]],
                vec![[10.0, 5.0], [11.0, 3.0]],
                vec![[30.0, 4.0]],
            ]
        );
        assert!(segments(&[], 2.0, true).is_empty());
    }

    #[test]
    fn steps_hold_their_value_across_a_pause() {
        // cwnd recorded only when it changes: flat from 2 to 10, then down to 5
        let lines = segments(
            &[(0.0, 1.0), (2.0, 4.0), (10.0, 5.0), (30.0, 5.0)],
            3.0,
            true,
        );
        let plain = |points: Vec<[f64; 2]>| Segment {
            points,
            held: false,
        };
        let held = |points: Vec<[f64; 2]>| Segment { points, held: true };
        assert_eq!(
            lines,
            vec![
                plain(vec![[0.0, 1.0], [2.0, 1.0], [2.0, 4.0]]),
                held(vec![[2.0, 4.0], [10.0, 4.0]]),
                plain(vec![[10.0, 4.0], [10.0, 5.0]]),
                held(vec![[10.0, 5.0], [30.0, 5.0]]),
                plain(vec![[30.0, 5.0]]),
            ]
        );
    }

    #[test]
    fn steps_hold_the_value_until_the_next_point() {
        let lines = segments(&[(0.0, 1.0), (1.0, 3.0), (2.0, 3.0), (3.0, 2.0)], 5.0, true);
        assert_eq!(
            lines.into_iter().map(|s| s.points).collect::<Vec<_>>(),
            vec![vec![
                [0.0, 1.0],
                [1.0, 1.0],
                [1.0, 3.0],
                [2.0, 3.0],
                [3.0, 3.0],
                [3.0, 2.0]
            ]]
        );
    }

    #[test]
    fn gap_follows_sampling_or_point_distance() {
        let points: Vec<(f64, f64)> = (0..10).map(|i| (i as f64 * 2.0, 0.0)).collect();
        // Thinned by count: the median distance counts
        assert_eq!(gap_threshold(&points, 0.0), 40.0);
        // Sampled by time with a larger interval
        assert_eq!(gap_threshold(&points, 5.0), 100.0);
        assert_eq!(gap_threshold(&[(1.0, 1.0)], 0.0), 0.0);
    }
}
