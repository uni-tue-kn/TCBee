//! How the TUI divides the terminal: what fits at which size, and the fixed widths

use ratatui::layout::{Constraint, Layout, Rect};

use crate::viz::model::CHARTS;

/// Below this size the UI shows only a hint
pub const MIN_WIDTH: u16 = 40;
pub const MIN_HEIGHT: u16 = 12;
/// From this size on, the full left column and four charts
pub const FULL_WIDTH: u16 = 120;
pub const FULL_HEIGHT: u16 = 30;
/// From this size on, a narrow left column and two charts
pub const COMPACT_WIDTH: u16 = 80;
pub const COMPACT_HEIGHT: u16 = 24;
/// Charts of a compact terminal
pub const COMPACT_CHARTS: usize = 2;

/// Width of the left column on full terminals
pub const LEFT_WIDTH: u16 = 42;
/// Width of the narrow left column
pub const NARROW_LEFT_WIDTH: u16 = 30;
/// Width the flow table needs next to the narrow column on a minimal terminal
pub const MIN_FLOWS_WIDTH: u16 = 40;

/// What the terminal has room for
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Fit {
    /// The full left column and four charts
    Full,
    /// A narrow left column and two charts
    Compact,
    /// No charts, sparklines in the group table instead
    Minimal,
}

impl Fit {
    pub fn of(area: Rect) -> Fit {
        if area.width >= FULL_WIDTH && area.height >= FULL_HEIGHT {
            Fit::Full
        } else if area.width >= COMPACT_WIDTH && area.height >= COMPACT_HEIGHT {
            Fit::Compact
        } else {
            Fit::Minimal
        }
    }

    /// Chart slots it shows
    pub fn charts(self) -> usize {
        match self {
            Fit::Full => CHARTS,
            Fit::Compact => COMPACT_CHARTS,
            Fit::Minimal => 0,
        }
    }

    /// The left column leaves out the rec/s columns
    pub fn narrow_column(self) -> bool {
        self != Fit::Full
    }

    /// Width of the left column in a terminal `width` cells wide. On a minimal terminal the
    /// column takes all of it unless the flows get some room next to it.
    pub fn left_width(self, width: u16) -> u16 {
        match self {
            Fit::Full => LEFT_WIDTH,
            Fit::Compact => NARROW_LEFT_WIDTH,
            Fit::Minimal if width >= NARROW_LEFT_WIDTH + MIN_FLOWS_WIDTH => NARROW_LEFT_WIDTH,
            Fit::Minimal => width,
        }
    }
}

/// Areas of `count` charts: one fills the area, two side by side, more in two rows
pub fn grid(area: Rect, count: usize) -> Vec<Rect> {
    let columns = |area: Rect, count: usize| {
        Layout::horizontal(vec![Constraint::Ratio(1, count as u32); count])
            .split(area)
            .to_vec()
    };
    match count {
        0 => Vec::new(),
        1 | 2 => columns(area, count),
        _ => {
            let [top, bottom] = Layout::vertical([Constraint::Ratio(1, 2); 2]).areas(area);
            let mut areas = columns(top, 2);
            areas.extend(columns(bottom, count - 2));
            areas
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_decide_what_fits() {
        let fit = |width, height| Fit::of(Rect::new(0, 0, width, height));
        assert_eq!(fit(120, 30), Fit::Full);
        assert_eq!(fit(160, 29), Fit::Compact);
        assert_eq!(fit(100, 30), Fit::Compact);
        assert_eq!(fit(79, 45), Fit::Minimal);
        assert_eq!(Fit::Full.left_width(120), LEFT_WIDTH);
        assert_eq!(Fit::Minimal.left_width(70), NARROW_LEFT_WIDTH);
        assert_eq!(Fit::Minimal.left_width(69), 69);
    }

    #[test]
    fn grid_fills_the_chart_area() {
        let area = Rect::new(0, 0, 100, 40);
        assert_eq!(grid(area, 1), [area]);
        assert_eq!(
            grid(area, 2),
            [Rect::new(0, 0, 50, 40), Rect::new(50, 0, 50, 40)]
        );
        assert_eq!(grid(area, 3)[2], Rect::new(0, 20, 100, 20));
        assert_eq!(grid(area, 4)[3], Rect::new(50, 20, 50, 20));
    }
}
