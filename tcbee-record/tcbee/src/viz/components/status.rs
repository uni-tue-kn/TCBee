//! The left column: run context, health and the probe group table

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
    Frame,
};

use crate::viz::{
    context::RunContext,
    format,
    groups::{ring_label, Group},
    layout::Fit,
    model::{Counters, Model, RingStats, ROW_HISTORY},
};

/// The column for a terminal of `fit`. The groups get sparklines when no chart is shown.
pub fn render(
    frame: &mut Frame,
    model: &Model,
    run: &RunContext,
    expanded: bool,
    fit: Fit,
    area: Rect,
) {
    // Inside the borders and the padding
    let inner = (area.width as usize).saturating_sub(4);
    let context = context_lines(run);
    let health = health_lines(&model.second, run, inner);
    let groups = GroupTable::new(fit, inner);
    let rows = groups.lines(model, run, expanded);
    let skipped = &run.skipped;
    // Each block has a border above and below. On a short terminal the blocks below get
    // what the ones above leave.
    let mut room = area.height;
    let mut take = |lines: usize| {
        let height = (lines as u16).min(room);
        room -= height;
        Constraint::Length(height)
    };
    let [context_area, health_area, groups_area, skipped_area] = Layout::vertical([
        take(context.len() + 2),
        take(health.len() + 2),
        take(rows.len() + 2),
        take(skipped_height(&run.skipped, area.width)),
    ])
    .areas(area);

    let title = format!("TCBee  {}", format::clock(model.elapsed()));
    frame.render_widget(
        Paragraph::new(context).block(block(bold_title(title).into())),
        context_area,
    );
    let title = column_title("Health", &HEALTH_LABELS, &HEALTH_WIDTHS, inner);
    frame.render_widget(Paragraph::new(health).block(block(title)), health_area);

    let title = column_title("Probe groups", &groups.labels(), &groups.widths(), inner);
    frame.render_widget(Paragraph::new(rows).block(block(title)), groups_area);

    // Not just the borders
    if !skipped.is_empty() && skipped_area.height > 2 {
        let lines: Vec<Line> = skipped
            .iter()
            .map(|reason| Line::from(reason.clone()))
            .collect();
        let paragraph = Paragraph::new(lines)
            .style(Style::default().fg(Color::Yellow))
            .wrap(Wrap { trim: false })
            .block(block(bold_title("Skipped").into()));
        frame.render_widget(paragraph, skipped_area);
    }
}

/// A bordered block, its content one cell in from the sides
fn block(title: Line<'_>) -> Block<'_> {
    Block::bordered()
        .title(title)
        .padding(Padding::horizontal(1))
}

/// A block title that stands out from the border: bold, a space on each side
pub fn bold_title(title: impl Into<String>) -> Span<'static> {
    Span::styled(
        format!(" {} ", title.into()),
        Style::default().add_modifier(Modifier::BOLD),
    )
}

/// A block title that names the value columns: the name in bold on the left, each label
/// right-aligned above its column. `widths` are those of the value columns, which end the
/// rows of a content area `inner` cells wide with a space between them. Labels that do not fit
/// next to the name are left out.
pub fn column_title(name: &str, labels: &[&str], widths: &[usize], inner: usize) -> Line<'static> {
    let name = bold_title(name);
    // From corner to corner: a padding cell, the content, a padding cell
    let mut cells = vec!['\u{2500}'; inner + 2];
    let mut end = inner + 1;
    for (label, width) in labels.iter().zip(widths).rev() {
        let label = format!(" {label} ");
        let length = label.chars().count();
        // The label ends one cell after the last of its column, over the padding or the gap
        let Some(start) = (end + 1).checked_sub(length) else {
            break;
        };
        // A label may take the space after the name
        if start + 1 < name.width() || end >= cells.len() {
            break;
        }
        for (cell, char) in cells[start..=end].iter_mut().zip(label.chars()) {
            *cell = char;
        }
        end = end.saturating_sub(width + 1);
    }
    let rest: String = cells.into_iter().skip(name.width()).collect();
    Line::from(vec![name, Span::raw(rest)])
}

/// Lines of the skipped block in a column `width` cells wide, its reasons wrapped
fn skipped_height(skipped: &[String], width: u16) -> usize {
    if skipped.is_empty() {
        return 0;
    }
    // Inside the borders and the padding, and a cell to spare for the word wrap
    let inner = (width as usize).saturating_sub(5).max(1);
    let lines: usize = skipped
        .iter()
        .map(|reason| reason.chars().count().div_ceil(inner).max(1))
        .sum();
    lines + 2
}

/// Where and how the run records
fn context_lines(context: &RunContext) -> Vec<Line<'static>> {
    let mut setup = Vec::new();
    if let Some(iface) = &context.iface {
        setup.push(iface.clone());
    }
    setup.push(format!("{} CPUs", context.cpus));
    if context.on_change {
        setup.push("on change".to_string());
    }
    vec![
        Line::from(context.dir.clone()),
        Line::from(setup.join(" \u{b7} ")),
    ]
}

/// Labels and widths of the value columns of the health block
const HEALTH_LABELS: [&str; 2] = ["now", "total"];
const HEALTH_WIDTHS: [usize; 2] = [9, 7];

/// A row of `name` and values right-aligned in `widths`, in a content area `inner` cells wide
fn columns(name: &str, values: &[String], widths: &[usize], inner: usize) -> String {
    let values = values
        .iter()
        .map(|value| Span::raw(value.clone()))
        .collect();
    styled_columns(Span::raw(name.to_string()), values, widths, inner).to_string()
}

/// `columns` with styled values
fn styled_columns(
    name: Span<'static>,
    values: Vec<Span<'static>>,
    widths: &[usize],
    inner: usize,
) -> Line<'static> {
    let taken: usize = widths.iter().map(|width| width + 1).sum();
    let pad = inner.saturating_sub(taken).saturating_sub(name.width());
    let mut spans = vec![name, Span::raw(" ".repeat(pad))];
    for (value, width) in values.into_iter().zip(widths) {
        let pad = (width + 1).saturating_sub(value.width());
        spans.push(Span::raw(" ".repeat(pad)));
        spans.push(value);
    }
    Line::from(spans)
}

/// Whether the recording keeps up: each row now and since the start, in a content area
/// `inner` cells wide
fn health_lines(counters: &Counters, run: &RunContext, inner: usize) -> Vec<Line<'static>> {
    let snap = &counters.snapshot;
    let red = Style::default().fg(Color::Red);
    let drop_style = if snap.dropped() > 0 {
        red
    } else {
        Style::default()
    };
    let row = |name: &str, now: String, total: String| {
        columns(name, &[now, total], &HEALTH_WIDTHS, inner)
    };
    let mut lines = vec![Line::from(row(
        "records/s",
        format::si(counters.handled_rate()),
        format::si(snap.handled() as f64),
    ))];
    // Runs that write no record are only the dropped ones, but for suppressed runs on change
    if run.on_change {
        lines.push(Line::from(row(
            "runs/s",
            format::si(counters.runs_rate()),
            format::si(counters.runs_total() as f64),
        )));
    }
    lines.extend([
        Line::styled(
            row(
                "drops/s",
                format::si(counters.dropped_rate()),
                format::si(snap.dropped() as f64),
            ),
            drop_style,
        ),
        Line::styled(
            row(
                "drop %",
                format!("{:.2}%", counters.drop_percent()),
                format!("{:.2}%", counters.drop_percent_total()),
            ),
            drop_style,
        ),
        Line::from(row(
            "disk",
            format!("{}/s", format::bytes(counters.disk_rate())),
            format::bytes(counters.bytes_written as f64),
        )),
    ]);
    if snap.state_errors() > 0 {
        let count = format::si(snap.state_errors() as f64);
        lines.push(Line::styled(format!("! {count} state errors"), red));
    }
    if snap.errors() > 0 {
        let count = format::si(snap.errors() as f64);
        lines.push(Line::styled(format!("! {count} read errors"), red));
    }
    lines
}

/// Value columns of the probe group table
const GROUP_LABELS: [&str; 2] = ["rec/s", "drops"];
const GROUP_WIDTHS: [usize; 2] = [6, 6];
/// Width of the group names, the longest is "tracepoints"
const GROUP_NAME_WIDTH: usize = 11;
/// Fewest cells a sparkline gets, and the cells it needs for its full header
const MIN_SPARK: usize = 4;
const FULL_SPARK_HEADER: usize = 9;

/// The probe group table of a column `inner` cells wide inside its padding
struct GroupTable {
    inner: usize,
    /// Cells of the sparkline column, None while charts are shown
    spark: Option<usize>,
}

impl GroupTable {
    /// Sparklines only replace the charts: on a terminal without them, if they fit
    fn new(fit: Fit, inner: usize) -> GroupTable {
        let taken = GROUP_NAME_WIDTH + GROUP_WIDTHS.iter().map(|width| width + 1).sum::<usize>();
        let room = inner.saturating_sub(taken + 1).min(ROW_HISTORY);
        GroupTable {
            inner,
            spark: (fit.charts() == 0 && room >= MIN_SPARK).then_some(room),
        }
    }

    fn labels(&self) -> Vec<&'static str> {
        let mut labels = GROUP_LABELS.to_vec();
        match self.spark {
            Some(width) if width >= FULL_SPARK_HEADER => labels.push("last 30 s"),
            Some(_) => labels.push("30 s"),
            None => {}
        }
        labels
    }

    fn widths(&self) -> Vec<usize> {
        let mut widths = GROUP_WIDTHS.to_vec();
        widths.extend(self.spark);
        widths
    }

    /// A line per active group, below the shares it has; with `expanded` a dimmed line per
    /// ring; and the key that shows or hides them
    fn lines(&self, model: &Model, run: &RunContext, expanded: bool) -> Vec<Line<'static>> {
        let dim = Style::default().add_modifier(Modifier::DIM);
        let mut lines = Vec::new();
        for row in &model.groups {
            let stats = model.second.ring_stats(&row.rings);
            let mut values = stat_spans(&stats);
            if let Some(width) = self.spark {
                values.push(Span::raw(spark(&row.history, width)));
            }
            let name = Span::raw(row.group.name());
            lines.push(styled_columns(name, values, &self.widths(), self.inner));
            if let Some(share) = share(row.group, &stats, run.on_change) {
                lines.push(Line::styled(format!("  {share}"), dim));
            }
            if expanded {
                for rb in &row.rings {
                    let stats = model.second.ring_stats(&[*rb]);
                    let name = Span::raw(format!("  {}", ring_label(*rb)));
                    let mut values = stat_spans(&stats);
                    // The sparkline column stays empty
                    if self.spark.is_some() {
                        values.push(Span::raw(""));
                    }
                    let line = styled_columns(name, values, &self.widths(), self.inner);
                    lines.push(line.style(dim));
                }
            }
        }
        let key = if expanded {
            "e: hide rings"
        } else {
            "e: show rings"
        };
        lines.push(Line::styled(key, dim));
        lines
    }
}

/// The rate of records and the drops of some rings, a dim dot for nothing
fn stat_spans(stats: &RingStats) -> Vec<Span<'static>> {
    let dot = || Span::styled("\u{b7}", Style::default().add_modifier(Modifier::DIM));
    let records = match stats.records {
        0.0 => dot(),
        records => Span::raw(format::si(records)),
    };
    let drops = match stats.drops {
        0 => dot(),
        drops => Span::styled(format::si(drops as f64), Style::default().fg(Color::Red)),
    };
    vec![records, drops]
}

/// The share of header packets that stand for several segments, or of the socket hook runs
/// suppressed on change, both since the start
fn share(group: Group, stats: &RingStats, on_change: bool) -> Option<String> {
    match group {
        Group::Headers => Some(format!("{:.0}% aggregated", stats.aggregated)),
        Group::Sock if on_change => Some(format!("{:.0}% suppressed", stats.suppressed)),
        _ => None,
    }
}

/// A sparkline of the last seconds in `width` cells: each cell the maximum of its seconds
fn spark(history: &[f64], width: usize) -> String {
    let seconds = history.len().div_ceil(width.max(1)).max(1);
    let cells: Vec<f64> = history
        .chunks(seconds)
        .map(|chunk| chunk.iter().copied().fold(0.0, f64::max))
        .collect();
    format::spark(&cells, width)
}
