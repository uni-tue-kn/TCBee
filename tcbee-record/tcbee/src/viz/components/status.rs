//! The left column: run context, health and the probe group table

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, Padding, Paragraph, Row, Table, Wrap},
    Frame,
};

use crate::viz::{
    context::RunContext,
    format,
    groups::{ring_label, Group},
    layout::Fit,
    model::{Counters, Model, RingStats},
};

/// The column for a terminal of `fit`, narrower than full without the rec/s columns
pub fn render(
    frame: &mut Frame,
    model: &Model,
    run: &RunContext,
    expanded: bool,
    fit: Fit,
    area: Rect,
) {
    let compact = fit.narrow_column();
    // Inside the borders and the padding
    let inner = (area.width as usize).saturating_sub(4);
    let context = context_lines(run);
    let health = health_lines(&model.second, run, inner);
    // What the borders, the padding and the name, rate and drop columns leave
    let fixed = if compact { 27 } else { 37 };
    let spark = (area.width as usize).saturating_sub(fixed).clamp(1, 16);
    let rows = group_rows(model, run, expanded, fit.charts(), compact, spark);
    let skipped = &run.skipped;
    // Each block has a border above and below
    let [context_area, health_area, groups_area, skipped_area] = Layout::vertical([
        Constraint::Length(context.len() as u16 + 2),
        Constraint::Length(health.len() as u16 + 2),
        // And a header
        Constraint::Length(rows.len() as u16 + 3),
        Constraint::Length(skipped_height(&run.skipped, area.width)),
    ])
    .areas(area);

    let title = format!("TCBee  {}", format::clock(model.elapsed()));
    frame.render_widget(
        Paragraph::new(context).block(block(bold_title(title).into())),
        context_area,
    );
    let title = column_title("Health", &HEALTH_LABELS, &HEALTH_WIDTHS, inner);
    frame.render_widget(Paragraph::new(health).block(block(title)), health_area);

    let (header, widths) = if compact {
        (
            vec!["group", "runs/s", " drops", ""],
            vec![
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Min(0),
            ],
        )
    } else {
        (
            vec!["group", "runs/s", " rec/s", " drops", ""],
            vec![
                Constraint::Length(11),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Min(0),
            ],
        )
    };
    let header = header
        .into_iter()
        .map(Cell::from)
        .collect::<Row>()
        .style(Style::default().add_modifier(Modifier::BOLD));
    let table = Table::new(rows, widths)
        .header(header)
        .block(block(bold_title("Probe groups (e: rings)").into()));
    frame.render_widget(table, groups_area);

    if !skipped.is_empty() {
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
        if start < name.width() || end >= cells.len() {
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
fn skipped_height(skipped: &[String], width: u16) -> u16 {
    if skipped.is_empty() {
        return 0;
    }
    // Inside the borders and the padding, and a cell to spare for the word wrap
    let inner = (width as usize).saturating_sub(5).max(1);
    let lines: usize = skipped
        .iter()
        .map(|reason| reason.chars().count().div_ceil(inner).max(1))
        .sum();
    lines as u16 + 2
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
    let taken: usize = widths.iter().map(|width| width + 1).sum();
    let mut row = format!("{name:<0$}", inner.saturating_sub(taken));
    for (value, width) in values.iter().zip(widths) {
        row.push_str(&format!(" {value:>width$}"));
    }
    row
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

/// One row per active group, and with `expanded` one per ring below. Groups whose chart is not
/// among the first `charts` get a sparkline.
fn group_rows(
    model: &Model,
    run: &RunContext,
    expanded: bool,
    charts: usize,
    compact: bool,
    spark: usize,
) -> Vec<Row<'static>> {
    let mut rows = Vec::new();
    for row in &model.groups {
        let stats = model.second.ring_stats(&row.rings);
        let note = match share_note(row.group, &stats, run.on_change) {
            Some(note) => note,
            // Groups without a chart get a sparkline instead
            None if !row.chart.is_some_and(|chart| chart < charts) => {
                format::spark(&row.history, spark)
            }
            None => String::new(),
        };
        rows.push(stats_row(
            row.group.name().to_string(),
            &stats,
            note,
            compact,
        ));
        if expanded {
            for rb in &row.rings {
                let stats = model.second.ring_stats(&[*rb]);
                let note = share_note(row.group, &stats, run.on_change).unwrap_or_default();
                let row = stats_row(format!(" {}", ring_label(*rb)), &stats, note, compact);
                rows.push(row.style(Style::default().add_modifier(Modifier::DIM)));
            }
        }
    }
    rows
}

/// The share of aggregated packets of a header group, or of suppressed runs on change
fn share_note(group: Group, stats: &RingStats, on_change: bool) -> Option<String> {
    match group {
        Group::Headers => Some(format!("agg {:.0}%", stats.aggregated)),
        Group::Sock if on_change => Some(format!("supp {:.0}%", stats.suppressed)),
        _ => None,
    }
}

fn stats_row(name: String, stats: &RingStats, note: String, compact: bool) -> Row<'static> {
    let drops = Cell::from(format!("{:>6}", format::si(stats.drops as f64)));
    let drops = if stats.drops > 0 {
        drops.style(Style::default().fg(Color::Red))
    } else {
        drops
    };
    let runs = Cell::from(format!("{:>6}", format::si(stats.runs)));
    match compact {
        true => Row::new([Cell::from(name), runs, drops, Cell::from(note)]),
        false => Row::new([
            Cell::from(name),
            runs,
            Cell::from(format!("{:>6}", format::si(stats.records))),
            drops,
            Cell::from(note),
        ]),
    }
}
