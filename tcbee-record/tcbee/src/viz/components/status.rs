//! The left column: run context, health and the probe group table

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame,
};

use crate::viz::{
    format,
    groups::{ring_label, Group},
    model::{Model, RingStats},
    view::View,
};

/// Width of the column on wide terminals
pub const LEFT_WIDTH: u16 = 42;

pub fn render(frame: &mut Frame, model: &Model, view: &View, expanded: bool, area: Rect) {
    let context = context_lines(view);
    let health = health_lines(model);
    let rows = group_rows(model, view, expanded);
    let skipped = &view.context.skipped;
    let [context_area, health_area, groups_area, skipped_area] = Layout::vertical([
        Constraint::Length(context.len() as u16 + 1),
        Constraint::Length(health.len() as u16 + 1),
        // Header and title
        Constraint::Length(rows.len() as u16 + 2),
        Constraint::Min(0),
    ])
    .areas(area);

    let title = Span::styled(
        format!("TCBee {}", format::clock(model.elapsed)),
        Style::default().add_modifier(Modifier::BOLD),
    );
    frame.render_widget(
        Paragraph::new(context).block(Block::new().borders(Borders::TOP).title(title)),
        context_area,
    );
    frame.render_widget(
        Paragraph::new(health).block(Block::new().borders(Borders::TOP).title("Health")),
        health_area,
    );

    let header = ["group", "runs/s", " rec/s", " drops", ""]
        .into_iter()
        .map(Cell::from)
        .collect::<Row>()
        .style(Style::default().add_modifier(Modifier::BOLD));
    let table = Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(0),
        ],
    )
    .header(header)
    .block(
        Block::new()
            .borders(Borders::TOP)
            .title("Probe groups (e: rings)"),
    );
    frame.render_widget(table, groups_area);

    if !skipped.is_empty() {
        let lines: Vec<Line> = skipped
            .iter()
            .map(|reason| Line::from(format!("- {reason}")))
            .collect();
        let paragraph = Paragraph::new(lines)
            .style(Style::default().fg(Color::Yellow))
            .wrap(Wrap { trim: false })
            .block(Block::new().borders(Borders::TOP).title("Skipped"));
        frame.render_widget(paragraph, skipped_area);
    }
}

/// Where and how the run records
fn context_lines(view: &View) -> Vec<Line<'static>> {
    let context = &view.context;
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
        Line::from(setup.join("  ")),
    ]
}

/// Whether the recording keeps up
fn health_lines(model: &Model) -> Vec<Line<'static>> {
    let snap = &model.snapshot;
    let red = Style::default().fg(Color::Red);
    let drop_style = if snap.dropped() > 0 {
        red
    } else {
        Style::default()
    };
    let row = |name: &str, value: String, total: String| format!("{name:<8}{value:>12}  {total}");
    let mut lines = vec![
        Line::from(row(
            "rec/s",
            format::si(model.handled_rate()),
            format!("total {}", format::si(snap.handled() as f64)),
        )),
        Line::from(row("runs/s", format::si(model.runs_rate()), String::new())),
        Line::styled(
            row(
                "drops/s",
                format::si(model.dropped_rate()),
                format!("total {}", format::si(snap.dropped() as f64)),
            ),
            drop_style,
        ),
        Line::styled(
            row(
                "drop %",
                format!("{:.2}%", model.drop_percent_total()),
                format!("now {:.2}%", model.drop_percent()),
            ),
            drop_style,
        ),
        Line::from(row(
            "disk",
            format!("{}/s", format::bytes(model.disk_rate())),
            format::bytes(model.bytes_written as f64),
        )),
    ];
    let mut warnings = Vec::new();
    if snap.state_errors() > 0 {
        warnings.push(format!(
            "{} state_err",
            format::si(snap.state_errors() as f64)
        ));
    }
    if snap.errors() > 0 {
        warnings.push(format!("{} read errors", format::si(snap.errors() as f64)));
    }
    if !warnings.is_empty() {
        lines.push(Line::styled(format!("! {}", warnings.join(", ")), red));
    }
    lines
}

/// One row per active group, and with `expanded` one per ring below
fn group_rows(model: &Model, view: &View, expanded: bool) -> Vec<Row<'static>> {
    let mut rows = Vec::new();
    for row in &model.groups {
        let stats = model.ring_stats(&row.rings);
        let note = match share_note(row.group, &stats, view.context.on_change) {
            Some(note) => note,
            // Groups without a chart get a sparkline instead
            None if !row.charted => format::spark(&row.history, 8),
            None => String::new(),
        };
        rows.push(stats_row(row.group.name().to_string(), &stats, note));
        if expanded {
            for rb in &row.rings {
                let stats = model.ring_stats(&[*rb]);
                let note =
                    share_note(row.group, &stats, view.context.on_change).unwrap_or_default();
                let row = stats_row(format!(" {}", ring_label(*rb)), &stats, note);
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

fn stats_row(name: String, stats: &RingStats, note: String) -> Row<'static> {
    let drops = Cell::from(format!("{:>6}", format::si(stats.drops as f64)));
    let drops = if stats.drops > 0 {
        drops.style(Style::default().fg(Color::Red))
    } else {
        drops
    };
    Row::new([
        Cell::from(name),
        Cell::from(format!("{:>6}", format::si(stats.runs))),
        Cell::from(format!("{:>6}", format::si(stats.records))),
        drops,
        Cell::from(note),
    ])
}
