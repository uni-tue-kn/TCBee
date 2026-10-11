//! Overview of the open database: what wrote it and, for recordings made with
//! `tcbee-record --metadata`, the run metadata from the `run.*` meta rows: host, kernel, probes,
//! clocks, sysctls, interfaces and the counters at start and stop.

use std::collections::BTreeMap;

use egui::{CollapsingHeader, Grid, RichText, ScrollArea};

use crate::{backend::db::DbBackend, settings::AppSettings, ui::theme};

/// Shown when the database has no run metadata
pub const NO_METADATA_HINT: &str =
    "This recording has no run metadata. Record with tcbee-record --metadata to see the host, \
     kernel, sysctls, interfaces, clocks and drop counters here.";

/// Meta keys of the database itself, shown first
const FILE_KEYS: [(&str, &str); 4] = [
    ("writer", "Writer"),
    ("trace_dir", "Trace directory"),
    ("created_at", "Created"),
    ("schema_version", "Schema version"),
];

/// A titled list of key/value rows
#[derive(Debug, PartialEq)]
pub struct Section {
    pub title: &'static str,
    pub rows: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Default)]
pub struct Table {
    pub header: Vec<&'static str>,
    pub rows: Vec<Vec<String>>,
}

/// Everything the tab shows, built from the meta rows
#[derive(Debug, PartialEq, Default)]
pub struct Overview {
    pub file: Vec<(String, String)>,
    pub has_metadata: bool,
    pub sections: Vec<Section>,
    pub interfaces: Table,
    /// Kernel and interface counters that changed between start and stop
    pub counters: Table,
    /// The recorder's own event counters at stop
    pub recorder_counters: Table,
    /// All `run.*` rows as stored
    pub all: Vec<(String, String)>,
}

/// The `run.*` rows without the prefix
struct RunMeta<'a> {
    rows: BTreeMap<&'a str, &'a str>,
}

impl<'a> RunMeta<'a> {
    fn new(meta: &'a [(String, String)]) -> Self {
        let rows = meta
            .iter()
            .filter_map(|(k, v)| Some((k.strip_prefix("run.")?, v.as_str())))
            .collect();
        Self { rows }
    }

    fn get(&self, key: &str) -> Option<&'a str> {
        self.rows.get(key).copied()
    }

    fn int(&self, key: &str) -> Option<i64> {
        self.get(key)?.parse().ok()
    }

    /// Members below `prefix` as (rest of the key, value)
    fn below(&self, prefix: &str) -> Vec<(&'a str, &'a str)> {
        let prefix = format!("{prefix}.");
        self.rows
            .iter()
            .filter_map(|(&k, &v)| Some((k.strip_prefix(prefix.as_str())?, v)))
            .collect()
    }

    /// Number of elements of the array at `prefix`
    fn len(&self, prefix: &str) -> usize {
        (0..)
            .take_while(|i| !self.below(&format!("{prefix}.{i}")).is_empty())
            .count()
    }

    /// The array at `prefix` joined with `sep`
    fn joined(&self, prefix: &str, sep: &str) -> Option<String> {
        let items: Vec<&str> = (0..self.len_scalar(prefix))
            .filter_map(|i| self.get(&format!("{prefix}.{i}")))
            .collect();
        (!items.is_empty()).then(|| items.join(sep))
    }

    /// Number of elements of an array of plain values at `prefix`
    fn len_scalar(&self, prefix: &str) -> usize {
        (0..)
            .take_while(|i| self.get(&format!("{prefix}.{i}")).is_some())
            .count()
    }
}

fn push(rows: &mut Vec<(String, String)>, label: &str, value: Option<String>) {
    if let Some(value) = value {
        rows.push((label.to_string(), value));
    }
}

fn yes_no(value: Option<&str>) -> String {
    match value {
        Some("true") => "on".to_string(),
        Some("false") => "off".to_string(),
        _ => "–".to_string(),
    }
}

/// UTC date and time of nanoseconds since the Unix epoch
fn format_utc(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        day_secs / 3600,
        day_secs / 60 % 60,
        day_secs % 60
    )
}

fn host_section(m: &RunMeta) -> Section {
    let mut rows = Vec::new();
    push(
        &mut rows,
        "Hostname",
        m.get("host.hostname").map(str::to_string),
    );
    push(
        &mut rows,
        "Kernel",
        m.get("kernel.release").map(str::to_string),
    );
    push(
        &mut rows,
        "Kernel build",
        m.get("kernel.version").map(str::to_string),
    );
    push(
        &mut rows,
        "Machine",
        m.get("kernel.machine").map(str::to_string),
    );
    push(
        &mut rows,
        "CPUs online",
        m.get("host.cpus_online").map(str::to_string),
    );
    push(
        &mut rows,
        "Network namespace",
        m.get("host.netns").map(str::to_string),
    );
    push(
        &mut rows,
        "Boot id",
        m.get("host.boot_id").map(str::to_string),
    );
    Section {
        title: "Host and kernel",
        rows,
    }
}

fn recording_section(m: &RunMeta) -> Section {
    let mut rows = Vec::new();
    push(&mut rows, "Command", m.joined("recorder.argv", " "));
    push(&mut rows, "Probe groups", m.joined("recorder.groups", ", "));
    push(
        &mut rows,
        "Interface",
        m.get("recorder.interface").map(str::to_string),
    );
    push(&mut rows, "Skipped", m.joined("recorder.skipped", "; "));
    let sizes: Vec<String> = m
        .below("recorder.ringbuf_sizes")
        .into_iter()
        .map(|(name, bytes)| match bytes.parse::<u64>() {
            Ok(b) if b >= 1 << 20 => format!("{name} {} MiB", b >> 20),
            Ok(b) => format!("{name} {} KiB", b >> 10),
            Err(_) => format!("{name} {bytes}"),
        })
        .collect();
    push(
        &mut rows,
        "Ring buffers per CPU",
        (!sizes.is_empty()).then(|| sizes.join(", ")),
    );
    Section {
        title: "Recording",
        rows,
    }
}

fn clock_section(m: &RunMeta) -> Section {
    let mut rows = Vec::new();
    let mono = |at: &str| m.int(&format!("{at}.clock.monotonic_ns"));
    let offset = |at: &str, clock: &str| m.int(&format!("{at}.clock.{clock}_minus_monotonic_ns"));
    if let (Some(t), Some(off)) = (mono("start"), offset("start", "realtime")) {
        rows.push(("Start".to_string(), format_utc(t + off)));
    }
    if let (Some(t), Some(off)) = (mono("stop"), offset("stop", "realtime")) {
        rows.push(("Stop".to_string(), format_utc(t + off)));
    }
    if let (Some(start), Some(stop)) = (mono("start"), mono("stop")) {
        rows.push((
            "Duration".to_string(),
            format!("{:.3} s", (stop - start) as f64 / 1e9),
        ));
    }
    if let Some(off) = offset("start", "realtime") {
        let uncertainty = m.int("start.clock.uncertainty_ns").unwrap_or(0);
        rows.push((
            "REALTIME − MONOTONIC".to_string(),
            format!("{off} ns ± {uncertainty} ns"),
        ));
    }
    if let (Some(start), Some(stop)) = (offset("start", "realtime"), offset("stop", "realtime")) {
        rows.push((
            "REALTIME offset drift".to_string(),
            format!("{:.1} µs", (stop - start) as f64 / 1e3),
        ));
    }
    if let (Some(tai), Some(real)) = (offset("start", "tai"), offset("start", "realtime")) {
        rows.push((
            "TAI − REALTIME".to_string(),
            format!("{:.0} s", (tai - real) as f64 / 1e9),
        ));
    }
    if let Some(sync) = m.get("start.ntp.synchronized") {
        let state = if sync == "true" { "yes" } else { "no" };
        let error = m
            .get("start.ntp.esterror_us")
            .map_or(String::new(), |e| format!(", estimated error {e} µs"));
        rows.push(("NTP synchronized".to_string(), format!("{state}{error}")));
    }
    Section {
        title: "Clocks",
        rows,
    }
}

fn interface_table(m: &RunMeta) -> Table {
    let rows = (0..m.len("interfaces"))
        .map(|i| {
            let get = |key: &str| m.get(&format!("interfaces.{i}.{key}"));
            let text = |key: &str| get(key).unwrap_or("–").to_string();
            let mut kinds: Vec<(&str, usize)> = Vec::new();
            for q in 0..m.len(&format!("interfaces.{i}.qdiscs")) {
                if let Some(kind) = get(&format!("qdiscs.{q}.kind")) {
                    match kinds.iter_mut().find(|(k, _)| *k == kind) {
                        Some((_, n)) => *n += 1,
                        None => kinds.push((kind, 1)),
                    }
                }
            }
            let qdiscs: Vec<String> = kinds
                .iter()
                .map(|(kind, n)| match n {
                    1 => kind.to_string(),
                    n => format!("{kind} ×{n}"),
                })
                .collect();
            vec![
                text("name"),
                text("mtu"),
                get("speed").map_or("–".to_string(), |s| format!("{s} Mb/s")),
                text("operstate"),
                yes_no(get("offloads.tso")),
                yes_no(get("offloads.gso")),
                yes_no(get("offloads.gro")),
                yes_no(get("offloads.lro")),
                if qdiscs.is_empty() {
                    "–".to_string()
                } else {
                    qdiscs.join(", ")
                },
            ]
        })
        .collect();
    Table {
        header: vec![
            "Interface",
            "MTU",
            "Speed",
            "State",
            "TSO",
            "GSO",
            "GRO",
            "LRO",
            "Qdiscs",
        ],
        rows,
    }
}

/// Numeric counters of the start sample that changed until stop. Clock, NTP and the recorder's
/// counters are shown elsewhere; interface drops are labelled with the interface name.
fn counter_table(m: &RunMeta) -> Table {
    let mut rows = Vec::new();
    for (key, start) in m.below("start") {
        if ["clock.", "ntp.", "tcbee."]
            .iter()
            .any(|skip| key.starts_with(skip))
        {
            continue;
        }
        let (Ok(start), Some(stop)) = (start.parse::<i64>(), m.int(&format!("stop.{key}"))) else {
            continue;
        };
        if stop == start {
            continue;
        }
        let label = match key.strip_prefix("interface_drops.") {
            Some(rest) => {
                let (index, counter) = rest.split_once('.').unwrap_or((rest, ""));
                let name = m
                    .get(&format!("start.interface_drops.{index}.name"))
                    .unwrap_or(index);
                format!("{name} {counter}")
            }
            None => key.to_string(),
        };
        rows.push(vec![
            label,
            start.to_string(),
            stop.to_string(),
            format!("{:+}", stop - start),
        ]);
    }
    Table {
        header: vec!["Counter", "Start", "Stop", "Change"],
        rows,
    }
}

fn recorder_counter_table(m: &RunMeta) -> Table {
    let rows = (0..m.len("stop.tcbee"))
        .map(|i| {
            ["name", "attempted", "handled", "dropped", "error"]
                .iter()
                .map(|key| {
                    m.get(&format!("stop.tcbee.{i}.{key}"))
                        .unwrap_or("–")
                        .to_string()
                })
                .collect()
        })
        .collect();
    Table {
        header: vec!["Ring buffer", "Attempted", "Handled", "Dropped", "Error"],
        rows,
    }
}

impl Overview {
    pub fn new(meta: &[(String, String)]) -> Self {
        let file = FILE_KEYS
            .iter()
            .filter_map(|(key, label)| {
                let (_, value) = meta.iter().find(|(k, _)| k == key)?;
                Some((label.to_string(), value.clone()))
            })
            .collect();
        let m = RunMeta::new(meta);
        if m.rows.is_empty() {
            return Self {
                file,
                ..Self::default()
            };
        }
        let sysctls = m
            .below("sysctls")
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self {
            file,
            has_metadata: true,
            sections: vec![
                host_section(&m),
                recording_section(&m),
                clock_section(&m),
                Section {
                    title: "TCP sysctls",
                    rows: sysctls,
                },
            ],
            interfaces: interface_table(&m),
            counters: counter_table(&m),
            recorder_counters: recorder_counter_table(&m),
            all: m
                .rows
                .iter()
                .map(|(k, v)| (format!("run.{k}"), v.to_string()))
                .collect(),
        }
    }
}

#[derive(Default)]
pub struct TabOverview {
    /// Built once per database; the meta rows never change while a file is open
    overview: Option<Overview>,
}

impl TabOverview {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn show(&mut self, ui: &mut egui::Ui, db: &DbBackend, settings: &AppSettings) {
        if !db.is_connected() {
            ui.centered_and_justified(|ui| {
                ui.label("No database loaded. Go to Home and select a database file.");
            });
            return;
        }
        let overview = self
            .overview
            .get_or_insert_with(|| Overview::new(db.meta()));
        let muted = theme::muted_text(settings.dark_mode);

        ScrollArea::vertical()
            .id_salt("overview_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Frame::NONE
                    .inner_margin(egui::Margin::symmetric(16, 12))
                    .show(ui, |ui| {
                        ui.heading("Database");
                        key_value_grid(ui, "overview_file", &overview.file);
                        ui.add_space(12.0);
                        if !overview.has_metadata {
                            ui.label(RichText::new(NO_METADATA_HINT).color(muted));
                            return;
                        }
                        for section in &overview.sections {
                            CollapsingHeader::new(RichText::new(section.title).strong())
                                .default_open(true)
                                .show(ui, |ui| {
                                    if section.rows.is_empty() {
                                        ui.label(RichText::new("Not recorded").color(muted));
                                    } else {
                                        key_value_grid(ui, section.title, &section.rows);
                                    }
                                });
                        }
                        let tables = [
                            (
                                "Interfaces",
                                &overview.interfaces,
                                "No interface was described.",
                            ),
                            (
                                "Counters changed during the recording",
                                &overview.counters,
                                "No counter changed, or the stop sample is missing.",
                            ),
                            (
                                "Recorder event counters",
                                &overview.recorder_counters,
                                "No stop sample: the recorder did not stop cleanly.",
                            ),
                        ];
                        for (title, table, empty) in tables {
                            CollapsingHeader::new(RichText::new(title).strong())
                                .default_open(true)
                                .show(ui, |ui| {
                                    if table.rows.is_empty() {
                                        ui.label(RichText::new(empty).color(muted));
                                    } else {
                                        table_grid(ui, title, table);
                                    }
                                });
                        }
                        CollapsingHeader::new(RichText::new("All metadata entries").strong())
                            .default_open(false)
                            .show(ui, |ui| key_value_grid(ui, "overview_all", &overview.all));
                    });
            });
    }
}

fn key_value_grid(ui: &mut egui::Ui, id: &str, rows: &[(String, String)]) {
    Grid::new(id)
        .num_columns(2)
        .striped(true)
        .spacing([24.0, 4.0])
        .show(ui, |ui| {
            for (key, value) in rows {
                ui.label(RichText::new(key).strong());
                ui.label(value);
                ui.end_row();
            }
        });
}

fn table_grid(ui: &mut egui::Ui, id: &str, table: &Table) {
    Grid::new(id)
        .num_columns(table.header.len())
        .striped(true)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            for title in &table.header {
                ui.label(RichText::new(*title).strong());
            }
            ui.end_row();
            for row in &table.rows {
                for cell in row {
                    ui.label(cell);
                }
                ui.end_row();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(rows: &[(&str, &str)]) -> Vec<(String, String)> {
        rows.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn without_run_rows_only_the_file_is_shown() {
        let o = Overview::new(&meta(&[
            ("schema_version", "3"),
            ("writer", "tcbee-process 0.1.0"),
        ]));
        assert!(!o.has_metadata);
        assert_eq!(
            o.file,
            vec![
                ("Writer".into(), "tcbee-process 0.1.0".into()),
                ("Schema version".into(), "3".into())
            ]
        );
        assert!(o.sections.is_empty());
    }

    #[test]
    fn run_rows_fill_sections_and_tables() {
        let o = Overview::new(&meta(&[
            ("run.format", "1"),
            ("run.host.hostname", "tcp1"),
            ("run.kernel.release", "6.8.0"),
            ("run.recorder.argv.0", "tcbee-record"),
            ("run.recorder.argv.1", "-k"),
            ("run.recorder.groups.0", "kernel"),
            (
                "run.recorder.ringbuf_sizes.TCP_SEND_SOCK_EVENTS",
                "16777216",
            ),
            ("run.sysctls.net.ipv4.tcp_congestion_control", "cubic"),
            ("run.interfaces.0.name", "eth0.100"),
            ("run.interfaces.0.mtu", "1500"),
            ("run.interfaces.0.offloads.tso", "true"),
            ("run.interfaces.0.offloads.lro", "false"),
            ("run.interfaces.0.qdiscs.0.kind", "mq"),
            ("run.interfaces.0.qdiscs.1.kind", "fq_codel"),
            ("run.interfaces.0.qdiscs.2.kind", "fq_codel"),
            ("run.start.clock.monotonic_ns", "1000000000"),
            (
                "run.start.clock.realtime_minus_monotonic_ns",
                "1759999999000000000",
            ),
            (
                "run.start.clock.tai_minus_monotonic_ns",
                "1760000036000000000",
            ),
            ("run.start.clock.uncertainty_ns", "120"),
            ("run.stop.clock.monotonic_ns", "3500000000"),
            (
                "run.stop.clock.realtime_minus_monotonic_ns",
                "1759999999000002000",
            ),
            ("run.start.tcp.TcpExt.TCPTimeouts", "4"),
            ("run.stop.tcp.TcpExt.TCPTimeouts", "9"),
            ("run.start.tcp.Tcp.ActiveOpens", "7"),
            ("run.stop.tcp.Tcp.ActiveOpens", "7"),
            ("run.start.interface_drops.0.name", "eth0.100"),
            ("run.start.interface_drops.0.rx_dropped", "1"),
            ("run.stop.interface_drops.0.name", "eth0.100"),
            ("run.stop.interface_drops.0.rx_dropped", "3"),
            ("run.stop.tcbee.0.name", "TCP_SEND_SOCK_EVENTS"),
            ("run.stop.tcbee.0.attempted", "10"),
            ("run.stop.tcbee.0.handled", "9"),
            ("run.stop.tcbee.0.dropped", "1"),
            ("run.stop.tcbee.0.error", "0"),
        ]));
        assert!(o.has_metadata);
        let section = |title: &str| {
            o.sections
                .iter()
                .find(|s| s.title == title)
                .unwrap_or_else(|| panic!("no section {title}"))
        };
        let value = |title: &str, key: &str| {
            section(title)
                .rows
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("no {key} in {title}"))
        };
        assert_eq!(value("Host and kernel", "Kernel"), "6.8.0");
        assert_eq!(value("Recording", "Command"), "tcbee-record -k");
        assert_eq!(
            value("Recording", "Ring buffers per CPU"),
            "TCP_SEND_SOCK_EVENTS 16 MiB"
        );
        assert_eq!(value("Clocks", "Start"), "2025-10-09 08:53:20 UTC");
        assert_eq!(value("Clocks", "Duration"), "2.500 s");
        assert_eq!(
            value("Clocks", "REALTIME − MONOTONIC"),
            "1759999999000000000 ns ± 120 ns"
        );
        assert_eq!(value("Clocks", "REALTIME offset drift"), "2.0 µs");
        assert_eq!(value("Clocks", "TAI − REALTIME"), "37 s");
        assert_eq!(
            section("TCP sysctls").rows,
            vec![("net.ipv4.tcp_congestion_control".into(), "cubic".into())]
        );
        assert_eq!(
            o.interfaces.rows,
            vec![vec![
                "eth0.100",
                "1500",
                "–",
                "–",
                "on",
                "–",
                "–",
                "off",
                "mq, fq_codel ×2"
            ]]
        );
        assert_eq!(
            o.counters.rows,
            vec![
                vec!["eth0.100 rx_dropped", "1", "3", "+2"],
                vec!["tcp.TcpExt.TCPTimeouts", "4", "9", "+5"],
            ]
        );
        assert_eq!(
            o.recorder_counters.rows,
            vec![vec!["TCP_SEND_SOCK_EVENTS", "10", "9", "1", "0"]]
        );
        assert_eq!(o.all.len(), 34);
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            format_utc(951_782_400_000_000_000),
            "2000-02-29 00:00:00 UTC"
        );
        assert_eq!(format_utc(-1_000_000_000), "1969-12-31 23:59:59 UTC");
    }
}
