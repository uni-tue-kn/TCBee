use std::sync::mpsc::{Receiver, SyncSender};

use egui::{RichText, ScrollArea};
use egui_plot::{Legend, Line, Plot, PlotBounds, PlotPoints};
use indexmap::IndexMap;
use tcbee_live_common::tcp_sock::FlowKey;

use crate::types::{CwndEvent, FilterCmd, FlowData, PALETTE, SAMPLE_INTERVAL_NS};

pub struct TcbeeApp {
    _rt: tokio::runtime::Runtime,
    event_rx: Receiver<CwndEvent>,
    disc_rx: Receiver<FlowKey>,
    filter_tx: SyncSender<FilterCmd>,
    flows: IndexMap<FlowKey, FlowData>,
    filter_text: String,
    t0: Option<u64>,
    now_secs: f64,
    color_idx: usize,
    select_ports: std::collections::HashSet<u16>,
    combined_plot: bool,
    auto_fit_x: bool,
    dark_mode: bool,
}

impl TcbeeApp {
    pub fn new(
        rt: tokio::runtime::Runtime,
        event_rx: Receiver<CwndEvent>,
        disc_rx: Receiver<FlowKey>,
        filter_tx: SyncSender<FilterCmd>,
        select_ports: std::collections::HashSet<u16>,
        combined_plot: bool,
        auto_fit_x: bool,
    ) -> Self {
        TcbeeApp {
            _rt: rt,
            event_rx,
            disc_rx,
            filter_tx,
            flows: IndexMap::new(),
            filter_text: String::new(),
            t0: None,
            now_secs: 0.0,
            color_idx: 0,
            select_ports,
            combined_plot,
            auto_fit_x,
            dark_mode: true,
        }
    }

    fn drain_channels(&mut self) {
        while let Ok(key) = self.disc_rx.try_recv() {
            let flow = self.flows.entry(key).or_insert_with(|| {
                let color = PALETTE[self.color_idx % PALETTE.len()];
                self.color_idx += 1;
                FlowData::new(&key, color)
            });
            if !flow.selected
                && (self.select_ports.contains(&key.src_port)
                    || self.select_ports.contains(&key.dst_port))
            {
                flow.selected = true;
                let _ = self.filter_tx.try_send(FilterCmd::Add(key));
            }
        }

        while let Ok(ev) = self.event_rx.try_recv() {
            let t0 = *self.t0.get_or_insert(ev.time_ns);
            if let Some(flow) = self.flows.get_mut(&ev.key) {
                if ev.time_ns.saturating_sub(flow.last_sample_ns) >= SAMPLE_INTERVAL_NS {
                    let t_sec = (ev.time_ns.saturating_sub(t0)) as f64 / 1e9;
                    flow.points.push([t_sec, ev.snd_cwnd as f64]);
                    flow.last_sample_ns = ev.time_ns;
                    if t_sec > self.now_secs {
                        self.now_secs = t_sec;
                    }
                }
            }
        }
    }
}

impl eframe::App for TcbeeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        self.drain_channels();

        egui::SidePanel::right("flows_panel")
            .resizable(true)
            .default_width(280.0)
            .show(ctx, |ui: &mut egui::Ui| {
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.heading("TCP Flows");
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            let icon = if self.dark_mode { "\u{2600}" } else { "\u{263E}" };
                            if ui
                                .small_button(icon)
                                .on_hover_text("Toggle theme")
                                .clicked()
                            {
                                self.dark_mode = !self.dark_mode;
                            }
                        },
                    );
                });

                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter_text)
                        .hint_text("Filter by port or IP\u{2026}")
                        .desired_width(f32::INFINITY),
                );

                let total = self.flows.len();
                let selected_count = self.flows.values().filter(|f| f.selected).count();
                if total > 0 {
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(format!("{selected_count} of {total} selected"))
                            .small()
                            .weak(),
                    );
                }

                ui.separator();

                ScrollArea::vertical()
                    .max_height((ui.available_height() - 100.0).max(60.0))
                    .show(ui, |ui: &mut egui::Ui| {
                        ui.add_space(2.0);
                        let keys: Vec<FlowKey> = self.flows.keys().copied().collect();
                        for key in keys {
                            let flow = self.flows.get_mut(&key).unwrap();
                            if !self.filter_text.is_empty()
                                && !flow.label.contains(&self.filter_text)
                            {
                                continue;
                            }
                            let was = flow.selected;
                            let color = flow.color;
                            let label = flow.label.clone();

                            ui.horizontal(|ui| {
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(10.0, 10.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().rect_filled(rect, 2.0, color);
                                ui.add_space(2.0);
                                ui.checkbox(&mut flow.selected, label);
                            });

                            if flow.selected != was {
                                let cmd = if flow.selected {
                                    FilterCmd::Add(key)
                                } else {
                                    FilterCmd::Remove(key)
                                };
                                let _ = self.filter_tx.try_send(cmd);
                            }
                        }
                        ui.add_space(2.0);
                    });

                ui.separator();

                ui.group(|ui| {
                    ui.label(RichText::new("View").strong());
                    ui.add_space(4.0);
                    ui.checkbox(&mut self.combined_plot, "Combined plot");
                    ui.checkbox(&mut self.auto_fit_x, "Auto fit x-axis");
                    if self.auto_fit_x {
                        ui.label(
                            RichText::new("x: 0 \u{2192} now (locked)")
                                .small()
                                .weak(),
                        );
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui: &mut egui::Ui| {
            let selected: Vec<(&FlowKey, &FlowData)> =
                self.flows.iter().filter(|(_, f)| f.selected).collect();

            if selected.is_empty() {
                ui.centered_and_justified(|ui: &mut egui::Ui| {
                    ui.label(
                        RichText::new(
                            "Select a flow in the panel on the right to display its cwnd graph.",
                        )
                        .weak(),
                    );
                });
                return;
            }

            let now = self.now_secs;
            let shared = self.auto_fit_x;

            let shared_bounds = shared.then(|| {
                let max_cwnd = selected
                    .iter()
                    .flat_map(|(_, f)| f.points.iter().map(|p| p[1]))
                    .fold(0.0_f64, f64::max);
                PlotBounds::from_min_max([0.0, 0.0], [now, max_cwnd * 1.05])
            });

            if self.combined_plot {
                Plot::new("cwnd_combined")
                    .x_axis_label("time (s)")
                    .y_axis_label("cwnd (segments)")
                    .legend(Legend::default())
                    .show(ui, |plot_ui| {
                        if let Some(b) = shared_bounds {
                            plot_ui.set_plot_bounds(b);
                        }
                        for (_, flow) in &selected {
                            let pts: PlotPoints = flow.points.iter().copied().collect();
                            plot_ui.line(Line::new(pts).color(flow.color).name(&flow.label));
                        }
                    });
            } else {
                let plot_height =
                    (ui.available_height() / selected.len() as f32).max(80.0);
                for (key, flow) in &selected {
                    let pts: PlotPoints = flow.points.iter().copied().collect();
                    let line = Line::new(pts).color(flow.color).name(&flow.label);
                    Plot::new(format!("cwnd_{:?}", key))
                        .height(plot_height)
                        .x_axis_label("time (s)")
                        .y_axis_label("cwnd (segments)")
                        .show(ui, |plot_ui| {
                            if let Some(b) = shared_bounds {
                                plot_ui.set_plot_bounds(b);
                            }
                            plot_ui.line(line);
                        });
                }
            }
        });
    }
}
