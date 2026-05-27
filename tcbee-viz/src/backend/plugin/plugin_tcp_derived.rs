use ts_storage::DataValue;

use crate::data::series_data::SeriesData;

use super::trait_plugin::Plugin;

const TCP_FIN: i64 = 0x01;
const TCP_SYN: i64 = 0x02;
const TCP_RST: i64 = 0x04;
const TCP_PSH: i64 = 0x08;
const TCP_ACK: i64 = 0x10;

pub struct BytesInFlightPlugin;

impl Default for BytesInFlightPlugin {
    fn default() -> Self {
        Self
    }
}

impl Plugin for BytesInFlightPlugin {
    fn name(&self) -> &str {
        "Bytes In Flight"
    }

    fn description(&self) -> &str {
        "Calculates BYTES_IN_FLIGHT = SND_NXT - SND_UNA, handling TCP sequence wraparound."
    }

    fn required_series(&self) -> Vec<String> {
        vec!["SND_NXT".to_string(), "SND_UNA".to_string()]
    }

    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String> {
        let snd_nxt = input.first().ok_or("Missing SND_NXT series")?;
        let snd_una = input.get(1).ok_or("Missing SND_UNA series")?;
        let raw_data = snd_nxt
            .raw_data
            .iter()
            .zip(&snd_una.raw_data)
            .filter_map(|((t, nxt), (_, una))| {
                let nxt = value_as_u32(nxt)?;
                let una = value_as_u32(una)?;
                Some((*t, DataValue::Int(nxt.wrapping_sub(una) as i64)))
            })
            .collect::<Vec<_>>();

        Ok(vec![int_series(
            "BYTES_IN_FLIGHT",
            snd_nxt,
            raw_data,
            egui::Color32::from_rgb(90, 160, 220),
        )])
    }
}

pub struct UsableSendWindowPlugin;

impl Default for UsableSendWindowPlugin {
    fn default() -> Self {
        Self
    }
}

impl Plugin for UsableSendWindowPlugin {
    fn name(&self) -> &str {
        "Usable Send Window"
    }

    fn description(&self) -> &str {
        "Calculates USABLE_SND_WND = SND_UNA + SND_WND - SND_NXT."
    }

    fn required_series(&self) -> Vec<String> {
        vec![
            "SND_UNA".to_string(),
            "SND_WND".to_string(),
            "SND_NXT".to_string(),
        ]
    }

    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String> {
        let snd_una = input.first().ok_or("Missing SND_UNA series")?;
        let snd_wnd = input.get(1).ok_or("Missing SND_WND series")?;
        let snd_nxt = input.get(2).ok_or("Missing SND_NXT series")?;
        let raw_data = snd_una
            .raw_data
            .iter()
            .zip(&snd_wnd.raw_data)
            .zip(&snd_nxt.raw_data)
            .filter_map(|(((t, una), (_, wnd)), (_, nxt))| {
                let una = value_as_u32(una)?;
                let wnd = value_as_u32(wnd)?;
                let nxt = value_as_u32(nxt)?;
                let upper = una.wrapping_add(wnd);
                Some((*t, DataValue::Int(upper.wrapping_sub(nxt) as i64)))
            })
            .collect::<Vec<_>>();

        Ok(vec![int_series(
            "USABLE_SND_WND",
            snd_una,
            raw_data,
            egui::Color32::from_rgb(220, 160, 80),
        )])
    }
}

pub struct DuplicateAckPlugin;

impl Default for DuplicateAckPlugin {
    fn default() -> Self {
        Self
    }
}

impl Plugin for DuplicateAckPlugin {
    fn name(&self) -> &str {
        "Duplicate ACK Detector"
    }

    fn description(&self) -> &str {
        "Marks repeated pure ACKs with the same ACK and SEQ number. Outputs DUP_ACK and DUP_ACK_COUNT."
    }

    fn required_series(&self) -> Vec<String> {
        vec![
            "ACK_NUM".to_string(),
            "SEQ_NUM".to_string(),
            "FLAGS".to_string(),
        ]
    }

    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String> {
        let ack_num = input.first().ok_or("Missing ACK_NUM series")?;
        let seq_num = input.get(1).ok_or("Missing SEQ_NUM series")?;
        let flags = input.get(2).ok_or("Missing FLAGS series")?;

        let mut last_ack: Option<(i64, i64)> = None;
        let mut dup_count = 0_i64;
        let mut dup_ack = Vec::new();
        let mut dup_ack_count = Vec::new();

        for (((t, ack), (_, seq)), (_, flags)) in ack_num
            .raw_data
            .iter()
            .zip(&seq_num.raw_data)
            .zip(&flags.raw_data)
        {
            let Some(ack) = value_as_i64(ack) else {
                continue;
            };
            let Some(seq) = value_as_i64(seq) else {
                continue;
            };
            let Some(flags) = value_as_i64(flags) else {
                continue;
            };

            if !is_pure_ack(flags) {
                dup_ack_count.push((*t, DataValue::Int(0)));
                continue;
            }

            let is_dup = last_ack == Some((ack, seq));
            if is_dup {
                dup_count += 1;
            } else {
                last_ack = Some((ack, seq));
                dup_count = 0;
            }
            if is_dup {
                dup_ack.push((*t, DataValue::Boolean(true)));
            }
            dup_ack_count.push((*t, DataValue::Int(dup_count)));
        }

        Ok(vec![
            bool_series(
                "DUP_ACK",
                ack_num,
                dup_ack,
                egui::Color32::from_rgb(230, 90, 90),
            ),
            int_series(
                "DUP_ACK_COUNT",
                ack_num,
                dup_ack_count,
                egui::Color32::from_rgb(230, 120, 90),
            ),
        ])
    }
}

pub struct RetransmissionPlugin;

impl Default for RetransmissionPlugin {
    fn default() -> Self {
        Self
    }
}

impl Plugin for RetransmissionPlugin {
    fn name(&self) -> &str {
        "Retransmission Detector"
    }

    fn description(&self) -> &str {
        "Marks drops below the previous sequence high-water mark as boolean RETRANSMISSION events. Map the input to SEQ_NUM or SND_NXT."
    }

    fn required_series(&self) -> Vec<String> {
        vec!["SEQ_NUM".to_string()]
    }

    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String> {
        let seq_num = input.first().ok_or("Missing SEQ_NUM/SND_NXT series")?;
        let mut high_water: Option<u32> = None;
        let raw_data =
            seq_num
                .raw_data
                .iter()
                .filter_map(|(t, seq)| {
                    let seq = value_as_u32(seq)?;
                    let event = high_water.is_some_and(|max| tcp_seq_before(seq, max));
                    high_water = Some(high_water.map_or(seq, |max| {
                        if tcp_seq_after(seq, max) {
                            seq
                        } else {
                            max
                        }
                    }));
                    event.then_some((*t, DataValue::Boolean(true)))
                })
                .collect::<Vec<_>>();

        Ok(vec![bool_series(
            "RETRANSMISSION",
            seq_num,
            raw_data,
            egui::Color32::from_rgb(200, 60, 120),
        )])
    }
}

pub struct SenderLimitationPlugin;

impl Default for SenderLimitationPlugin {
    fn default() -> Self {
        Self
    }
}

impl Plugin for SenderLimitationPlugin {
    fn name(&self) -> &str {
        "Sender Limitation"
    }

    fn description(&self) -> &str {
        "Estimates CWND_UTILIZATION and SENDER_LIMITATION: 0=not full, 1=cwnd-limited, 2=rwnd-limited."
    }

    fn required_series(&self) -> Vec<String> {
        vec![
            "SND_NXT".to_string(),
            "SND_UNA".to_string(),
            "SND_WND".to_string(),
            "SND_CWND".to_string(),
            "advmss".to_string(),
        ]
    }

    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String> {
        let snd_nxt = input.first().ok_or("Missing SND_NXT series")?;
        let snd_una = input.get(1).ok_or("Missing SND_UNA series")?;
        let snd_wnd = input.get(2).ok_or("Missing SND_WND series")?;
        let snd_cwnd = input.get(3).ok_or("Missing SND_CWND series")?;
        let advmss = input.get(4).ok_or("Missing advmss series")?;

        let mut utilization = Vec::new();
        let mut limitation = Vec::new();
        let mut limitation_labels = Vec::new();
        let mut last_limit = None;

        for (((t, nxt), (_, una)), (_, wnd)) in snd_nxt
            .raw_data
            .iter()
            .zip(&snd_una.raw_data)
            .zip(&snd_wnd.raw_data)
        {
            let Some(nxt) = value_as_u32(nxt) else {
                continue;
            };
            let Some(una) = value_as_u32(una) else {
                continue;
            };
            let Some(wnd) = value_as_f64(wnd) else {
                continue;
            };
            let Some(cwnd) = value_at_or_before(snd_cwnd, *t) else {
                continue;
            };
            let Some(advmss) = value_at_or_before(advmss, *t) else {
                continue;
            };
            let cwnd_bytes = cwnd * advmss;
            if cwnd_bytes <= 0.0 {
                continue;
            }

            let bytes_in_flight = nxt.wrapping_sub(una) as f64;
            let usable_rwnd = wnd - bytes_in_flight;
            let util = bytes_in_flight / cwnd_bytes;
            let limit = if usable_rwnd <= advmss {
                2
            } else if util >= 0.95 {
                1
            } else {
                0
            };
            utilization.push((*t, DataValue::Float(util)));
            limitation.push((*t, DataValue::Int(limit)));
            if last_limit != Some(limit) {
                limitation_labels.push((*t, DataValue::String(sender_limitation_label(limit))));
                last_limit = Some(limit);
            }
        }

        Ok(vec![
            float_series(
                "CWND_UTILIZATION",
                snd_nxt,
                utilization,
                egui::Color32::from_rgb(120, 190, 120),
            ),
            int_series(
                "SENDER_LIMITATION",
                snd_nxt,
                limitation,
                egui::Color32::from_rgb(150, 120, 220),
            ),
            string_series(
                "SENDER_LIMITATION_LABEL",
                snd_nxt,
                limitation_labels,
                egui::Color32::from_rgb(150, 120, 220),
            ),
        ])
    }
}

pub struct LossEpisodePlugin;

impl Default for LossEpisodePlugin {
    fn default() -> Self {
        Self
    }
}

impl Plugin for LossEpisodePlugin {
    fn name(&self) -> &str {
        "Loss Episode Detector"
    }

    fn description(&self) -> &str {
        "Starts a new LOSS_EPISODE_ID whenever total_retrans increases."
    }

    fn required_series(&self) -> Vec<String> {
        vec!["total_retrans".to_string()]
    }

    fn compute(&self, input: &[SeriesData]) -> Result<Vec<SeriesData>, String> {
        let total_retrans = input.first().ok_or("Missing total_retrans series")?;
        let mut last_total = None;
        let mut episode_id = 0_i64;
        let raw_data = total_retrans
            .raw_data
            .iter()
            .filter_map(|(t, total)| {
                let total = value_as_i64(total)?;
                if let Some(last) = last_total {
                    if total > last {
                        episode_id += 1;
                    }
                }
                last_total = Some(total);
                Some((*t, DataValue::Int(episode_id)))
            })
            .collect::<Vec<_>>();

        Ok(vec![int_series(
            "LOSS_EPISODE_ID",
            total_retrans,
            raw_data,
            egui::Color32::from_rgb(230, 130, 60),
        )])
    }
}

fn is_pure_ack(flags: i64) -> bool {
    flags & TCP_ACK != 0 && flags & (TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH) == 0
}

fn sender_limitation_label(limit: i64) -> String {
    match limit {
        1 => "cwnd-limited".to_string(),
        2 => "rwnd-limited".to_string(),
        _ => "not-full".to_string(),
    }
}

fn tcp_seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn tcp_seq_after(a: u32, b: u32) -> bool {
    tcp_seq_before(b, a)
}

fn value_as_i64(value: &DataValue) -> Option<i64> {
    match value {
        DataValue::Int(value) => Some(*value),
        DataValue::Float(value) => Some(*value as i64),
        DataValue::Boolean(value) => Some(i64::from(*value)),
        DataValue::String(_) => None,
    }
}

fn value_as_u32(value: &DataValue) -> Option<u32> {
    value_as_i64(value).map(|value| value as u32)
}

fn value_as_f64(value: &DataValue) -> Option<f64> {
    match value {
        DataValue::Int(value) => Some(*value as f64),
        DataValue::Float(value) => Some(*value),
        DataValue::Boolean(value) => Some(f64::from(*value as u8)),
        DataValue::String(_) => None,
    }
}

fn value_at_or_before(series: &SeriesData, timestamp: f64) -> Option<f64> {
    series
        .raw_data
        .iter()
        .take_while(|(t, _)| *t <= timestamp)
        .last()
        .and_then(|(_, value)| value_as_f64(value))
}

fn int_series(
    name: &str,
    template: &SeriesData,
    raw_data: Vec<(f64, DataValue)>,
    color: egui::Color32,
) -> SeriesData {
    let (points, y_min, y_max) = numeric_points_and_bounds(&raw_data);
    let mut out = SeriesData::new(
        name.to_string(),
        -1,
        DataValue::Int(0),
        template.global_t_min,
        template.global_t_max,
        y_min,
        y_max,
        color,
    );
    out.points = points;
    out.raw_data = raw_data;
    out
}

fn bool_series(
    name: &str,
    template: &SeriesData,
    raw_data: Vec<(f64, DataValue)>,
    color: egui::Color32,
) -> SeriesData {
    let (points, y_min, y_max) = numeric_points_and_bounds(&raw_data);
    let mut out = SeriesData::new(
        name.to_string(),
        -1,
        DataValue::Boolean(false),
        template.global_t_min,
        template.global_t_max,
        y_min,
        y_max,
        color,
    );
    out.points = points;
    out.raw_data = raw_data;
    out
}

fn float_series(
    name: &str,
    template: &SeriesData,
    raw_data: Vec<(f64, DataValue)>,
    color: egui::Color32,
) -> SeriesData {
    let (points, y_min, y_max) = numeric_points_and_bounds(&raw_data);
    let mut out = SeriesData::new(
        name.to_string(),
        -1,
        DataValue::Float(0.0),
        template.global_t_min,
        template.global_t_max,
        y_min,
        y_max,
        color,
    );
    out.points = points;
    out.raw_data = raw_data;
    out
}

fn string_series(
    name: &str,
    template: &SeriesData,
    raw_data: Vec<(f64, DataValue)>,
    color: egui::Color32,
) -> SeriesData {
    let string_points = raw_data
        .iter()
        .filter_map(|(t, value)| {
            let DataValue::String(value) = value else {
                return None;
            };
            Some((*t, value.clone()))
        })
        .collect();
    let mut out = SeriesData::new(
        name.to_string(),
        -1,
        DataValue::String(String::new()),
        template.global_t_min,
        template.global_t_max,
        0.0,
        1.0,
        color,
    );
    out.string_points = string_points;
    out.raw_data = raw_data;
    out
}

fn numeric_points_and_bounds(raw_data: &[(f64, DataValue)]) -> (Vec<(f64, f64)>, f64, f64) {
    let mut y_min = f64::MAX;
    let mut y_max = f64::MIN;
    let points = raw_data
        .iter()
        .filter_map(|(t, value)| {
            let value = value_as_f64(value)?;
            y_min = y_min.min(value);
            y_max = y_max.max(value);
            Some((*t, value))
        })
        .collect::<Vec<_>>();

    if y_min > y_max {
        (points, 0.0, 1.0)
    } else {
        (points, y_min, y_max)
    }
}
