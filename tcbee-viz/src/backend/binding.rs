//! Plugin input binding.
//!
//! A flow can hold several series with the same name: send and receive copies, raw columns and
//! derived series. The plugins zip their inputs by index, so only rows of one `(source, dir)`
//! group are aligned. [`resolve_inputs`] picks one series per required name.

use ts_storage::{Dir, SeriesInfo, SeriesKind};

/// How well a series name matches a required name. Lower is better.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Exact,
    CaseInsensitive,
    Alphanumeric,
}

/// Sources in order of preference. Unknown sources come after the last one.
const SOURCE_ORDER: &[&str] = &["tcp_probe", "sock", "tcp4", "tcp6", "cwnd", "cubic", "bbr"];

fn tier(required: &str, name: &str) -> Option<Tier> {
    if name == required {
        Some(Tier::Exact)
    } else if name.eq_ignore_ascii_case(required) {
        Some(Tier::CaseInsensitive)
    } else if normalize_series_name(name) == normalize_series_name(required) {
        Some(Tier::Alphanumeric)
    } else {
        None
    }
}

fn normalize_series_name(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

/// Preference among series of the same tier: raw over derived, then source order, then
/// send over recv over none. The id breaks ties so the result is deterministic.
fn preference(s: &SeriesInfo) -> (u8, usize, u8, i64) {
    let kind = match s.kind {
        SeriesKind::Raw => 0,
        SeriesKind::Derived => 1,
    };
    let source = SOURCE_ORDER
        .iter()
        .position(|n| *n == s.source)
        .unwrap_or(SOURCE_ORDER.len());
    (kind, source, dir_rank(s.dir), s.id)
}

fn dir_rank(d: Dir) -> u8 {
    match d {
        Dir::Send => 0,
        Dir::Recv => 1,
        Dir::None => 2,
    }
}

fn group_of(s: &SeriesInfo) -> (SeriesKind, &str, Dir) {
    (s.kind, s.source.as_str(), s.dir)
}

/// Best series for one name among `candidates`: best tier first, then preference.
fn best<'a>(
    required: &str,
    candidates: impl Iterator<Item = &'a SeriesInfo>,
) -> Option<(Tier, &'a SeriesInfo)> {
    candidates
        .filter_map(|s| tier(required, &s.name).map(|t| (t, s)))
        .min_by_key(|(t, s)| (*t, preference(s)))
}

/// Best series for a single required name among all `available` ones.
fn best_match_series_id(required: &str, available: &[SeriesInfo]) -> Option<i64> {
    best(required, available.iter()).map(|(_, s)| s.id)
}

/// Resolves all inputs of one plugin run.
///
/// If one `(kind, source, dir)` group holds a series for every required name, and each of them
/// matches at the best tier available anywhere in the flow (tiers take precedence over the
/// group), all inputs come from that group; the first such group in preference order wins.
/// Otherwise (for example SenderLimitation, which needs `SND_*` from tcp_probe and `advmss`
/// from sock) every input is resolved independently.
pub fn resolve_inputs(required: &[String], available: &[SeriesInfo]) -> Vec<Option<i64>> {
    let best_tiers: Vec<Option<Tier>> = required
        .iter()
        .map(|r| best(r, available.iter()).map(|(t, _)| t))
        .collect();

    if !required.is_empty() && best_tiers.iter().all(Option::is_some) {
        let mut groups: Vec<&SeriesInfo> = available.iter().collect();
        groups.sort_by_key(|s| preference(s));
        let mut tried: Vec<(SeriesKind, &str, Dir)> = Vec::new();
        for first in groups {
            let g = group_of(first);
            if tried.contains(&g) {
                continue;
            }
            tried.push(g);

            let picks: Vec<Option<i64>> = required
                .iter()
                .zip(&best_tiers)
                .map(|(r, bt)| {
                    best(r, available.iter().filter(|s| group_of(s) == g))
                        .filter(|(t, _)| Some(*t) == *bt)
                        .map(|(_, s)| s.id)
                })
                .collect();
            if picks.iter().all(Option::is_some) {
                return picks;
            }
        }
    }

    required
        .iter()
        .map(|r| best_match_series_id(r, available))
        .collect()
}

/// `snd_cwnd · sock · send`, as shown in series lists and plot legends. The direction is left
/// out when there is none (`BYTES_IN_FLIGHT · derived`).
pub fn series_label(s: &SeriesInfo) -> String {
    match s.dir {
        Dir::None => format!("{} · {}", s.name, s.source),
        Dir::Send => format!("{} · {} · send", s.name, s.source),
        Dir::Recv => format!("{} · {} · recv", s.name, s.source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ts_storage::ColType;

    fn raw(id: i64, source: &str, dir: Dir, name: &str) -> SeriesInfo {
        SeriesInfo {
            id,
            flow_id: 1,
            kind: SeriesKind::Raw,
            source: source.to_string(),
            dir,
            name: name.to_string(),
            value_type: ColType::U32,
            tbl: Some(format!("ev_{source}")),
            col: Some(name.to_string()),
            n: 10,
            t_min: Some(0),
            t_max: Some(9),
            v_min: Some(0.0),
            v_max: Some(1.0),
        }
    }

    fn derived(id: i64, name: &str) -> SeriesInfo {
        SeriesInfo {
            kind: SeriesKind::Derived,
            source: "derived".to_string(),
            dir: Dir::None,
            tbl: None,
            col: None,
            ..raw(id, "derived", Dir::None, name)
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn send_preferred_over_recv_and_none() {
        let a = [
            raw(1, "sock", Dir::Recv, "snd_cwnd"),
            raw(2, "sock", Dir::Send, "snd_cwnd"),
        ];
        assert_eq!(best_match_series_id("snd_cwnd", &a), Some(2));
        let a = [
            raw(1, "tcp4", Dir::None, "seq"),
            raw(2, "tcp4", Dir::Recv, "seq"),
        ];
        assert_eq!(best_match_series_id("seq", &a), Some(2));
    }

    #[test]
    fn source_order_then_dir() {
        let a = [
            raw(1, "bbr", Dir::None, "x"),
            raw(2, "cwnd", Dir::Send, "x"),
            raw(3, "tcp6", Dir::Send, "x"),
            raw(4, "tcp4", Dir::Recv, "x"),
            raw(5, "sock", Dir::Recv, "x"),
            raw(6, "tcp_probe", Dir::None, "x"),
        ];
        assert_eq!(best_match_series_id("x", &a), Some(6));
        assert_eq!(best_match_series_id("x", &a[..5]), Some(5));
        assert_eq!(best_match_series_id("x", &a[..4]), Some(4));
        assert_eq!(best_match_series_id("x", &a[..3]), Some(3));
        assert_eq!(best_match_series_id("x", &a[..2]), Some(2));
        assert_eq!(best_match_series_id("x", &a[..1]), Some(1));
        // An unknown source ranks after bbr.
        let a = [raw(1, "zzz", Dir::Send, "x"), raw(2, "bbr", Dir::None, "x")];
        assert_eq!(best_match_series_id("x", &a), Some(2));
    }

    #[test]
    fn raw_over_derived() {
        let a = [derived(1, "SND_NXT"), raw(2, "bbr", Dir::None, "SND_NXT")];
        assert_eq!(best_match_series_id("SND_NXT", &a), Some(2));
        // A derived series is used when it is the only match.
        let a = [derived(1, "BYTES_IN_FLIGHT")];
        assert_eq!(best_match_series_id("BYTES_IN_FLIGHT", &a), Some(1));
    }

    #[test]
    fn tiers_beat_preference() {
        let a = [
            raw(1, "tcp_probe", Dir::None, "snd_una"),
            raw(2, "bbr", Dir::None, "SND_UNA"),
        ];
        assert_eq!(best_match_series_id("SND_UNA", &a), Some(2));
        let a = [
            raw(1, "tcp_probe", Dir::None, "SND_UNA"),
            raw(2, "tcp_probe", Dir::None, "snd-una"),
            raw(3, "tcp_probe", Dir::None, "snd_una"),
        ];
        assert_eq!(best_match_series_id("SND_UNA", &a), Some(1));
        assert_eq!(best_match_series_id("Snd_Una", &a[1..]), Some(3));
        assert_eq!(best_match_series_id("sndUna", &a[1..2]), Some(2));
        assert_eq!(best_match_series_id("missing", &a), None);
    }

    #[test]
    fn inputs_come_from_one_group() {
        // sock/send has both, tcp_probe only one of them: without grouping, tcp_probe would win
        // for SND_NXT and sock for SND_UNA.
        let a = [
            raw(1, "tcp_probe", Dir::None, "SND_NXT"),
            raw(2, "sock", Dir::Recv, "SND_NXT"),
            raw(3, "sock", Dir::Recv, "SND_UNA"),
            raw(4, "sock", Dir::Send, "SND_NXT"),
            raw(5, "sock", Dir::Send, "SND_UNA"),
        ];
        let got = resolve_inputs(&names(&["SND_NXT", "SND_UNA"]), &a);
        assert_eq!(got, vec![Some(4), Some(5)]);
        // Not all in the better group: take the first group with every input.
        let a = [
            raw(1, "tcp_probe", Dir::None, "SND_NXT"),
            raw(2, "sock", Dir::Recv, "SND_NXT"),
            raw(3, "sock", Dir::Recv, "SND_UNA"),
        ];
        assert_eq!(
            resolve_inputs(&names(&["SND_NXT", "SND_UNA"]), &a),
            vec![Some(2), Some(3)]
        );
    }

    #[test]
    fn group_must_keep_the_best_tier() {
        // tcp_probe is the preferred source and holds both names, but its snd_una only matches
        // case-insensitively while bbr has an exact SND_UNA. A group may not degrade the tier.
        let a = [
            raw(1, "tcp_probe", Dir::None, "SND_NXT"),
            raw(2, "tcp_probe", Dir::None, "snd_una"),
            raw(3, "bbr", Dir::None, "SND_NXT"),
            raw(4, "bbr", Dir::None, "SND_UNA"),
        ];
        assert_eq!(
            resolve_inputs(&names(&["SND_NXT", "SND_UNA"]), &a),
            vec![Some(3), Some(4)]
        );
    }

    #[test]
    fn raw_group_beats_derived_group() {
        let a = [
            derived(1, "SND_NXT"),
            derived(2, "SND_UNA"),
            raw(3, "cubic", Dir::None, "SND_NXT"),
            raw(4, "cubic", Dir::None, "SND_UNA"),
        ];
        assert_eq!(
            resolve_inputs(&names(&["SND_NXT", "SND_UNA"]), &a),
            vec![Some(3), Some(4)]
        );
    }

    #[test]
    fn independent_when_no_group_has_all() {
        // SenderLimitation: SND_* from tcp_probe, advmss from sock (send before recv).
        let req = names(&["SND_NXT", "SND_UNA", "SND_WND", "SND_CWND", "advmss"]);
        let mut a = vec![
            raw(1, "tcp_probe", Dir::None, "SND_NXT"),
            raw(2, "tcp_probe", Dir::None, "SND_UNA"),
            raw(3, "tcp_probe", Dir::None, "SND_WND"),
            raw(4, "tcp_probe", Dir::None, "SND_CWND"),
            raw(5, "sock", Dir::Recv, "advmss"),
            raw(6, "sock", Dir::Send, "advmss"),
            raw(7, "sock", Dir::Send, "snd_cwnd"),
        ];
        assert_eq!(
            resolve_inputs(&req, &a),
            vec![Some(1), Some(2), Some(3), Some(4), Some(6)]
        );
        // A missing input stays None, the others are still resolved.
        a.remove(5);
        a.remove(4);
        let got = resolve_inputs(&req, &a);
        assert_eq!(got, vec![Some(1), Some(2), Some(3), Some(4), None]);
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(resolve_inputs(&[], &[]), Vec::<Option<i64>>::new());
        assert_eq!(resolve_inputs(&names(&["a"]), &[]), vec![None]);
    }

    #[test]
    fn label_shows_source_and_dir() {
        assert_eq!(
            series_label(&raw(1, "sock", Dir::Send, "snd_cwnd")),
            "snd_cwnd · sock · send"
        );
        assert_eq!(
            series_label(&derived(1, "BYTES_IN_FLIGHT")),
            "BYTES_IN_FLIGHT · derived"
        );
    }
}
