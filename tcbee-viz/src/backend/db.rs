use std::cell::{OnceCell, RefCell};
use std::path::PathBuf;

use ts_storage::{
    open_store, DataPoint, DataValue, Engine, Flow, SeriesInfo, SeriesKind, Store, StoreError,
};

use crate::{backend::binding::series_label, data::series_data::SeriesData};

/// File extensions the file dialog and the usage text offer.
pub const DB_EXTENSIONS: &[&str] = &["sqlite", "db", "duck", "duckdb"];

/// `.sqlite, .db, .duck or .duckdb`
pub fn extensions_text() -> String {
    let (last, init) = DB_EXTENSIONS.split_last().expect("extensions");
    let init: Vec<String> = init.iter().map(|e| format!(".{e}")).collect();
    format!("{} or .{}", init.join(", "), last)
}

/// Display name and cargo feature of an engine.
fn engine_info(engine: Engine) -> (&'static str, &'static str) {
    match engine {
        Engine::Sqlite => ("SQLite", "sqlite"),
        Engine::DuckDb => ("DuckDB", "duckdb"),
    }
}

pub fn engine_name(engine: Engine) -> &'static str {
    engine_info(engine).0
}

/// Error text for the UI. Only a disabled engine gets a message of its own; the other errors
/// are shown as ts-storage words them (a v1 file already says to reprocess the trace).
pub fn describe_open_error(e: &StoreError) -> String {
    match e {
        StoreError::EngineDisabled(engine) => {
            let (name, feature) = engine_info(*engine);
            format!(
                "This file is a {name} database, but this build does not include {name} \
                 support. Rebuild with `--features {feature}`."
            )
        }
        other => other.to_string(),
    }
}

#[derive(Default)]
pub struct DbBackend {
    store: Option<Box<dyn Store>>,
    /// Flows never change while a file is open, so they are read once.
    flows: OnceCell<Vec<Flow>>,
    /// Last read error that was logged, so a failing plot reload logs once, not every frame.
    last_error: RefCell<Option<String>>,
}

impl DbBackend {
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let store = open_store(&path).map_err(|e| describe_open_error(&e))?;
        Ok(Self {
            store: Some(store),
            ..Self::default()
        })
    }

    pub fn is_connected(&self) -> bool {
        self.store.is_some()
    }

    /// The engine of the open file.
    pub fn engine(&self) -> Option<Engine> {
        self.store.as_ref().map(|s| s.engine())
    }

    /// Logs an error unless it is the same as the previous one.
    fn report(&self, msg: String) {
        let mut last = self.last_error.borrow_mut();
        if last.as_deref() != Some(msg.as_str()) {
            eprintln!("tcbee-viz: {msg}");
            *last = Some(msg);
        }
    }

    /// All flows, read from the file on first use.
    pub fn list_flows(&self) -> &[Flow] {
        let Some(db) = &self.store else { return &[] };
        self.flows.get_or_init(|| {
            db.flows().unwrap_or_else(|e| {
                self.report(format!("listing flows failed: {e}"));
                Vec::new()
            })
        })
    }

    pub fn get_flow_by_id(&self, id: i64) -> Option<&Flow> {
        self.list_flows().iter().find(|f| f.id == id)
    }

    pub fn flow_exists(&self, id: i64) -> bool {
        self.get_flow_by_id(id).is_some()
    }

    /// The catalog rows of a flow's series. This queries the file; callers keep the result.
    pub fn list_series_for_flow(&self, flow_id: i64) -> Vec<SeriesInfo> {
        let Some(db) = &self.store else {
            return Vec::new();
        };
        db.series(flow_id).unwrap_or_else(|e| {
            self.report(format!("listing series failed: {e}"));
            Vec::new()
        })
    }

    /// Reads the points of one series, ordered by (ts, seq). `range` is inclusive.
    fn for_each(
        &self,
        series: &SeriesInfo,
        range: Option<(f64, f64)>,
        f: &mut dyn FnMut(DataPoint),
    ) -> Result<(), String> {
        let Some(db) = &self.store else {
            return Err("No database connection".to_string());
        };
        db.for_each_point(series, range, f)
            .map_err(|e| format!("reading {} failed: {}", series_label(series), e))
    }

    /// Points in a time range for plotting, keeping at most one point per sample interval.
    /// `map` turns a value into the plotted one or drops it. A read error is logged once and
    /// leaves the plot empty.
    fn load_sampled<T>(
        &self,
        series: &SeriesInfo,
        t_min: f64,
        t_max: f64,
        sample_interval: f64,
        map: impl Fn(DataValue) -> Option<T>,
    ) -> Vec<(f64, T)> {
        let mut out = Vec::new();
        let mut next_timestamp = f64::NEG_INFINITY;
        let result = self.for_each(series, Some((t_min, t_max)), &mut |p| {
            if sample_interval <= 0.0 || p.timestamp >= next_timestamp {
                if let Some(v) = map(p.value) {
                    next_timestamp = p.timestamp + sample_interval;
                    out.push((p.timestamp, v));
                }
            }
        });
        if let Err(e) = result {
            self.report(e);
            out.clear();
        }
        out
    }

    /// Numeric points (booleans as 0/1) in a range.
    pub fn load_range_sampled(
        &self,
        series: &SeriesInfo,
        t_min: f64,
        t_max: f64,
        sample_interval: f64,
    ) -> Vec<(f64, f64)> {
        self.load_sampled(series, t_min, t_max, sample_interval, |v| {
            datavalue_as_f64(&v)
        })
    }

    /// String points in a range.
    pub fn load_range_strings_sampled(
        &self,
        series: &SeriesInfo,
        t_min: f64,
        t_max: f64,
        sample_interval: f64,
    ) -> Vec<(f64, String)> {
        self.load_sampled(series, t_min, t_max, sample_interval, |v| match v {
            DataValue::String(s) => Some(s),
            _ => None,
        })
    }

    /// True boolean events in a range (as 1.0).
    pub fn load_range_bool_events_sampled(
        &self,
        series: &SeriesInfo,
        t_min: f64,
        t_max: f64,
        sample_interval: f64,
    ) -> Vec<(f64, f64)> {
        self.load_sampled(series, t_min, t_max, sample_interval, |v| {
            matches!(v, DataValue::Boolean(true)).then_some(1.0)
        })
    }

    /// Load ALL data points for a series (used by plugins, they need the full dataset).
    pub fn load_all(&self, series: &SeriesInfo) -> Result<Vec<(f64, DataValue)>, String> {
        let mut out = Vec::with_capacity(series.n.max(0) as usize);
        self.for_each(series, None, &mut |p| out.push((p.timestamp, p.value)))?;
        Ok(out)
    }

    /// Loads the full data of the selected series as plugin inputs (`raw_data` and `points`).
    /// Any read error fails the whole call, so a plugin never runs on partial data.
    pub fn load_inputs(
        &self,
        available: &[SeriesInfo],
        series_ids: &[i64],
        colors: &[egui::Color32],
    ) -> Result<Vec<SeriesData>, String> {
        let (x_min, x_max) = flow_x_bounds(available).unwrap_or((0.0, 1.0));
        let mut out = Vec::with_capacity(series_ids.len());
        for (i, &sid) in series_ids.iter().enumerate() {
            let info = available
                .iter()
                .find(|s| s.id == sid)
                .ok_or_else(|| format!("series {sid} is not available in this flow"))?;
            let color = colors.get(i).copied().unwrap_or(egui::Color32::WHITE);
            let mut sd = SeriesData::from_info(info, x_min, x_max, color);
            sd.raw_data = self.load_all(info)?;
            sd.points = sd
                .raw_data
                .iter()
                .filter_map(|(t, v)| datavalue_as_f64(v).map(|f| (*t, f)))
                .collect();
            sd.loaded_range = Some((x_min, x_max));
            out.push(sd);
        }
        Ok(out)
    }

    /// Persist a newly computed series as a derived series of the flow.
    pub fn create_series_for_flow(&self, flow_id: i64, series: &SeriesData) -> Result<(), String> {
        let db = self.store.as_ref().ok_or("No database connection")?;
        db.create_derived(flow_id, &series.name, series.val_type, &to_points(series))
            .map(|_| ())
            .map_err(|e| format!("saving series {} failed: {}", series.name, e))
    }

    /// Replace the derived series of the same name (its id is kept), or create it if there is
    /// none. Raw series are never touched.
    pub fn replace_series_for_flow(&self, flow_id: i64, series: &SeriesData) -> Result<(), String> {
        let db = self.store.as_ref().ok_or("No database connection")?;
        let existing =
            self.existing_series_for_flow(flow_id, std::slice::from_ref(&series.name))?;
        match existing.first() {
            Some(old) => db
                .replace_derived(old, &to_points(series))
                .map(|_| ())
                .map_err(|e| format!("replacing series {} failed: {}", series.name, e)),
            None => self.create_series_for_flow(flow_id, series),
        }
    }

    /// The DERIVED series of the flow with one of the given names. Raw series do not count.
    pub fn existing_series_for_flow(
        &self,
        flow_id: i64,
        names: &[String],
    ) -> Result<Vec<SeriesInfo>, String> {
        let db = self.store.as_ref().ok_or("No database connection")?;
        let all = db
            .series(flow_id)
            .map_err(|e| format!("listing series failed: {}", e))?;
        Ok(all
            .into_iter()
            .filter(|s| s.kind == SeriesKind::Derived && names.contains(&s.name))
            .collect())
    }
}

fn to_points(series: &SeriesData) -> Vec<DataPoint> {
    series
        .raw_data
        .iter()
        .map(|(t, v)| DataPoint {
            timestamp: *t,
            value: v.clone(),
        })
        .collect()
}

/// Min and max timestamp over the series that have points (catalog values, no query).
pub fn flow_x_bounds<'a>(series: impl IntoIterator<Item = &'a SeriesInfo>) -> Option<(f64, f64)> {
    let mut t_min = f64::MAX;
    let mut t_max = f64::MIN;
    for s in series.into_iter().filter(|s| s.n > 0) {
        if let (Some(lo), Some(hi)) = (s.t_min, s.t_max) {
            t_min = t_min.min(lo as f64);
            t_max = t_max.max(hi as f64);
        }
    }
    (t_min <= t_max).then_some((t_min, t_max))
}

pub fn datavalue_as_f64(v: &DataValue) -> Option<f64> {
    match v {
        DataValue::Float(f) => Some(*f),
        DataValue::Int(i) => Some(*i as f64),
        DataValue::Boolean(b) => Some(if *b { 1.0 } else { 0.0 }),
        DataValue::String(_) => None,
    }
}

pub fn format_flow(flow: &Flow) -> String {
    format!(
        "ID:{} {}:{} → {}:{}",
        flow.id, flow.tuple.src, flow.tuple.sport, flow.tuple.dst, flow.tuple.dport,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::binding::resolve_inputs;
    use crate::backend::plugin::PluginKind;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use ts_storage::{
        create_store, Catalog, ColType, Column, CreateOptions, Dir, EventBatch, EventTable,
        IpTuple, StatsAccumulator, ValueKind,
    };

    const fn col(name: &'static str, ty: ColType) -> Column {
        Column { name, ty }
    }

    static PROBE_COLS: [Column; 4] = [
        col("SND_NXT", ColType::U32),
        col("SND_UNA", ColType::U32),
        col("SND_WND", ColType::U32),
        col("SND_CWND", ColType::U32),
    ];
    static PROBE: EventTable = EventTable {
        source: "tcp_probe",
        columns: &PROBE_COLS,
    };

    static SOCK_COLS: [Column; 3] = [
        col("advmss", ColType::U16),
        col("total_retrans", ColType::U32),
        col("snd_cwnd", ColType::U32),
    ];
    static SOCK: EventTable = EventTable {
        source: "sock",
        columns: &SOCK_COLS,
    };

    static TCP4_COLS: [Column; 3] = [
        col("SEQ_NUM", ColType::U32),
        col("ACK_NUM", ColType::U32),
        col("FLAGS", ColType::U8),
    ];
    static TCP4: EventTable = EventTable {
        source: "tcp4",
        columns: &TCP4_COLS,
    };

    const N: i64 = 60;

    fn ts(i: i64) -> i64 {
        1_000_000 + i * 1000
    }

    /// One flow with the inputs of every plugin. tcp4 and sock exist as send and recv copies
    /// with different values; the recv copies must never be picked.
    fn build(engine: Engine, path: &Path) {
        let s = create_store(engine, path, CreateOptions::default()).unwrap();
        s.create_tables(&[&PROBE, &SOCK, &TCP4]).unwrap();
        let mut acc = StatsAccumulator::new();
        let mut w = s.writer().unwrap();

        let mut b = EventBatch::new(&PROBE, N as usize);
        for i in 0..N {
            b.push_header(1, Dir::None, ts(i), i);
            b.u32(0).push((i * 100 + 500) as u32);
            b.u32(1).push((i * 100) as u32);
            b.u32(2).push(10_000);
            b.u32(3).push(10 + (i / 10) as u32);
        }
        acc.observe(&b).unwrap();
        w.write(b).unwrap();

        for (dir, add) in [(Dir::Send, 0u32), (Dir::Recv, 7)] {
            let mut b = EventBatch::new(&SOCK, N as usize);
            for i in 0..N {
                b.push_header(1, dir, ts(i), i);
                b.u16(0).push(1448 + add as u16);
                b.u32(1).push(add + (i / 20) as u32);
                b.u32(2).push(add + 10);
            }
            acc.observe(&b).unwrap();
            w.write(b).unwrap();

            let mut b = EventBatch::new(&TCP4, N as usize);
            for i in 0..N {
                b.push_header(1, dir, ts(i), i);
                // Row 31 repeats the sequence number of row 30 (retransmission, duplicate ack).
                let k = if i == 31 { 30 } else { i } as u32;
                b.u32(0).push(add + k * 100);
                b.u32(1).push(add + 1000);
                b.u8(2).push(0x10);
            }
            acc.observe(&b).unwrap();
            w.write(b).unwrap();
        }
        w.close().unwrap();

        let flow = Flow::new(
            1,
            IpTuple {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                sport: 1234,
                dport: 80,
                l4proto: 6,
            },
        );
        s.finish(Catalog {
            flows: vec![flow],
            series: acc.into_series(1),
            meta: vec![("writer".into(), "tcbee-viz test".into())],
        })
        .unwrap();
    }

    /// Engines this build includes, with a file extension for the fixture.
    fn engines() -> Vec<(Engine, &'static str)> {
        [
            (cfg!(feature = "sqlite"), Engine::Sqlite, "sqlite"),
            (cfg!(feature = "duckdb"), Engine::DuckDb, "duck"),
        ]
        .into_iter()
        .filter(|(enabled, ..)| *enabled)
        .map(|(_, engine, ext)| (engine, ext))
        .collect()
    }

    fn fixture(engine: Engine, ext: &str) -> (tempfile::TempDir, DbBackend) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("t.{ext}"));
        build(engine, &path);
        let db = DbBackend::open(path).unwrap();
        (dir, db)
    }

    fn find<'a>(all: &'a [SeriesInfo], source: &str, dir: Dir, name: &str) -> &'a SeriesInfo {
        all.iter()
            .find(|s| s.source == source && s.dir == dir && s.name == name)
            .unwrap_or_else(|| panic!("no {source}/{dir:?}/{name}"))
    }

    fn colors(n: usize) -> Vec<egui::Color32> {
        crate::data::preprocessing::generate_colors(n)
    }

    /// Resolved input ids of a plugin; panics if one is unbound.
    fn bound_ids(kind: PluginKind, available: &[SeriesInfo]) -> Vec<i64> {
        let required = kind.create().required_series();
        resolve_inputs(&required, available)
            .into_iter()
            .map(|id| id.unwrap_or_else(|| panic!("{kind:?}: unbound input")))
            .collect()
    }

    #[test]
    fn open_lists_flows_series_and_catalog_bounds() {
        for (engine, ext) in engines() {
            let (_d, db) = fixture(engine, ext);
            assert_eq!(db.engine(), Some(engine));
            assert_eq!(db.list_flows().len(), 1);
            let series = db.list_series_for_flow(1);
            // 4 probe + 3 sock send + 3 sock recv + 3 tcp4 send + 3 tcp4 recv
            assert_eq!(series.len(), 16);
            assert!(series.iter().all(|s| s.n == N));
            assert_eq!(
                flow_x_bounds(&series),
                Some((ts(0) as f64, ts(N - 1) as f64))
            );
            let una = find(&series, "tcp_probe", Dir::None, "SND_UNA");
            assert_eq!(
                (una.v_min, una.v_max),
                (Some(0.0), Some(((N - 1) * 100) as f64))
            );
            assert_eq!(una.value_type.value_kind(), ValueKind::Int);
            assert_eq!(flow_x_bounds(&db.list_series_for_flow(99)), None);
            assert!(db.get_flow_by_id(99).is_none());
            assert!(db.flow_exists(1) && !db.flow_exists(99));
        }
    }

    #[test]
    fn range_loading_and_downsampling() {
        for (engine, ext) in engines() {
            let (_d, db) = fixture(engine, ext);
            let series = db.list_series_for_flow(1);
            let una = find(&series, "tcp_probe", Dir::None, "SND_UNA");

            let all = db.load_range_sampled(una, 0.0, f64::MAX / 2.0, 0.0);
            assert_eq!(all.len(), N as usize);
            assert_eq!(all[3], (ts(3) as f64, 300.0));

            // Inclusive range.
            let r = db.load_range_sampled(una, ts(10) as f64, ts(12) as f64, 0.0);
            assert_eq!(
                r.iter().map(|p| p.1).collect::<Vec<_>>(),
                vec![1000.0, 1100.0, 1200.0]
            );

            // One point per 5000 ns interval keeps every fifth sample.
            let sampled = db.load_range_sampled(una, 0.0, f64::MAX / 2.0, 5000.0);
            assert_eq!(sampled.len(), (N as usize).div_ceil(5));
            assert_eq!(sampled[1].0, ts(5) as f64);

            assert_eq!(db.load_all(una).unwrap().len(), N as usize);
        }
    }

    /// Every plugin finds all its inputs, never binds a recv copy, and takes the inputs of one
    /// run from one `(source, dir)` group where the names allow it.
    #[test]
    fn every_plugin_binds_its_inputs() {
        for (engine, ext) in engines() {
            let (_d, db) = fixture(engine, ext);
            let available = db.list_series_for_flow(1);
            let by_id = |id: i64| available.iter().find(|s| s.id == id).unwrap();

            for kind in PluginKind::ALL {
                let required = kind.create().required_series();
                let ids = bound_ids(*kind, &available);
                assert!(ids.iter().all(|&id| by_id(id).dir != Dir::Recv), "{kind:?}");
                if required.iter().any(|r| r == "SEQ_NUM") {
                    assert!(ids.iter().all(|&id| by_id(id).source == "tcp4"), "{kind:?}");
                }
                if required.iter().any(|r| r == "advmss") {
                    // SenderLimitation: SND_* from tcp_probe, advmss from sock/send.
                    assert_eq!(by_id(ids[0]).source, "tcp_probe");
                    assert_eq!(by_id(*ids.last().unwrap()).source, "sock");
                }
            }
        }
    }

    /// Every plugin runs on the loaded inputs and saves; saving again replaces the derived
    /// series and keeps its id.
    #[test]
    fn every_plugin_saves_and_replaces() {
        for (engine, ext) in engines() {
            let (_d, db) = fixture(engine, ext);
            let available = db.list_series_for_flow(1);
            let raw_count = available.len();

            for kind in PluginKind::ALL {
                let plugin = kind.create();
                let ids = bound_ids(*kind, &available);
                let inputs = db
                    .load_inputs(&available, &ids, &colors(ids.len()))
                    .unwrap();
                assert_eq!(inputs.len(), ids.len());
                assert!(inputs.iter().all(|s| s.raw_data.len() == N as usize));
                // Labels carry source and dir so that legends are unambiguous.
                assert!(inputs[0].name.contains(" · "));

                let out = plugin
                    .compute(&inputs)
                    .unwrap_or_else(|e| panic!("{}: {e}", plugin.name()));
                assert!(!out.is_empty(), "{}", plugin.name());

                for s in &out {
                    db.create_series_for_flow(1, s).unwrap();
                    // A second create is an error; the UI asks to overwrite instead.
                    assert!(db.create_series_for_flow(1, s).is_err());
                }
                let names: Vec<String> = out.iter().map(|s| s.name.clone()).collect();
                let before = db.existing_series_for_flow(1, &names).unwrap();
                assert_eq!(before.len(), out.len(), "{}", plugin.name());
                assert!(before.iter().all(|s| s.kind == SeriesKind::Derived));

                for s in &out {
                    db.replace_series_for_flow(1, s).unwrap();
                }
                let after = db.existing_series_for_flow(1, &names).unwrap();
                let mut ids_before: Vec<i64> = before.iter().map(|s| s.id).collect();
                let mut ids_after: Vec<i64> = after.iter().map(|s| s.id).collect();
                ids_before.sort();
                ids_after.sort();
                assert_eq!(ids_before, ids_after, "replace must keep ids");

                for s in &out {
                    let saved = after.iter().find(|x| x.name == s.name).unwrap();
                    assert_eq!(saved.value_type.value_kind(), s.val_type, "{}", s.name);
                    assert_eq!(saved.n as usize, s.raw_data.len());
                    assert_eq!(db.load_all(saved).unwrap().len(), s.raw_data.len());
                }
            }

            // Derived series are in the list, raw ones untouched.
            let now = db.list_series_for_flow(1);
            assert!(now.len() > raw_count);
            assert_eq!(
                now.iter().filter(|s| s.kind == SeriesKind::Raw).count(),
                raw_count
            );
            // A string series (SENDER_LIMITATION_LABEL) saved.
            assert!(now
                .iter()
                .any(|s| s.kind == SeriesKind::Derived && s.value_type == ColType::Text));
        }
    }

    /// A series that cannot be read fails `load_all` and `load_inputs`; nothing is computed or
    /// saved from an empty result.
    #[test]
    fn failing_read_is_an_error_not_an_empty_series() {
        for (engine, ext) in engines() {
            let (_d, db) = fixture(engine, ext);
            let mut available = db.list_series_for_flow(1);
            let ids = bound_ids(PluginKind::BytesInFlight, &available);
            let broken_id = ids[0];
            let broken = available.iter_mut().find(|s| s.id == broken_id).unwrap();
            broken.col = Some("no_such_column".to_string());
            let broken = broken.clone();

            let err = db.load_all(&broken).unwrap_err();
            assert!(err.contains("reading"), "{err}");
            let err = db
                .load_inputs(&available, &ids, &colors(ids.len()))
                .err()
                .expect("load_inputs must fail");
            assert!(err.contains("reading"), "{err}");
            // Plot loaders log and draw nothing, they do not panic.
            assert!(db.load_range_sampled(&broken, 0.0, 1e12, 0.0).is_empty());
            // An id that is not in the list is an error too.
            assert!(db.load_inputs(&available, &[-1], &colors(1)).is_err());
            // Nothing was saved.
            assert!(db
                .list_series_for_flow(1)
                .iter()
                .all(|s| s.kind == SeriesKind::Raw));
        }
    }

    #[test]
    fn replace_changes_points_and_overwrite_ignores_raw() {
        for (engine, ext) in engines() {
            let (_d, db) = fixture(engine, ext);
            let mk = |name: &str, n: usize| {
                let mut s = SeriesData::new(
                    name.to_string(),
                    -1,
                    ValueKind::Int,
                    0.0,
                    1.0,
                    0.0,
                    1.0,
                    egui::Color32::WHITE,
                );
                s.raw_data = (0..n)
                    .map(|i| (i as f64 * 10.0, DataValue::Int(i as i64)))
                    .collect();
                s
            };
            // A derived series named like a raw one does not count as a raw conflict.
            let names = vec!["SND_UNA".to_string()];
            assert!(db.existing_series_for_flow(1, &names).unwrap().is_empty());
            db.replace_series_for_flow(1, &mk("SND_UNA", 5)).unwrap(); // nothing to replace: creates
            let old = db.existing_series_for_flow(1, &names).unwrap();
            assert_eq!(old.len(), 1);
            assert_eq!(old[0].n, 5);

            db.replace_series_for_flow(1, &mk("SND_UNA", 8)).unwrap();
            let new = db.existing_series_for_flow(1, &names).unwrap();
            assert_eq!(new.len(), 1);
            assert_eq!(new[0].id, old[0].id);
            assert_eq!(new[0].n, 8);
            // The raw SND_UNA is untouched.
            let all = db.list_series_for_flow(1);
            assert_eq!(find(&all, "tcp_probe", Dir::None, "SND_UNA").n, N);
            // With the derived duplicate in the list, binding still prefers the raw series.
            let id = resolve_inputs(&names, &all)[0].unwrap();
            assert_eq!(
                all.iter().find(|s| s.id == id).unwrap().kind,
                SeriesKind::Raw
            );
        }
    }

    #[test]
    fn open_errors_are_readable() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.sqlite");
        std::fs::write(&junk, b"definitely not a database").unwrap();
        assert!(DbBackend::open(junk).is_err());
        assert!(DbBackend::open(dir.path().join("missing.db")).is_err());

        let msg = describe_open_error(&StoreError::EngineDisabled(Engine::DuckDb));
        assert_eq!(
            msg,
            "This file is a DuckDB database, but this build does not include DuckDB support. \
             Rebuild with `--features duckdb`."
        );
        let msg = describe_open_error(&StoreError::EngineDisabled(Engine::Sqlite));
        assert!(msg.contains("--features sqlite"), "{msg}");
        let msg = describe_open_error(&StoreError::UnsupportedSchema { found: None });
        assert!(msg.contains("reprocess the trace"), "{msg}");
    }

    #[test]
    fn extension_text() {
        assert_eq!(extensions_text(), ".sqlite, .db, .duck or .duckdb");
    }

    /// A file of an engine that is not built in gives the disabled-engine message.
    #[cfg(any(not(feature = "duckdb"), not(feature = "sqlite")))]
    #[test]
    fn disabled_engine_message() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(not(feature = "duckdb"))]
        {
            let p = dir.path().join("x.duck");
            let mut bytes = vec![0u8; 8];
            bytes.extend(b"DUCK");
            bytes.extend([0u8; 64]);
            std::fs::write(&p, bytes).unwrap();
            let err = DbBackend::open(p).err().unwrap();
            assert!(err.contains("does not include DuckDB support"), "{err}");
        }
        #[cfg(not(feature = "sqlite"))]
        {
            let p = dir.path().join("x.sqlite");
            let mut bytes = b"SQLite format 3\0".to_vec();
            bytes.extend([0u8; 64]);
            std::fs::write(&p, bytes).unwrap();
            let err = DbBackend::open(p).err().unwrap();
            assert!(err.contains("does not include SQLite support"), "{err}");
        }
    }
}
