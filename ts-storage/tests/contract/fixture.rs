//! Tables, row builders, temp files and readers shared by the cases.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use ts_storage::{
    Catalog, ColType, Column, CreateOptions, DataPoint, DataValue, Dir, Engine, EventBatch,
    EventTable, Flow, IpTuple, SeriesInfo, StatsAccumulator, Store, StoreError,
};

const fn col(name: &'static str, ty: ColType) -> Column {
    Column { name, ty }
}

static ALL_COLS: [Column; 8] = [
    col("b", ColType::Bool),
    col("w8", ColType::U8),
    col("w16", ColType::U16),
    col("w32", ColType::U32),
    col("w64", ColType::U64),
    col("i", ColType::I64),
    col("f", ColType::F64),
    col("t", ColType::Text),
];
/// One column of each `ColType`.
pub static ALL: EventTable = EventTable {
    source: "all",
    columns: &ALL_COLS,
};

static OTHER_COLS: [Column; 2] = [col("x", ColType::U32), col("y", ColType::Text)];
pub static OTHER: EventTable = EventTable {
    source: "other",
    columns: &OTHER_COLS,
};

// ---------------------------------------------------------------------------------------------
// Rows and flows

#[derive(Clone)]
pub struct AllRow {
    pub flow: i64,
    pub dir: Dir,
    pub ts: i64,
    pub seq: i64,
    pub b: bool,
    pub w8: u8,
    pub w16: u16,
    pub w32: u32,
    pub w64: u64,
    pub i: i64,
    pub f: f64,
    pub t: String,
}

/// A row of `ALL` with zero values; override fields with struct update syntax.
pub fn row(flow: i64, dir: Dir, ts: i64, seq: i64) -> AllRow {
    AllRow {
        flow,
        dir,
        ts,
        seq,
        b: false,
        w8: 0,
        w16: 0,
        w32: 0,
        w64: 0,
        i: 0,
        f: 0.0,
        t: String::new(),
    }
}

/// A row of `ALL` whose `w32` column is `x`.
pub fn row32(flow: i64, dir: Dir, ts: i64, seq: i64, x: u32) -> AllRow {
    AllRow {
        w32: x,
        ..row(flow, dir, ts, seq)
    }
}

pub fn all_batch(rows: &[AllRow]) -> EventBatch {
    let mut b = EventBatch::new(&ALL, rows.len());
    for r in rows {
        b.push_header(r.flow, r.dir, r.ts, r.seq);
        b.bool(0).push(r.b);
        b.u8(1).push(r.w8);
        b.u16(2).push(r.w16);
        b.u32(3).push(r.w32);
        b.u64(4).push(r.w64);
        b.i64(5).push(r.i);
        b.f64(6).push(r.f);
        b.text(7).push(r.t.clone());
    }
    b
}

/// `(flow, dir, ts, seq, x, y)` rows of `OTHER`.
pub fn other_batch(rows: &[(i64, Dir, i64, i64, u32, &str)]) -> EventBatch {
    let mut b = EventBatch::new(&OTHER, rows.len());
    for &(flow, dir, ts, seq, x, y) in rows {
        b.push_header(flow, dir, ts, seq);
        b.u32(0).push(x);
        b.text(1).push(y.into());
    }
    b
}

/// `10.0.0.1:sport -> 2001:db8::2:80`, TCP.
pub fn tuple(sport: i64) -> IpTuple {
    IpTuple {
        src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst: "2001:db8::2".parse().unwrap(),
        sport,
        dport: 80,
        l4proto: 6,
    }
}

pub fn flow(id: i64, sport: i64) -> Flow {
    Flow::new(id, tuple(sport))
}

/// Like `flow`, with source and destination swapped: an IPv6 source and an IPv4 destination, so
/// both address families occur in both columns.
pub fn flow_v6_to_v4(id: i64, sport: i64) -> Flow {
    let t = tuple(sport);
    Flow::new(
        id,
        IpTuple {
            src: t.dst,
            dst: t.src,
            ..t
        },
    )
}

/// Five rows of flow `flow` (direction send, timestamps 10, 20, ..., 50) with extreme values of
/// every column type, in ascending timestamp order.
pub fn extreme_rows(flow: i64) -> Vec<AllRow> {
    vec![
        AllRow {
            b: true,
            w8: u8::MAX,
            w16: u16::MAX,
            w32: u32::MAX,
            w64: u64::MAX,
            i: -1,
            f: -1.0,
            ..row(flow, Dir::Send, 10, 0)
        },
        AllRow {
            w64: 1 << 63,
            i: i64::MIN,
            f: f64::MIN_POSITIVE,
            t: "it's \"quoted\"; DROP TABLE flows; -- \\ %_".into(),
            ..row(flow, Dir::Send, 20, 1)
        },
        AllRow {
            w64: (1 << 63) + 1,
            i: i64::MAX,
            f: f64::MAX,
            t: "h\u{e9}llo \u{2713} \u{65e5}\u{672c}\u{8a9e} \u{1f600}".into(),
            ..row(flow, Dir::Send, 30, 2)
        },
        AllRow {
            w64: i64::MAX as u64,
            t: "long text 0123456789 ".repeat(500),
            ..row(flow, Dir::Send, 40, 3)
        },
        AllRow {
            f: 2.5e-300,
            t: "0".into(),
            ..row(flow, Dir::Send, 50, 4)
        },
    ]
}

// ---------------------------------------------------------------------------------------------
// Temp files

/// A database path in its own temp dir, which is removed on drop.
pub struct Env {
    pub dir: TempDir,
    pub path: PathBuf,
}

impl Env {
    pub fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.db");
        Env { dir, path }
    }

    /// A path inside the directory.
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Writes a file inside the directory and returns its path.
    pub fn write_file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.file(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    pub fn partial(&self) -> PathBuf {
        let mut s = self.path.as_os_str().to_owned();
        s.push(".partial");
        PathBuf::from(s)
    }

    /// Names of all files in the directory (database, sidecars, partial files).
    pub fn files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

// ---------------------------------------------------------------------------------------------
// Building and reading databases

/// Writes `batches` into `tables` and finishes with the statistics of what was written.
pub fn build(
    engine: Engine,
    path: &Path,
    tables: &[&'static EventTable],
    batches: Vec<EventBatch>,
    flows: Vec<Flow>,
) -> Result<(), StoreError> {
    let s = ts_storage::create(engine, path, CreateOptions::default())?;
    s.create_tables(tables)?;
    let mut acc = StatsAccumulator::new();
    let mut w = s.writer()?;
    for b in batches {
        acc.observe(&b)?;
        w.write(b)?;
    }
    w.close()?;
    s.finish(Catalog {
        flows,
        series: acc.into_series(1),
        meta: vec![("writer".into(), "contract test".into())],
    })
}

/// `build` with the rows as one batch of table `ALL`.
pub fn build_all(
    engine: Engine,
    path: &Path,
    rows: &[AllRow],
    flows: Vec<Flow>,
) -> Result<(), StoreError> {
    build(engine, path, &[&ALL], vec![all_batch(rows)], flows)
}

/// A finished database of table `ALL` (flows 1 and 2) opened for reading.
pub fn open_all(engine: Engine, rows: &[AllRow]) -> (Env, Box<dyn Store>) {
    let env = Env::new();
    build_all(engine, &env.path, rows, vec![flow(1, 1), flow(2, 2)]).unwrap();
    let st = ts_storage::open(&env.path).unwrap();
    (env, st)
}

pub fn find(st: &dyn Store, flow: i64, source: &str, dir: Dir, name: &str) -> SeriesInfo {
    st.series(flow)
        .unwrap()
        .into_iter()
        .find(|s| s.source == source && s.dir == dir && s.name == name)
        .unwrap_or_else(|| panic!("no series {source}/{dir:?}/{name} in flow {flow}"))
}

pub fn dp(timestamp: f64, value: DataValue) -> DataPoint {
    DataPoint { timestamp, value }
}

pub fn int_points(v: &[(f64, i64)]) -> Vec<DataPoint> {
    v.iter().map(|&(t, x)| dp(t, DataValue::Int(x))).collect()
}

/// The one reader all others are built on: the points of a series, optionally in a range.
pub fn read(st: &dyn Store, s: &SeriesInfo, range: Option<(f64, f64)>) -> Vec<DataPoint> {
    let mut out = Vec::new();
    st.for_each_point(s, range, &mut |p| out.push(p)).unwrap();
    out
}

pub fn times(st: &dyn Store, s: &SeriesInfo, range: Option<(f64, f64)>) -> Vec<f64> {
    read(st, s, range).iter().map(|p| p.timestamp).collect()
}

/// Values of an integer series; panics on another kind.
pub fn ints(st: &dyn Store, s: &SeriesInfo, range: Option<(f64, f64)>) -> Vec<i64> {
    read(st, s, range)
        .iter()
        .map(|p| p.value.as_int().unwrap())
        .collect()
}

/// `Debug` of each value (`Int(1)`, `Float(1.0)`, ...): `DataValue` has no `PartialEq`, and the
/// text tells the kinds apart.
pub fn debug_values(st: &dyn Store, s: &SeriesInfo, range: Option<(f64, f64)>) -> Vec<String> {
    read(st, s, range)
        .iter()
        .map(|p| format!("{:?}", p.value))
        .collect()
}

/// `(timestamp, Debug of the value)` for every point.
pub fn debug_points(
    st: &dyn Store,
    s: &SeriesInfo,
    range: Option<(f64, f64)>,
) -> Vec<(f64, String)> {
    read(st, s, range)
        .iter()
        .map(|p| (p.timestamp, format!("{:?}", p.value)))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Schema v1 files

#[cfg(feature = "sqlite")]
const V1_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT, src TEXT NOT NULL, dst TEXT NOT NULL,
    sport INTEGER NOT NULL, dport INTEGER NOT NULL, l4proto INTEGER NOT NULL,
    UNIQUE (src, dst, sport, dport, l4proto));
CREATE TABLE IF NOT EXISTS flow_attributes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id INTEGER, name TEXT NOT NULL,
    value_boolean INTEGER DEFAULT -1, value_text TEXT, value_integer INTEGER DEFAULT -1,
    value_float REAL DEFAULT -1, UNIQUE (flow_id, name),
    FOREIGN KEY (flow_id) REFERENCES flows(id));
CREATE TABLE IF NOT EXISTS time_series (
    time_series_id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id INTEGER NOT NULL,
    name TEXT NOT NULL, type INTEGER NOT NULL, UNIQUE (flow_id, name),
    FOREIGN KEY (flow_id) REFERENCES flows(id));
CREATE TABLE IF NOT EXISTS time_series_data (
    time_series_id INTEGER NOT NULL, timestamp FLOAT NOT NULL,
    value_boolean INTEGER DEFAULT -1, value_text TEXT, value_integer INTEGER DEFAULT -1,
    value_float REAL DEFAULT -1, PRIMARY KEY (time_series_id, timestamp),
    FOREIGN KEY (time_series_id) REFERENCES time_series(time_series_id) ON DELETE CASCADE);
INSERT INTO flows (src, dst, sport, dport, l4proto) VALUES ('10.0.0.1', '10.0.0.2', 1, 2, 6);
INSERT INTO time_series (flow_id, name, type) VALUES (1, 'snd_cwnd', 0);
INSERT INTO time_series_data (time_series_id, timestamp, value_integer) VALUES (1, 1.0, 10);
";

#[cfg(feature = "duckdb")]
const V1_DUCKDB: &str = "
CREATE SEQUENCE IF NOT EXISTS flow_id_seq;
CREATE SEQUENCE IF NOT EXISTS flow_attribute_id_seq;
CREATE SEQUENCE IF NOT EXISTS time_series_id_seq;
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY DEFAULT nextval('flow_id_seq'), src TEXT NOT NULL, dst TEXT NOT NULL,
    sport INTEGER NOT NULL, dport INTEGER NOT NULL, l4proto INTEGER NOT NULL,
    UNIQUE (src, dst, sport, dport, l4proto));
CREATE TABLE IF NOT EXISTS flow_attributes (
    id INTEGER PRIMARY KEY DEFAULT nextval('flow_attribute_id_seq'), flow_id INTEGER,
    name TEXT NOT NULL, value UNION(inum INTEGER, str VARCHAR, fnum DOUBLE, bool BOOLEAN),
    type INTEGER, UNIQUE (flow_id, name), FOREIGN KEY (flow_id) REFERENCES flows(id));
CREATE TABLE IF NOT EXISTS time_series (
    time_series_id INTEGER PRIMARY KEY DEFAULT nextval('time_series_id_seq'),
    flow_id INTEGER NOT NULL, name TEXT NOT NULL, type INTEGER NOT NULL,
    UNIQUE (flow_id, name), FOREIGN KEY (flow_id) REFERENCES flows(id));
CREATE TABLE IF NOT EXISTS time_series_data (
    time_series_id INTEGER NOT NULL, timestamp DOUBLE NOT NULL,
    value UNION(inum INTEGER, str VARCHAR, fnum DOUBLE, bool BOOLEAN), type INTEGER,
    PRIMARY KEY (time_series_id, timestamp),
    FOREIGN KEY (time_series_id) REFERENCES time_series(time_series_id));
INSERT INTO flows (src, dst, sport, dport, l4proto) VALUES ('10.0.0.1', '10.0.0.2', 1, 2, 6);
INSERT INTO time_series (flow_id, name, type) VALUES (1, 'snd_cwnd', 0);
INSERT INTO time_series_data (time_series_id, timestamp, value, type)
    VALUES (1, 1.0, union_value(inum := 10), 0);
";

/// Creates a database file in the old schema, with the engine's
/// raw driver.
pub fn make_v1(engine: Engine, path: &Path) {
    match engine {
        #[cfg(feature = "sqlite")]
        Engine::Sqlite => {
            let c = rusqlite::Connection::open(path).unwrap();
            c.execute_batch(V1_SQLITE).unwrap();
        }
        #[cfg(feature = "duckdb")]
        Engine::DuckDb => {
            let c = duckdb::Connection::open(path).unwrap();
            c.execute_batch(V1_DUCKDB).unwrap();
        }
        #[allow(unreachable_patterns)]
        _ => unreachable!("engine {engine:?} is not enabled"),
    }
}
