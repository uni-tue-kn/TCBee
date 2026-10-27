//! Table definitions shared by the unit tests.

use super::schema::{ColType, Column, EventTable};

const fn c(name: &'static str, ty: ColType) -> Column {
    Column { name, ty }
}

static DEMO_COLS: [Column; 3] = [
    c("SND_CWND", ColType::U32),
    c("pacing_rate", ColType::U64),
    c("ok", ColType::Bool),
];
pub static DEMO: EventTable = EventTable {
    source: "demo",
    columns: &DEMO_COLS,
};

static ZETA_COLS: [Column; 4] = [
    c("u", ColType::U64),
    c("i", ColType::I64),
    c("f", ColType::F64),
    c("t", ColType::Text),
];
/// Source "zeta": u64, i64, f64, text.
pub static ZETA: EventTable = EventTable {
    source: "zeta",
    columns: &ZETA_COLS,
};

static ALPHA_COLS: [Column; 2] = [c("b", ColType::Bool), c("w", ColType::U16)];
/// Source "alpha" (sorts before "zeta"): bool, u16.
pub static ALPHA: EventTable = EventTable {
    source: "alpha",
    columns: &ALPHA_COLS,
};

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use super::batch::EventBatch;
use super::schema::Dir;
use crate::{DataPoint, DataValue, Flow, IpTuple};

/// A unique database path in the temp dir. Dropping it removes the file, the `.partial` file and
/// the SQLite/DuckDB sidecars of both.
pub struct TmpDb(PathBuf);

impl TmpDb {
    pub fn new() -> TmpDb {
        static N: AtomicU32 = AtomicU32::new(0);
        TmpDb(std::env::temp_dir().join(format!(
            "ts_storage_{}_{}.db",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// `<path>.partial`
    pub fn partial(&self) -> PathBuf {
        self.suffixed(".partial")
    }

    pub fn suffixed(&self, suffix: &str) -> PathBuf {
        let mut s = self.0.as_os_str().to_owned();
        s.push(suffix);
        PathBuf::from(s)
    }
}

impl Default for TmpDb {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TmpDb {
    fn drop(&mut self) {
        for suffix in [
            "",
            "-journal",
            "-wal",
            "-shm",
            ".wal",
            ".partial",
            ".partial-journal",
            ".partial-wal",
            ".partial-shm",
            ".partial.wal",
        ] {
            let _ = std::fs::remove_file(self.suffixed(suffix));
        }
    }
}

/// `10.0.0.1:sport -> 2001:db8::2:80`, protocol 6.
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

/// `(flow_id, dir, ts, seq, u, i, f, t)`: one row of the `ZETA` table.
pub type ZetaRow = (i64, Dir, i64, i64, u64, i64, f64, &'static str);

pub fn zeta_batch(rows: &[ZetaRow]) -> EventBatch {
    let mut b = EventBatch::new(&ZETA, rows.len());
    for (flow, dir, ts, seq, u, i, f, t) in rows {
        b.push_header(*flow, *dir, *ts, *seq);
        b.u64(0).push(*u);
        b.i64(1).push(*i);
        b.f64(2).push(*f);
        b.text(3).push((*t).into());
    }
    b
}

/// `(flow_id, ts, seq, b, w)`: one row of the `ALPHA` table (direction none).
#[cfg(feature = "duckdb")]
pub type AlphaRow = (i64, i64, i64, bool, u16);

#[cfg(feature = "duckdb")]
pub fn alpha_batch(rows: &[AlphaRow]) -> EventBatch {
    let mut b = EventBatch::new(&ALPHA, rows.len());
    for (flow, ts, seq, x, w) in rows {
        b.push_header(*flow, Dir::None, *ts, *seq);
        b.bool(0).push(*x);
        b.u16(1).push(*w);
    }
    b
}

/// Derived samples from `(timestamp, value)` pairs.
pub fn pts(v: &[(f64, DataValue)]) -> Vec<DataPoint> {
    v.iter()
        .map(|(t, v)| DataPoint {
            timestamp: *t,
            value: v.clone(),
        })
        .collect()
}
