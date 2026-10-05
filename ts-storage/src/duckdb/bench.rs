//! Appender per batch vs. one cached appender (the numbers quoted in the module docs).
//!
//! `cargo test --release --lib bench_appender -- --ignored --nocapture`
//!
//! 2 M rows of a table with 4 fixed + 6 columns (20 M values) in batches of 4096 rows. Measured
//! on the development machine (release): cached 0.58 to 0.60 s (34 M values/s), appender
//! created and flushed per batch 1.37 s (14.5 M values/s), i.e. per-batch is 2.3x slower.

use super::*;
use crate::schema::Column;
use crate::testutil::TmpDb;
use std::time::{Duration, Instant};

static COLS: [Column; 6] = [
    Column {
        name: "a",
        ty: ColType::U32,
    },
    Column {
        name: "b",
        ty: ColType::U32,
    },
    Column {
        name: "c",
        ty: ColType::U64,
    },
    Column {
        name: "d",
        ty: ColType::U16,
    },
    Column {
        name: "e",
        ty: ColType::I64,
    },
    Column {
        name: "f",
        ty: ColType::F64,
    },
];
static T: EventTable = EventTable {
    source: "bench",
    columns: &COLS,
};
const ROWS: usize = 2_000_000;
const BATCH: usize = 4096;

fn make_batch(start: usize) -> EventBatch {
    let n = BATCH.min(ROWS - start);
    let mut b = EventBatch::new(&T, n);
    for k in 0..n {
        let i = (start + k) as u64;
        b.push_header(1 + (i % 7) as i64, Dir::Send, i as i64 * 1000, i as i64);
        b.u32(0).push(i as u32);
        b.u32(1).push((i * 3) as u32);
        b.u64(2).push(i * 5);
        b.u16(3).push(i as u16);
        b.i64(4).push(-(i as i64));
        b.f64(5).push(i as f64 * 0.25);
    }
    b
}

/// Seconds spent appending (batch construction excluded).
fn run(cached: bool) -> f64 {
    let db = TmpDb::new();
    let conn = Connection::open(db.path()).unwrap();
    conn.execute_batch(&create_table_sql(D, &T)).unwrap();
    let w = conn.try_clone().unwrap();
    let mut total = Duration::ZERO;
    let mut cached_app = cached.then(|| w.appender("ev_bench").unwrap());
    for start in (0..ROWS).step_by(BATCH) {
        let rb = to_record_batch(make_batch(start)).unwrap();
        let t0 = Instant::now();
        match &mut cached_app {
            Some(app) => app.append_record_batch(rb).unwrap(),
            None => {
                let mut app = w.appender("ev_bench").unwrap();
                app.append_record_batch(rb).unwrap();
                app.flush().unwrap();
            }
        }
        total += t0.elapsed();
    }
    if let Some(app) = &mut cached_app {
        let t0 = Instant::now();
        app.flush().unwrap();
        total += t0.elapsed();
    }
    drop(cached_app);
    let n: i64 = conn
        .query_row("SELECT count(*) FROM ev_bench", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, ROWS as i64);
    total.as_secs_f64()
}

#[test]
#[ignore = "benchmark"]
fn bench_appender_per_batch_vs_cached() {
    let values = (ROWS * 10) as f64;
    for round in 0..3 {
        let (p, c) = (run(false), run(true));
        eprintln!(
            "round {round}: per-batch {p:.3}s ({:.1} M values/s), cached {c:.3}s ({:.1} M values/s), per-batch {:+.0}%",
            values / p / 1e6,
            values / c / 1e6,
            (p / c - 1.0) * 100.0
        );
    }
}
