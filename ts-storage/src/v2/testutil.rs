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
