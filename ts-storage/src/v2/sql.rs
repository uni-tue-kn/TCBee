//! Portable (SQLite and DuckDB) statements. Identifiers come from static schema definitions and
//! are always quoted; values are always `?` parameters.

use super::schema::{quote_ident, ColType};

/// Column list of `series`, in `insert_series` parameter order.
pub const SERIES_COLUMNS: &str = r#""id", "flow_id", "kind", "source", "dir", "name", "value_type", "tbl", "col", "n", "t_min", "t_max", "v_min", "v_max""#;

fn points(tbl: &str, col: &str, extra: &str) -> String {
    format!(
        r#"SELECT "ts", {} FROM {} WHERE "flow_id" = ? AND "dir" = ?{} ORDER BY "ts", "seq""#,
        quote_ident(col),
        quote_ident(tbl),
        extra
    )
}

/// Parameters: flow_id, dir, ts_lo, ts_hi (both inclusive).
pub fn range_query(tbl: &str, col: &str) -> String {
    points(tbl, col, r#" AND "ts" >= ? AND "ts" <= ?"#)
}

/// Parameters: flow_id, dir.
pub fn all_points_query(tbl: &str, col: &str) -> String {
    points(tbl, col, "")
}

/// The `derived_samples` column that holds values of type `ty`.
pub fn derived_value_column(ty: ColType) -> &'static str {
    match ty {
        ColType::Bool => "v_bool",
        ColType::F64 => "v_float",
        ColType::Text => "v_text",
        ColType::U8 | ColType::U16 | ColType::U32 | ColType::U64 | ColType::I64 => "v_int",
    }
}

fn derived_points(ty: ColType, extra: &str) -> String {
    format!(
        r#"SELECT "ts", "{}" FROM "derived_samples" WHERE "series_id" = ?{} ORDER BY "ts", "seq""#,
        derived_value_column(ty),
        extra
    )
}

/// Parameters: series_id, ts_lo, ts_hi (both inclusive).
pub fn derived_range_query(ty: ColType) -> String {
    derived_points(ty, r#" AND "ts" >= ? AND "ts" <= ?"#)
}

/// Parameters: series_id.
pub fn derived_all_query(ty: ColType) -> String {
    derived_points(ty, "")
}

/// Parameters: series_id, ts, seq, then the value for the column of `ty`; the other value
/// columns stay NULL.
pub fn insert_derived_sample(ty: ColType) -> String {
    format!(
        r#"INSERT INTO "derived_samples" ("series_id", "ts", "seq", "{}") VALUES (?, ?, ?, ?)"#,
        derived_value_column(ty)
    )
}

pub const DELETE_DERIVED_SAMPLES: &str = r#"DELETE FROM "derived_samples" WHERE "series_id" = ?"#;

pub const INSERT_FLOW: &str = r#"INSERT INTO "flows" ("id", "src", "dst", "sport", "dport", "l4proto") VALUES (?, ?, ?, ?, ?, ?)"#;
pub const SELECT_FLOWS: &str =
    r#"SELECT "id", "src", "dst", "sport", "dport", "l4proto" FROM "flows" ORDER BY "id""#;
pub const SELECT_FLOW: &str =
    r#"SELECT "id", "src", "dst", "sport", "dport", "l4proto" FROM "flows" WHERE "id" = ?"#;

pub fn insert_series() -> String {
    format!(
        r#"INSERT INTO "series" ({SERIES_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
    )
}

pub fn select_series_by_flow() -> String {
    format!(r#"SELECT {SERIES_COLUMNS} FROM "series" WHERE "flow_id" = ? ORDER BY "id""#)
}

pub fn select_series_by_id() -> String {
    format!(r#"SELECT {SERIES_COLUMNS} FROM "series" WHERE "id" = ?"#)
}

pub const DELETE_SERIES: &str = r#"DELETE FROM "series" WHERE "id" = ?"#;
pub const MAX_SERIES_ID: &str = r#"SELECT MAX("id") FROM "series""#;

/// Parameters: n, t_min, t_max, v_min, v_max, id.
pub const UPDATE_SERIES_STATS: &str = r#"UPDATE "series" SET "n" = ?, "t_min" = ?, "t_max" = ?, "v_min" = ?, "v_max" = ? WHERE "id" = ?"#;

/// Parameters: key, value.
pub const UPSERT_META: &str = r#"INSERT INTO "meta" ("key", "value") VALUES (?, ?) ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value""#;
pub const SELECT_META: &str = r#"SELECT "key", "value" FROM "meta" ORDER BY "key""#;
pub const SELECT_META_VALUE: &str = r#"SELECT "value" FROM "meta" WHERE "key" = ?"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_query_text() {
        assert_eq!(
            range_query("ev_sock", "SND_CWND"),
            r#"SELECT "ts", "SND_CWND" FROM "ev_sock" WHERE "flow_id" = ? AND "dir" = ? AND "ts" >= ? AND "ts" <= ? ORDER BY "ts", "seq""#
        );
        assert_eq!(
            all_points_query("ev_sock", "a\"b"),
            r#"SELECT "ts", "a""b" FROM "ev_sock" WHERE "flow_id" = ? AND "dir" = ? ORDER BY "ts", "seq""#
        );
    }

    #[test]
    fn derived_and_catalog() {
        assert_eq!(
            derived_range_query(ColType::F64),
            r#"SELECT "ts", "v_float" FROM "derived_samples" WHERE "series_id" = ? AND "ts" >= ? AND "ts" <= ? ORDER BY "ts", "seq""#
        );
        assert_eq!(
            insert_derived_sample(ColType::Bool),
            r#"INSERT INTO "derived_samples" ("series_id", "ts", "seq", "v_bool") VALUES (?, ?, ?, ?)"#
        );
        assert_eq!(derived_value_column(ColType::I64), "v_int");
        assert_eq!(insert_series().matches('?').count(), 14);
        assert_eq!(SERIES_COLUMNS.split(", ").count(), 14);
        assert_eq!(
            select_series_by_id(),
            format!(r#"SELECT {SERIES_COLUMNS} FROM "series" WHERE "id" = ?"#)
        );
    }
}
