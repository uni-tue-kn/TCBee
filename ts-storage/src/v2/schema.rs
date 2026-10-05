//! Schema of the v2 database as plain Rust data, plus the DDL renderer for both engines.

use super::error::StoreError;

/// Version written to `meta.schema_version`.
pub const SCHEMA_VERSION: i64 = 2;

/// Names of the four fixed columns at the front of every event table.
pub(crate) const FIXED_EVENT_COLUMNS: [&str; 4] = ["flow_id", "dir", "ts", "seq"];

/// Storage type of an event column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ColType {
    Bool = 0,
    U8 = 1,
    U16 = 2,
    U32 = 3,
    U64 = 4,
    I64 = 5,
    F64 = 6,
    Text = 7,
}

impl ColType {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: i64) -> Option<ColType> {
        match code {
            0 => Some(ColType::Bool),
            1 => Some(ColType::U8),
            2 => Some(ColType::U16),
            3 => Some(ColType::U32),
            4 => Some(ColType::U64),
            5 => Some(ColType::I64),
            6 => Some(ColType::F64),
            7 => Some(ColType::Text),
            _ => None,
        }
    }

    /// The kind of `DataValue` the read API returns for this column type.
    pub fn value_kind(self) -> ValueKind {
        match self {
            ColType::Bool => ValueKind::Bool,
            ColType::U8 | ColType::U16 | ColType::U32 | ColType::U64 | ColType::I64 => {
                ValueKind::Int
            }
            ColType::F64 => ValueKind::Float,
            ColType::Text => ValueKind::String,
        }
    }

    fn sql(self, d: Dialect) -> &'static str {
        match (d, self) {
            (Dialect::DuckDb, ColType::Bool) => "BOOLEAN",
            (Dialect::DuckDb, ColType::U8) => "UTINYINT",
            (Dialect::DuckDb, ColType::U16) => "USMALLINT",
            (Dialect::DuckDb, ColType::U32) => "UINTEGER",
            (Dialect::DuckDb, ColType::U64) => "UBIGINT",
            (Dialect::DuckDb, ColType::I64) => "BIGINT",
            (Dialect::DuckDb, ColType::F64) => "DOUBLE",
            (Dialect::DuckDb, ColType::Text) => "VARCHAR",
            (Dialect::Sqlite, ColType::F64) => "REAL",
            (Dialect::Sqlite, ColType::Text) => "TEXT",
            (Dialect::Sqlite, _) => "INTEGER",
        }
    }
}

/// The four kinds of values a derived series can hold (the kinds of `DataValue`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueKind {
    Int,
    Float,
    Bool,
    String,
}

impl From<ValueKind> for ColType {
    fn from(k: ValueKind) -> ColType {
        match k {
            ValueKind::Int => ColType::I64,
            ValueKind::Float => ColType::F64,
            ValueKind::Bool => ColType::Bool,
            ValueKind::String => ColType::Text,
        }
    }
}

/// Direction of a trace file, stored in `ev_*.dir` and `series.dir`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Dir {
    None = 0,
    Send = 1,
    Recv = 2,
}

impl Dir {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: i64) -> Option<Dir> {
        match code {
            0 => Some(Dir::None),
            1 => Some(Dir::Send),
            2 => Some(Dir::Recv),
            _ => None,
        }
    }
}

/// `series.kind`: raw series point at an event table column, derived ones at `derived_samples`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SeriesKind {
    Raw = 0,
    Derived = 1,
}

impl SeriesKind {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: i64) -> Option<SeriesKind> {
        match code {
            0 => Some(SeriesKind::Raw),
            1 => Some(SeriesKind::Derived),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    DuckDb,
}

/// One column of an event table (a binding field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: &'static str,
    pub ty: ColType,
}

/// An event table `ev_<source>`: the four fixed columns plus one column per binding field.
#[derive(Debug, PartialEq, Eq)]
pub struct EventTable {
    /// `"sock"`; the table is `"ev_" + source`.
    pub source: &'static str,
    /// Binding fields, without the four fixed columns.
    pub columns: &'static [Column],
}

impl EventTable {
    pub fn table_name(&self) -> String {
        format!("ev_{}", self.source)
    }

    /// Checks that column names are unique and do not collide with the fixed columns
    /// (case-insensitively). `EventBatch::new` and `create_table_sql` run it and panic on a
    /// violation, since table definitions are static.
    pub fn check(&self) -> Result<(), StoreError> {
        for (i, c) in self.columns.iter().enumerate() {
            if FIXED_EVENT_COLUMNS
                .iter()
                .any(|f| f.eq_ignore_ascii_case(c.name))
            {
                return Err(StoreError::TypeMismatch(format!(
                    "column {} of table {} clashes with a fixed column",
                    c.name, self.source
                )));
            }
            if self.columns[..i]
                .iter()
                .any(|o| o.name.eq_ignore_ascii_case(c.name))
            {
                return Err(StoreError::TypeMismatch(format!(
                    "duplicate column {} in table {}",
                    c.name, self.source
                )));
            }
        }
        Ok(())
    }
}

/// SQL type of a column of a fixed table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlType {
    Text,
    BigInt,
    Integer,
    TinyInt,
    Double,
    Boolean,
}

impl SqlType {
    fn sql(self, d: Dialect) -> &'static str {
        match (d, self) {
            (_, SqlType::Text) => "TEXT",
            (Dialect::DuckDb, SqlType::BigInt) => "BIGINT",
            (Dialect::DuckDb, SqlType::Integer) => "INTEGER",
            (Dialect::DuckDb, SqlType::TinyInt) => "TINYINT",
            (Dialect::DuckDb, SqlType::Double) => "DOUBLE",
            (Dialect::DuckDb, SqlType::Boolean) => "BOOLEAN",
            (Dialect::Sqlite, SqlType::Double) => "REAL",
            (Dialect::Sqlite, _) => "INTEGER",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FixedColumn {
    pub name: &'static str,
    pub ty: SqlType,
    pub not_null: bool,
}

/// A table with a fixed, hand-written definition.
#[derive(Debug)]
pub struct Table {
    pub name: &'static str,
    pub columns: &'static [FixedColumn],
    /// Table constraints, as SQL text. Static, never user-supplied.
    pub constraints: &'static [&'static str],
}

const fn col(name: &'static str, ty: SqlType, not_null: bool) -> FixedColumn {
    FixedColumn { name, ty, not_null }
}

pub static META: Table = Table {
    name: "meta",
    columns: &[
        col("key", SqlType::Text, true),
        col("value", SqlType::Text, true),
    ],
    constraints: &["PRIMARY KEY (\"key\")"],
};

pub static FLOWS: Table = Table {
    name: "flows",
    columns: &[
        col("id", SqlType::BigInt, true),
        col("src", SqlType::Text, true),
        col("dst", SqlType::Text, true),
        col("sport", SqlType::Integer, true),
        col("dport", SqlType::Integer, true),
        col("l4proto", SqlType::Integer, true),
    ],
    constraints: &[
        "PRIMARY KEY (\"id\")",
        "UNIQUE (\"src\", \"dst\", \"sport\", \"dport\", \"l4proto\")",
    ],
};

pub static SERIES: Table = Table {
    name: "series",
    columns: &[
        col("id", SqlType::BigInt, true),
        col("flow_id", SqlType::BigInt, true),
        col("kind", SqlType::Integer, true),
        col("source", SqlType::Text, true),
        col("dir", SqlType::Integer, true),
        col("name", SqlType::Text, true),
        col("value_type", SqlType::Integer, true),
        col("tbl", SqlType::Text, false),
        col("col", SqlType::Text, false),
        col("n", SqlType::BigInt, true),
        col("t_min", SqlType::BigInt, false),
        col("t_max", SqlType::BigInt, false),
        col("v_min", SqlType::Double, false),
        col("v_max", SqlType::Double, false),
    ],
    constraints: &[
        "PRIMARY KEY (\"id\")",
        "UNIQUE (\"flow_id\", \"source\", \"dir\", \"name\")",
    ],
};

pub static DERIVED_SAMPLES: Table = Table {
    name: "derived_samples",
    columns: &[
        col("series_id", SqlType::BigInt, true),
        col("ts", SqlType::BigInt, true),
        col("seq", SqlType::BigInt, true),
        col("v_int", SqlType::BigInt, false),
        col("v_float", SqlType::Double, false),
        col("v_bool", SqlType::Boolean, false),
        col("v_text", SqlType::Text, false),
    ],
    constraints: &[],
};

/// Quotes an identifier with `"`, doubling embedded quotes.
pub(crate) fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn render_create(name: &str, cols: Vec<String>, constraints: &[&str]) -> String {
    let mut lines = cols;
    lines.extend(constraints.iter().map(|c| c.to_string()));
    format!(
        "CREATE TABLE {} (\n    {}\n)",
        quote_ident(name),
        lines.join(",\n    ")
    )
}

/// `CREATE TABLE` for an event table.
pub fn create_table_sql(d: Dialect, t: &EventTable) -> String {
    if let Err(e) = t.check() {
        panic!("invalid event table definition: {e}");
    }
    let dir_ty = SqlType::TinyInt.sql(d);
    let big = SqlType::BigInt.sql(d);
    let mut cols = vec![
        format!("\"flow_id\" {big} NOT NULL"),
        format!("\"dir\" {dir_ty} NOT NULL"),
        format!("\"ts\" {big} NOT NULL"),
        format!("\"seq\" {big} NOT NULL"),
    ];
    cols.extend(
        t.columns
            .iter()
            .map(|c| format!("{} {} NOT NULL", quote_ident(c.name), c.ty.sql(d))),
    );
    render_create(&t.table_name(), cols, &[])
}

/// `CREATE TABLE` for one of the fixed tables.
pub fn create_fixed_table_sql(d: Dialect, t: &Table) -> String {
    let cols = t
        .columns
        .iter()
        .map(|c| {
            format!(
                "{} {}{}",
                quote_ident(c.name),
                c.ty.sql(d),
                if c.not_null { " NOT NULL" } else { "" }
            )
        })
        .collect();
    render_create(t.name, cols, t.constraints)
}

/// Index over `(flow_id, dir, ts, seq)`; SQLite only, DuckDB builds no indexes on event tables.
pub fn create_index_sql(d: Dialect, t: &EventTable) -> Option<String> {
    match d {
        Dialect::DuckDb => None,
        Dialect::Sqlite => Some(format!(
            "CREATE INDEX {} ON {} (\"flow_id\", \"dir\", \"ts\", \"seq\")",
            quote_ident(&format!("{}_idx", t.table_name())),
            quote_ident(&t.table_name())
        )),
    }
}

/// Index of `derived_samples`; SQLite only, created together with the table.
pub fn create_derived_index_sql(d: Dialect) -> Option<String> {
    match d {
        Dialect::DuckDb => None,
        Dialect::Sqlite => Some(
            "CREATE INDEX \"derived_samples_idx\" ON \"derived_samples\" (\"series_id\", \"ts\", \"seq\")"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::testutil::DEMO;

    #[test]
    fn ddl_duckdb() {
        assert_eq!(
            create_table_sql(Dialect::DuckDb, &DEMO),
            concat!(
                "CREATE TABLE \"ev_demo\" (\n",
                "    \"flow_id\" BIGINT NOT NULL,\n",
                "    \"dir\" TINYINT NOT NULL,\n",
                "    \"ts\" BIGINT NOT NULL,\n",
                "    \"seq\" BIGINT NOT NULL,\n",
                "    \"SND_CWND\" UINTEGER NOT NULL,\n",
                "    \"pacing_rate\" UBIGINT NOT NULL,\n",
                "    \"ok\" BOOLEAN NOT NULL\n",
                ")"
            )
        );
        assert_eq!(create_index_sql(Dialect::DuckDb, &DEMO), None);
        assert_eq!(create_derived_index_sql(Dialect::DuckDb), None);
    }

    #[test]
    fn ddl_sqlite() {
        assert_eq!(
            create_table_sql(Dialect::Sqlite, &DEMO),
            concat!(
                "CREATE TABLE \"ev_demo\" (\n",
                "    \"flow_id\" INTEGER NOT NULL,\n",
                "    \"dir\" INTEGER NOT NULL,\n",
                "    \"ts\" INTEGER NOT NULL,\n",
                "    \"seq\" INTEGER NOT NULL,\n",
                "    \"SND_CWND\" INTEGER NOT NULL,\n",
                "    \"pacing_rate\" INTEGER NOT NULL,\n",
                "    \"ok\" INTEGER NOT NULL\n",
                ")"
            )
        );
        assert_eq!(
            create_index_sql(Dialect::Sqlite, &DEMO).unwrap(),
            r#"CREATE INDEX "ev_demo_idx" ON "ev_demo" ("flow_id", "dir", "ts", "seq")"#
        );
        assert_eq!(
            create_derived_index_sql(Dialect::Sqlite).unwrap(),
            r#"CREATE INDEX "derived_samples_idx" ON "derived_samples" ("series_id", "ts", "seq")"#
        );
    }

    #[test]
    fn ddl_fixed_tables() {
        assert_eq!(
            create_fixed_table_sql(Dialect::DuckDb, &FLOWS),
            concat!(
                "CREATE TABLE \"flows\" (\n",
                "    \"id\" BIGINT NOT NULL,\n",
                "    \"src\" TEXT NOT NULL,\n",
                "    \"dst\" TEXT NOT NULL,\n",
                "    \"sport\" INTEGER NOT NULL,\n",
                "    \"dport\" INTEGER NOT NULL,\n",
                "    \"l4proto\" INTEGER NOT NULL,\n",
                "    PRIMARY KEY (\"id\"),\n",
                "    UNIQUE (\"src\", \"dst\", \"sport\", \"dport\", \"l4proto\")\n",
                ")"
            )
        );
        assert_eq!(
            create_fixed_table_sql(Dialect::Sqlite, &SERIES),
            concat!(
                "CREATE TABLE \"series\" (\n",
                "    \"id\" INTEGER NOT NULL,\n",
                "    \"flow_id\" INTEGER NOT NULL,\n",
                "    \"kind\" INTEGER NOT NULL,\n",
                "    \"source\" TEXT NOT NULL,\n",
                "    \"dir\" INTEGER NOT NULL,\n",
                "    \"name\" TEXT NOT NULL,\n",
                "    \"value_type\" INTEGER NOT NULL,\n",
                "    \"tbl\" TEXT,\n",
                "    \"col\" TEXT,\n",
                "    \"n\" INTEGER NOT NULL,\n",
                "    \"t_min\" INTEGER,\n",
                "    \"t_max\" INTEGER,\n",
                "    \"v_min\" REAL,\n",
                "    \"v_max\" REAL,\n",
                "    PRIMARY KEY (\"id\"),\n",
                "    UNIQUE (\"flow_id\", \"source\", \"dir\", \"name\")\n",
                ")"
            )
        );
        assert_eq!(
            create_fixed_table_sql(Dialect::DuckDb, &DERIVED_SAMPLES),
            concat!(
                "CREATE TABLE \"derived_samples\" (\n",
                "    \"series_id\" BIGINT NOT NULL,\n",
                "    \"ts\" BIGINT NOT NULL,\n",
                "    \"seq\" BIGINT NOT NULL,\n",
                "    \"v_int\" BIGINT,\n",
                "    \"v_float\" DOUBLE,\n",
                "    \"v_bool\" BOOLEAN,\n",
                "    \"v_text\" TEXT\n",
                ")"
            )
        );
        assert_eq!(
            create_fixed_table_sql(Dialect::Sqlite, &META),
            concat!(
                "CREATE TABLE \"meta\" (\n",
                "    \"key\" TEXT NOT NULL,\n",
                "    \"value\" TEXT NOT NULL,\n",
                "    PRIMARY KEY (\"key\")\n",
                ")"
            )
        );
    }

    #[test]
    fn column_name_checks() {
        assert!(DEMO.check().is_ok());
        static BAD: [Column; 1] = [Column {
            name: "Seq",
            ty: ColType::U8,
        }];
        assert!(EventTable {
            source: "x",
            columns: &BAD
        }
        .check()
        .is_err());
        static DUP: [Column; 2] = [
            Column {
                name: "a",
                ty: ColType::U8,
            },
            Column {
                name: "A",
                ty: ColType::U8,
            },
        ];
        assert!(EventTable {
            source: "x",
            columns: &DUP
        }
        .check()
        .is_err());
    }

    #[test]
    #[should_panic(expected = "invalid event table")]
    fn ddl_rejects_reserved_column() {
        static BAD: [Column; 1] = [Column {
            name: "TS",
            ty: ColType::U8,
        }];
        create_table_sql(
            Dialect::Sqlite,
            &EventTable {
                source: "x",
                columns: &BAD,
            },
        );
    }

    #[test]
    fn codes_and_kinds() {
        for c in 0..8 {
            assert_eq!(ColType::from_code(c).unwrap().code() as i64, c);
        }
        assert_eq!(ColType::from_code(8), None);
        assert_eq!(ColType::from(ValueKind::Int), ColType::I64);
        assert_eq!(ColType::from(ValueKind::Bool), ColType::Bool);
        assert_eq!(ColType::U64.value_kind(), ValueKind::Int);
        assert_eq!(ColType::Text.value_kind(), ValueKind::String);
        assert_eq!(Dir::from_code(2), Some(Dir::Recv));
        assert_eq!(Dir::from_code(3), None);
        assert_eq!(SeriesKind::from_code(1), Some(SeriesKind::Derived));
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
    }
}
