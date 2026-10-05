//! Column-oriented ingest batch.

use super::error::StoreError;
use super::schema::{ColType, Dir, EventTable};

#[derive(Debug, Clone, PartialEq)]
pub enum ColumnData {
    Bool(Vec<bool>),
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    U64(Vec<u64>),
    I64(Vec<i64>),
    F64(Vec<f64>),
    Text(Vec<String>),
}

impl ColumnData {
    fn new(ty: ColType, cap: usize) -> ColumnData {
        match ty {
            ColType::Bool => ColumnData::Bool(Vec::with_capacity(cap)),
            ColType::U8 => ColumnData::U8(Vec::with_capacity(cap)),
            ColType::U16 => ColumnData::U16(Vec::with_capacity(cap)),
            ColType::U32 => ColumnData::U32(Vec::with_capacity(cap)),
            ColType::U64 => ColumnData::U64(Vec::with_capacity(cap)),
            ColType::I64 => ColumnData::I64(Vec::with_capacity(cap)),
            ColType::F64 => ColumnData::F64(Vec::with_capacity(cap)),
            ColType::Text => ColumnData::Text(Vec::with_capacity(cap)),
        }
    }

    pub fn col_type(&self) -> ColType {
        match self {
            ColumnData::Bool(_) => ColType::Bool,
            ColumnData::U8(_) => ColType::U8,
            ColumnData::U16(_) => ColType::U16,
            ColumnData::U32(_) => ColType::U32,
            ColumnData::U64(_) => ColType::U64,
            ColumnData::I64(_) => ColType::I64,
            ColumnData::F64(_) => ColType::F64,
            ColumnData::Text(_) => ColType::Text,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            ColumnData::Bool(v) => v.len(),
            ColumnData::U8(v) => v.len(),
            ColumnData::U16(v) => v.len(),
            ColumnData::U32(v) => v.len(),
            ColumnData::U64(v) => v.len(),
            ColumnData::I64(v) => v.len(),
            ColumnData::F64(v) => v.len(),
            ColumnData::Text(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn approx_bytes(&self) -> usize {
        match self {
            ColumnData::Bool(v) => v.len(),
            ColumnData::U8(v) => v.len(),
            ColumnData::U16(v) => v.len() * 2,
            ColumnData::U32(v) => v.len() * 4,
            ColumnData::U64(v) => v.len() * 8,
            ColumnData::I64(v) => v.len() * 8,
            ColumnData::F64(v) => v.len() * 8,
            ColumnData::Text(v) => v.iter().map(|s| s.len() + 24).sum(),
        }
    }
}

/// Rows for one event table, stored column by column.
#[derive(Debug, Clone)]
pub struct EventBatch {
    table: &'static EventTable,
    flow_id: Vec<i64>,
    dir: Vec<u8>,
    ts: Vec<i64>,
    seq: Vec<i64>,
    cols: Vec<ColumnData>,
}

macro_rules! accessor {
    ($name:ident, $variant:ident, $ty:ty) => {
        /// Typed access to column `col`; panics on a type mismatch.
        pub fn $name(&mut self, col: usize) -> &mut Vec<$ty> {
            match &mut self.cols[col] {
                ColumnData::$variant(v) => v,
                other => panic!(
                    "column {} of table {} is {:?}, not {}",
                    col,
                    self.table.source,
                    other.col_type(),
                    stringify!($variant)
                ),
            }
        }
    };
}

impl EventBatch {
    /// Panics if the table definition is invalid (`EventTable::check`).
    pub fn new(table: &'static EventTable, capacity: usize) -> Self {
        if let Err(e) = table.check() {
            panic!("invalid event table definition: {e}");
        }
        EventBatch {
            table,
            flow_id: Vec::with_capacity(capacity),
            dir: Vec::with_capacity(capacity),
            ts: Vec::with_capacity(capacity),
            seq: Vec::with_capacity(capacity),
            cols: table
                .columns
                .iter()
                .map(|c| ColumnData::new(c.ty, capacity))
                .collect(),
        }
    }

    pub fn push_header(&mut self, flow_id: i64, dir: Dir, ts: i64, seq: i64) {
        self.flow_id.push(flow_id);
        self.dir.push(dir.code());
        self.ts.push(ts);
        self.seq.push(seq);
    }

    accessor!(bool, Bool, bool);
    accessor!(u8, U8, u8);
    accessor!(u16, U16, u16);
    accessor!(u32, U32, u32);
    accessor!(u64, U64, u64);
    accessor!(i64, I64, i64);
    accessor!(f64, F64, f64);
    accessor!(text, Text, String);

    pub fn table(&self) -> &'static EventTable {
        self.table
    }

    /// Number of rows (length of the header columns).
    pub fn len(&self) -> usize {
        self.ts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ts.is_empty()
    }

    pub fn flow_ids(&self) -> &[i64] {
        &self.flow_id
    }

    pub fn dirs(&self) -> &[u8] {
        &self.dir
    }

    pub fn timestamps(&self) -> &[i64] {
        &self.ts
    }

    pub fn seqs(&self) -> &[i64] {
        &self.seq
    }

    pub fn columns(&self) -> &[ColumnData] {
        &self.cols
    }

    /// Splits the batch into `(flow_id, dir, ts, seq, columns)` without copying, for engines that
    /// hand the `Vec`s to a bulk-load API.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(self) -> (Vec<i64>, Vec<u8>, Vec<i64>, Vec<i64>, Vec<ColumnData>) {
        (self.flow_id, self.dir, self.ts, self.seq, self.cols)
    }

    /// Approximate payload size in bytes, for back-pressure decisions.
    pub fn approx_bytes(&self) -> usize {
        self.flow_id.len() * 8
            + self.dir.len()
            + self.ts.len() * 8
            + self.seq.len() * 8
            + self
                .cols
                .iter()
                .map(ColumnData::approx_bytes)
                .sum::<usize>()
    }

    /// Checks that all columns have the header's length, the types match the table and no `f64`
    /// value is NaN (all engines reject it, so they behave the same).
    pub fn validate(&self) -> Result<(), StoreError> {
        let n = self.len();
        if self.flow_id.len() != n || self.dir.len() != n || self.seq.len() != n {
            return Err(StoreError::TypeMismatch(format!(
                "header columns of {} differ in length",
                self.table.source
            )));
        }
        if self.cols.len() != self.table.columns.len() {
            return Err(StoreError::TypeMismatch(format!(
                "table {} has {} columns, batch has {}",
                self.table.source,
                self.table.columns.len(),
                self.cols.len()
            )));
        }
        for (def, data) in self.table.columns.iter().zip(&self.cols) {
            if data.col_type() != def.ty {
                return Err(StoreError::TypeMismatch(format!(
                    "column {} of {} is {:?}, expected {:?}",
                    def.name,
                    self.table.source,
                    data.col_type(),
                    def.ty
                )));
            }
            if matches!(data, ColumnData::F64(v) if v.iter().any(|x| x.is_nan())) {
                return Err(StoreError::TypeMismatch(format!(
                    "column {} of {} contains NaN (not storable: SQLite turns it into NULL)",
                    def.name, self.table.source
                )));
            }
            if data.len() != n {
                return Err(StoreError::TypeMismatch(format!(
                    "column {} of {} has {} values for {} rows",
                    def.name,
                    self.table.source,
                    data.len(),
                    n
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ZETA;

    fn push_row(b: &mut EventBatch, ts: i64) {
        b.push_header(1, Dir::Send, ts, 0);
        b.u64(0).push(7);
        b.i64(1).push(-1);
        b.f64(2).push(0.5);
        b.text(3).push("x".into());
    }

    #[test]
    fn push_and_validate() {
        let mut b = EventBatch::new(&ZETA, 4);
        assert!(b.is_empty());
        b.push_header(1, Dir::Send, 100, 0);
        b.u64(0).push(7);
        assert!(b.validate().is_err()); // other columns are short
        let mut b = EventBatch::new(&ZETA, 4);
        push_row(&mut b, 100);
        assert!(b.validate().is_ok());
        assert_eq!(b.len(), 1);
        assert!(b.approx_bytes() > 8 * 3);
        b.push_header(1, Dir::Send, 101, 1);
        assert!(b.validate().is_err()); // columns are one row short
    }

    #[test]
    #[should_panic(expected = "not U32")]
    fn wrong_accessor_panics() {
        let mut b = EventBatch::new(&ZETA, 1);
        b.u32(0);
    }

    #[test]
    fn nan_is_rejected() {
        let mut b = EventBatch::new(&ZETA, 2);
        push_row(&mut b, 1);
        assert!(b.validate().is_ok());
        b.push_header(1, Dir::Send, 2, 1);
        b.u64(0).push(1);
        b.i64(1).push(1);
        b.f64(2).push(f64::NAN);
        b.text(3).push(String::new());
        assert!(matches!(b.validate(), Err(StoreError::TypeMismatch(m)) if m.contains("NaN")));
        // Infinities are fine.
        b.f64(2)[1] = f64::INFINITY;
        assert!(b.validate().is_ok());
    }

    #[test]
    fn validate_detects_type_mismatch() {
        let mut b = EventBatch::new(&ZETA, 1);
        b.cols[0] = ColumnData::U32(vec![]);
        assert!(matches!(b.validate(), Err(StoreError::TypeMismatch(_))));
    }
}
