//! `EventBatch` to Arrow `RecordBatch`.

use std::sync::Arc;

use ::duckdb::arrow::array::{
    ArrayRef, BooleanArray, Float64Array, Int64Array, Int8Array, StringArray, UInt16Array,
    UInt32Array, UInt64Array, UInt8Array,
};
use ::duckdb::arrow::datatypes::{DataType, Field, Schema};
use ::duckdb::arrow::record_batch::RecordBatch;

use crate::v2::batch::{ColumnData, EventBatch};
use crate::v2::error::StoreError;
use crate::v2::schema::ColType;

fn arrow_type(ty: ColType) -> DataType {
    match ty {
        ColType::Bool => DataType::Boolean,
        ColType::U8 => DataType::UInt8,
        ColType::U16 => DataType::UInt16,
        ColType::U32 => DataType::UInt32,
        ColType::U64 => DataType::UInt64,
        ColType::I64 => DataType::Int64,
        ColType::F64 => DataType::Float64,
        ColType::Text => DataType::Utf8,
    }
}

/// Validates the batch and moves it into an Arrow record batch. Numeric `Vec`s become Arrow
/// buffers without a copy; bool and text are re-encoded. `dir` is a `TINYINT` (codes 0..=2):
/// the `Vec<u8>` to `Vec<i8>` collect is an in-place iterator collect, so there is no extra
/// copy in practice.
pub(crate) fn to_record_batch(batch: EventBatch) -> Result<RecordBatch, StoreError> {
    batch.validate()?;
    let table = batch.table();
    let mut fields = vec![
        Field::new("flow_id", DataType::Int64, false),
        Field::new("dir", DataType::Int8, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("seq", DataType::Int64, false),
    ];
    fields.extend(
        table
            .columns
            .iter()
            .map(|c| Field::new(c.name, arrow_type(c.ty), false)),
    );
    let (flow_id, dir, ts, seq, cols) = batch.into_parts();
    let mut arrays: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from(flow_id)),
        Arc::new(Int8Array::from(
            dir.into_iter().map(|d| d as i8).collect::<Vec<i8>>(),
        )),
        Arc::new(Int64Array::from(ts)),
        Arc::new(Int64Array::from(seq)),
    ];
    for c in cols {
        arrays.push(match c {
            ColumnData::Bool(v) => Arc::new(BooleanArray::from(v)),
            ColumnData::U8(v) => Arc::new(UInt8Array::from(v)),
            ColumnData::U16(v) => Arc::new(UInt16Array::from(v)),
            ColumnData::U32(v) => Arc::new(UInt32Array::from(v)),
            ColumnData::U64(v) => Arc::new(UInt64Array::from(v)),
            ColumnData::I64(v) => Arc::new(Int64Array::from(v)),
            ColumnData::F64(v) => Arc::new(Float64Array::from(v)),
            ColumnData::Text(v) => Arc::new(StringArray::from(v)),
        });
    }
    RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays)
        .map_err(|e| StoreError::TypeMismatch(format!("arrow: {e}")))
}
