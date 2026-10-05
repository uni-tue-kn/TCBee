//! The `Event` trait and the `event_schema!` macro that declares a binding's event table.
//!
//! A binding names every column once, in the macro call. The column name is the series name the
//! visualizer matches on (mixed case, and the `SSTRESH` spelling of `tcp_probe`, are part of it).
//! The column type is the struct field's type; `push_row` does not compile if the two disagree.

use std::fmt;

use ts_storage::{EventBatch, EventTable, IpTuple};

/// Why a record could not be decoded.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer is not exactly one record long.
    Size { expected: usize, got: usize },
    /// bincode rejected the buffer.
    Bincode(String),
    /// The 4 byte divider at the end of the record is wrong: the file is misaligned or corrupt.
    Divider,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Size { expected, got } => {
                write!(f, "record is {got} bytes, expected {expected}")
            }
            DecodeError::Bincode(e) => write!(f, "cannot decode record: {e}"),
            DecodeError::Divider => write!(f, "record divider mismatch (misaligned trace file)"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// One trace record type with its event table.
pub trait Event: Sized {
    /// Table of this binding: `source` and one column per field, in field order.
    const TABLE: &'static EventTable;
    /// Size of one record in the trace file (the bincode encoding).
    const ENTRY_SIZE: usize;

    /// Decodes exactly `ENTRY_SIZE` bytes. Does not check the divider (see `check_divider`).
    fn decode(buf: &[u8]) -> Result<Self, DecodeError>;
    /// Flow identity of the record. The address decoding differs per binding on purpose (family
    /// vs `addr_v4 != 0`, host vs network byte order), so it is written out for each one.
    fn flow_key(&self) -> IpTuple;
    /// Recorder timestamp, nanoseconds since boot.
    fn ts_ns(&self) -> i64;
    /// Whether the 4 byte divider at the end of the record is intact.
    fn check_divider(&self) -> bool;
    /// Appends the field values to the column vectors of `batch`; the caller has already pushed
    /// the header (flow, dir, ts, seq).
    fn push_row(&self, batch: &mut EventBatch);
}

/// Object safe view of a decoded `Event` (`Event` has consts and `Sized`), so the file table can
/// hold one decoder function pointer per binding.
pub trait Row {
    fn flow_key(&self) -> IpTuple;
    fn ts_ns(&self) -> i64;
    fn push_row(&self, batch: &mut EventBatch);
}

impl<E: Event> Row for E {
    fn flow_key(&self) -> IpTuple {
        Event::flow_key(self)
    }
    fn ts_ns(&self) -> i64 {
        Event::ts_ns(self)
    }
    fn push_row(&self, batch: &mut EventBatch) {
        Event::push_row(self, batch)
    }
}

/// bincode decoding shared by all bindings. A failure is an error, not a `Default` record.
pub fn decode_bincode<T: serde::de::DeserializeOwned>(
    buf: &[u8],
    entry_size: usize,
) -> Result<T, DecodeError> {
    if buf.len() != entry_size {
        return Err(DecodeError::Size {
            expected: entry_size,
            got: buf.len(),
        });
    }
    bincode::deserialize(buf).map_err(|e| DecodeError::Bincode(e.to_string()))
}

// Typed accessors (not a generic push) so that a field whose type differs from its declared
// column type is a compile error.
macro_rules! push_col {
    ($b:ident, $i:expr, Bool, $v:expr) => {
        $b.bool($i).push($v)
    };
    ($b:ident, $i:expr, U8, $v:expr) => {
        $b.u8($i).push($v)
    };
    ($b:ident, $i:expr, U16, $v:expr) => {
        $b.u16($i).push($v)
    };
    ($b:ident, $i:expr, U32, $v:expr) => {
        $b.u32($i).push($v)
    };
    ($b:ident, $i:expr, U64, $v:expr) => {
        $b.u64($i).push($v)
    };
    ($b:ident, $i:expr, I64, $v:expr) => {
        $b.i64($i).push($v)
    };
    ($b:ident, $i:expr, F64, $v:expr) => {
        $b.f64($i).push($v)
    };
    ($b:ident, $i:expr, Text, $v:expr) => {
        $b.text($i).push($v)
    };
}
pub(crate) use push_col;

macro_rules! col_name {
    ($field:ident) => {
        stringify!($field)
    };
    ($field:ident, $col:literal) => {
        $col
    };
}
pub(crate) use col_name;

/// Declares the `Event` impl of a binding. A column is `field: Type` when the column name equals
/// the field name, otherwise `field => "name": Type`:
///
/// ```ignore
/// event_schema! {
///     TcpProbe => "tcp_probe" {
///         mark => "MARK": U32,
///         ssthresh => "SSTRESH": U32,
///     }
///     { fn flow_key(&self) -> IpTuple { /* ... */ } }
/// }
/// ```
///
/// The struct needs the fields `time` (u64, ns) and `div` (`[u8; 4]`), a `Deserialize` impl, and a
/// `FromBuffer` impl (its `ENTRY_SIZE` is reused until WP6 removes the old reader). The block
/// after the columns holds the hand-written `flow_key`.
macro_rules! event_schema {
    (
        $ty:ty => $source:literal {
            $( $field:ident $(=> $col:literal)? : $ct:ident ),+ $(,)?
        }
        { $($extra:tt)* }
    ) => {
        impl $crate::event::Event for $ty {
            const TABLE: &'static ::ts_storage::EventTable = &::ts_storage::EventTable {
                source: $source,
                columns: &[
                    $( ::ts_storage::Column {
                        name: $crate::event::col_name!($field $(, $col)?),
                        ty: ::ts_storage::ColType::$ct,
                    } ),+
                ],
            };
            const ENTRY_SIZE: usize = <$ty as $crate::reader::FromBuffer>::ENTRY_SIZE;

            fn decode(buf: &[u8]) -> Result<Self, $crate::event::DecodeError> {
                $crate::event::decode_bincode::<$ty>(buf, <Self as $crate::event::Event>::ENTRY_SIZE)
            }
            fn ts_ns(&self) -> i64 {
                self.time as i64
            }
            fn check_divider(&self) -> bool {
                self.div == 0xFFFFFFFFu32.to_be_bytes()
            }
            fn push_row(&self, b: &mut ::ts_storage::EventBatch) {
                $crate::event::event_schema!(@push b, self, 0usize; $( $field : $ct ),+);
            }
            $($extra)*
        }
    };
    (@push $b:ident, $s:ident, $i:expr; ) => {};
    (@push $b:ident, $s:ident, $i:expr; $f:ident : $ct:ident $(, $rf:ident : $rct:ident)*) => {
        $crate::event::push_col!($b, $i, $ct, $s.$f);
        $crate::event::event_schema!(@push $b, $s, $i + 1; $( $rf : $rct ),*);
    };
}
pub(crate) use event_schema;
