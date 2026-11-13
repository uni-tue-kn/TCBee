"""Column-oriented sample batches and optional array/dataframe adapters."""

from dataclasses import dataclass

from ._util import integer

_NUMPY_DTYPES = {
    "bool": "bool",
    "u8": "uint8",
    "u16": "uint16",
    "u32": "uint32",
    "u64": "uint64",
    "i64": "int64",
    "f64": "float64",
    "text": "object",
}
_PANDAS_DTYPES = {
    "bool": "boolean",
    "u8": "UInt8",
    "u16": "UInt16",
    "u32": "UInt32",
    "u64": "UInt64",
    "i64": "Int64",
    "f64": "float64",
    "text": "object",
}


@dataclass
class Samples:
    """Three equally sized columns; no per-sample wrapper objects.

    ts_ns and seq remain exact integers. Eager reads own their data and can be
    used after the database closes. Values preserve stored NULLs as None.
    """

    ts_ns: list[int]
    seq: list[int]
    values: list
    value_type: str

    def __len__(self):
        return len(self.ts_ns)

    def seconds(self, *, origin_ns):
        """Seconds from an explicit shared origin, subtracting before rounding."""
        integer(origin_ns, "origin_ns")
        return [(timestamp - origin_ns) / 1e9 for timestamp in self.ts_ns]

    def to_numpy(self):
        """Return ts_ns, seq, value arrays; nullable values use object dtype.

        Imports NumPy only when called. No integer column is converted to float.
        """
        import numpy as np

        dtype = "object" if None in self.values else _NUMPY_DTYPES[self.value_type]
        return {
            "ts_ns": np.asarray(self.ts_ns, dtype="int64"),
            "seq": np.asarray(self.seq, dtype="int64"),
            "value": np.asarray(self.values, dtype=dtype),
        }

    def to_frame(self):
        """Return a pandas DataFrame with explicit integer/nullable dtypes.

        Floating values containing NULL use object dtype, so NULL stays None. The index does not imply metric alignment.
        """
        import pandas as pd

        dtype = _PANDAS_DTYPES[self.value_type]
        if self.value_type == "f64" and None in self.values:
            dtype = "object"
        return pd.DataFrame(
            {
                "ts_ns": pd.Series(self.ts_ns, dtype="int64"),
                "seq": pd.Series(self.seq, dtype="int64"),
                "value": pd.Series(self.values, dtype=dtype),
            }
        )
