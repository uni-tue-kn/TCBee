"""Catalog-backed series selection and bounded sample reads."""

from dataclasses import dataclass, field, replace

from ._util import direction_code, integer, quote, window
from .errors import AmbiguousSelection, NotFound, TCBeeError
from .samples import Samples

_COLUMNS = (
    "id, flow_id, kind, source, dir, name, value_type, tbl, col, n, t_min, t_max, v_min, v_max"
)
_TYPES = ("bool", "u8", "u16", "u32", "u64", "i64", "f64", "text")
_DIRECTIONS = ("none", "send", "recv")


@dataclass(frozen=True)
class Gap:
    """Events missing between two recorded events of a series, found from hook_seq.

    start_ns and end_ns are the timestamps of the recorded events around the
    gap (start_ns <= end_ns). For events missing before the first recorded one,
    both are the timestamp of that event. first_seq is the hook_seq of the
    first missing event.
    """

    start_ns: int
    end_ns: int
    first_seq: int
    missing: int


@dataclass(frozen=True)
class Series:
    """One metric for a flow, source and direction, with stored summary bounds.

    minimum and maximum are approximate catalog values, not exact sample
    extrema. In particular the writer saturates u64 catalog bounds at i64::MAX.
    """

    _db: object = field(repr=False, compare=False)
    id: int
    flow_id: int
    kind: str
    source: str
    direction: str
    name: str
    value_type: str
    _table: str | None = field(repr=False)
    _column: str | None = field(repr=False)
    sample_count: int
    start_ns: int | None
    end_ns: int | None
    minimum: float | None
    maximum: float | None

    @classmethod
    def _from_row(cls, db, row):
        sid, fid, kind, source, direction, name, ty, table, column, *stats = row
        if kind not in (0, 1) or direction not in range(3) or ty not in range(8):
            raise TCBeeError(f"Invalid catalog codes in series {sid}")
        return cls(
            db,
            sid,
            fid,
            ("raw", "derived")[kind],
            source,
            _DIRECTIONS[direction],
            name,
            _TYPES[ty],
            table,
            column,
            *stats,
        )

    def _sample_query(self, start_ns, end_ns):
        window(start_ns, end_ns)
        if self.kind == "raw":
            if not self._table or not self._table.startswith("ev_") or not self._column:
                raise TCBeeError(f"Invalid event table/column in series {self.id}")
            sql = f"SELECT e.ts, e.seq, e.{quote(self._column)} AS value FROM {quote(self._table)} AS e"
            conditions = ["flow_id = ?", "dir = ?"]
            params = [self.flow_id, direction_code(self.direction)]
        else:
            column = {"bool": "v_bool", "f64": "v_float", "text": "v_text"}.get(
                self.value_type, "v_int"
            )
            sql = f"SELECT ts, seq, {quote(column)} FROM derived_samples"
            conditions, params = ["series_id = ?"], [self.id]
        if start_ns is not None:
            conditions.append("ts >= ?")
            params.append(start_ns)
        if end_ns is not None:
            conditions.append("ts < ?")
            params.append(end_ns)
        return sql + " WHERE " + " AND ".join(conditions) + " ORDER BY ts, seq", params

    def gaps(self, *, start_ns=None, end_ns=None):
        """Events missing from this series according to hook_seq (the seq column).

        Returns the gaps that overlap the half-open window [start_ns, end_ns),
        ordered by seq, or None if they are unknown: for derived series and for
        runs recorded without hook_seq (--no-hook-seq stores seq 0). An empty
        list means no event is missing between recorded ones; losses after the
        last recorded event cannot be seen. Same query and rules as ts_storage's
        Store::seq_gaps (crates/ts-storage/src/gaps.rs), whose range is inclusive.
        """
        window(start_ns, end_ns)
        if self.kind != "raw":
            return None
        if not self._table or not self._table.startswith("ev_"):
            raise TCBeeError(f"Invalid event table in series {self.id}")
        # One hook_seq counter feeds one (table, flow, dir): order by seq, not ts, which
        # can go back across CPUs.
        sql = (
            'SELECT "seq", "ts", "prev_seq", "prev_ts" FROM (SELECT "seq", "ts", '
            'LAG("seq") OVER w AS "prev_seq", LAG("ts") OVER w AS "prev_ts" '
            f'FROM {quote(self._table)} WHERE "flow_id" = ? AND "dir" = ? '
            'WINDOW w AS (ORDER BY "seq", "ts")) AS g '
            'WHERE "prev_seq" IS NULL OR "seq" - "prev_seq" > 1 ORDER BY "seq"'
        )
        gaps = []
        for seq, ts, prev_seq, prev_ts in self._db._rows(
            sql, (self.flow_id, direction_code(self.direction))
        ):
            if prev_seq is None:
                # The first row holds the lowest seq
                if seq == 0:
                    return None
                if seq == 1:
                    continue
                gap = Gap(ts, ts, 1, seq - 1)
            else:
                gap = Gap(min(prev_ts, ts), max(prev_ts, ts), prev_seq + 1, seq - prev_seq - 1)
            if (start_ns is None or gap.end_ns >= start_ns) and (
                end_ns is None or gap.start_ns < end_ns
            ):
                gaps.append(gap)
        return gaps

    def iter_batches(self, *, batch_size=65_536, start_ns=None, end_ns=None):
        """Stream selected samples with bounded Python memory and one SQL query.

        Ranges are half-open boot-nanosecond intervals [start_ns, end_ns).
        Equal timestamps and sequence numbers are retained. Each iterator owns
        an independent cursor; close it explicitly if stopping early.
        """
        integer(batch_size, "batch_size", 1)
        sql, params = self._sample_query(start_ns, end_ns)
        return self._batches(sql, params, batch_size)

    def _batches(self, sql, params, batch_size):
        with self._db._cursor(sql, params) as cursor:
            while True:
                self._db._check_open()
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    return
                # Transpose in C rather than constructing a Python object per sample.
                timestamps, sequences, values = map(list, zip(*rows))
                del rows
                if self.value_type == "u64" and self._db.engine == "sqlite":
                    values = [
                        None if value is None else value & ((1 << 64) - 1) for value in values
                    ]
                elif self.value_type == "bool" and self._db.engine == "sqlite":
                    values = [None if value is None else bool(value) for value in values]
                yield Samples(timestamps, sequences, values, self.value_type)

    def read_numpy(self, *, start_ns=None, end_ns=None):
        """Load ts_ns/seq/value NumPy arrays, using DuckDB's native column export.

        This avoids Python row materialization on DuckDB. SQLite uses the same
        bounded reader as read(). Nullable columns use object dtype with None.
        """
        if self._db.engine == "sqlite":
            return self.read(start_ns=start_ns, end_ns=end_ns).to_numpy()
        import numpy as np

        sql, params = self._sample_query(start_ns, end_ns)
        with self._db._cursor(sql, params) as cursor:
            columns = list(cursor.fetchnumpy().values())
        result = {}
        for name, column in zip(("ts_ns", "seq", "value"), columns):
            if np.ma.isMaskedArray(column):
                nullable = np.asarray(column.data, dtype=object)
                nullable[np.ma.getmaskarray(column)] = None
                column = nullable
            result[name] = column
        return result

    def read(self, *, start_ns=None, end_ns=None):
        """Explicitly load the selected samples in memory, preserving their types."""
        result = Samples([], [], [], self.value_type)
        for batch in self.iter_batches(start_ns=start_ns, end_ns=end_ns):
            result.ts_ns.extend(batch.ts_ns)
            result.seq.extend(batch.seq)
            result.values.extend(batch.values)
        return result


@dataclass(frozen=True, repr=False)
class SeriesQuery:
    _db: object
    _flow_id: int
    _predicates: tuple = ()
    _params: tuple = ()

    def filter(self, *, source=None, name=None, direction=None, kind=None):
        predicates, params = list(self._predicates), list(self._params)
        for column, value in (
            ("source", source),
            ("name", name),
            ("dir", direction),
            ("kind", kind),
        ):
            if value is None:
                continue
            if column == "dir":
                value = direction_code(value)
            elif column == "kind":
                if value not in ("raw", "derived"):
                    raise ValueError("kind must be 'raw' or 'derived'")
                value = ("raw", "derived").index(value)
            predicates.append(f"{column} = ?")
            params.append(value)
        return replace(self, _predicates=tuple(predicates), _params=tuple(params))

    def _sql(self):
        where = " AND ".join(("flow_id = ?", *self._predicates))
        return f"SELECT {_COLUMNS} FROM series WHERE {where} ORDER BY source, dir, name, id"

    def _take(self, size):
        return tuple(
            Series._from_row(self._db, row)
            for row in self._db._rows(
                self._sql() + " LIMIT ?", (self._flow_id, *self._params, size)
            )
        )

    def one(self, **filters):
        """Select exactly one metric; omitting direction is allowed only if unique."""
        matches = self.filter(**filters)._take(2)
        if not matches:
            raise NotFound(
                f"No matching series for flow {self._flow_id}; inspect flow.series().show()"
            )
        if len(matches) > 1:
            candidates = ", ".join(f"{s.id}: {s.source}.{s.name} ({s.direction})" for s in matches)
            raise AmbiguousSelection(
                f"Multiple matching series: {candidates}; specify source/name/direction or series ID"
            )
        return matches[0]

    def first(self):
        matches = self._take(1)
        return matches[0] if matches else None

    def __iter__(self):
        with self._db._cursor(self._sql(), (self._flow_id, *self._params)) as cursor:
            while True:
                self._db._check_open()
                rows = cursor.fetchmany(256)
                if not rows:
                    return
                for row in rows:
                    self._db._check_open()
                    yield Series._from_row(self._db, row)

    def show(self, *, limit=30, file=None):
        integer(limit, "limit", 1)
        matches = self._take(limit + 1)
        print("ID | Metric | Direction | Type | Sample values | Bounds (approx.)", file=file)
        for series in matches[:limit]:
            print(
                f"{series.id} | {series.source}.{series.name} | {series.direction} | "
                f"{series.value_type} | {series.sample_count} | {series.minimum} .. {series.maximum}",
                file=file,
            )
        if len(matches) > limit:
            print("… more series; use filter() to narrow the selection", file=file)

    def __repr__(self):
        return f"<SeriesQuery flow={self._flow_id}; use show(), filter(), one() or iterate>"
