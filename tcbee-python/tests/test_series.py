import importlib.util
import io
import math
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fixtures import create_database

import tcbee


class SeriesTests:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "flow.db"
        self.t = create_database(self.path, self.engine)
        # Add unsigned, derived, NULL and embedded-quote column cases.
        if self.engine == "duckdb":
            import duckdb

            writer = duckdb.connect(str(self.path))
        else:
            writer = sqlite3.connect(self.path)
        self.add_series(
            writer, 5, 0, "sock", 1, "max_pacing_rate", 4, "ev_sock", "max_pacing_rate", 4
        )
        for sid, ty, col, vals in (
            (6, 5, "v_int", [2**63 - 1, None]),
            (7, 6, "v_float", [float("nan"), None]),
            (8, 0, "v_bool", [True, None]),
            (9, 7, "v_text", ["label", None]),
        ):
            self.add_series(writer, sid, 1, "derived", 0, f"metric_{sid}", ty, None, None, 2)
            for seq, value in enumerate(vals):
                writer.execute(
                    f'INSERT INTO derived_samples(series_id, ts, seq, "{col}") VALUES (?, ?, ?, ?)',
                    (sid, self.t + seq, seq, value),
                )
        writer.execute('ALTER TABLE ev_sock ADD COLUMN "a""b" INTEGER')
        writer.execute('UPDATE ev_sock SET "a""b" = snd_cwnd')
        self.add_series(writer, 11, 0, "sock", 1, 'a"b', 3, "ev_sock", 'a"b', 4)
        # Fully identical ordering keys must not lose samples at batch boundaries.
        writer.execute(
            "INSERT INTO ev_sock(flow_id, dir, ts, seq, snd_cwnd) VALUES (?, ?, ?, ?, ?)",
            (1, 1, self.t + 1, 1, 11),
        )
        writer.commit()
        writer.close()
        self.db = tcbee.open(self.path)
        self.addCleanup(self.db.close)
        self.series = self.db.flow(1).series().one(source="sock", name="snd_cwnd", direction="send")

    def add_series(self, writer, sid, kind, source, direction, name, ty, table, col, n):
        writer.execute(
            "INSERT INTO series VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sid,
                1,
                kind,
                source,
                direction,
                name,
                ty,
                table,
                col,
                n,
                self.t,
                self.t + 3,
                None,
                None,
            ),
        )

    def test_selection_and_discovery(self):
        catalog = self.db.flow(1).series()
        with self.assertRaisesRegex(tcbee.AmbiguousSelection, "send"):
            catalog.one(source="sock", name="snd_cwnd")
        with self.assertRaises(tcbee.NotFound):
            catalog.one(name="does_not_exist")
        with self.assertRaises(tcbee.NotFound):
            self.db.series(999)
        with self.assertRaises(ValueError):
            catalog.one(direction="both")
        with self.assertRaises(ValueError):
            catalog.filter(kind="invalid")
        self.assertEqual(len(list(catalog.filter(kind="derived"))), 4)
        self.assertEqual(self.db.series(1).id, self.series.id)
        self.assertEqual(self.db.flow(3).series().one(name="SND_CWND").direction, "none")
        with self.assertRaises(tcbee.NotFound):
            self.db.flow(3).series().one(name="SND_CWND", direction="send")
        self.assertIsNone(catalog.filter(name="missing").first())
        out = io.StringIO()
        catalog.show(limit=1, file=out)
        self.assertIn("more series", out.getvalue())

    def test_ordering_and_half_open_windows(self):
        samples = self.series.read()
        self.assertEqual(samples.ts_ns, [self.t, self.t + 1, self.t + 1, self.t + 1, self.t + 3])
        self.assertEqual(samples.seq, [0, 1, 1, 2, 3])
        self.assertEqual(samples.values, [10, 11, 11, 12, 13])
        self.assertEqual(samples.seconds(origin_ns=self.t), [0.0, 1e-9, 1e-9, 1e-9, 3e-9])
        self.assertEqual(
            self.series.read(start_ns=self.t + 1, end_ns=self.t + 3).values, [11, 11, 12]
        )
        self.assertEqual(len(self.series.read(start_ns=self.t, end_ns=self.t)), 0)
        self.assertEqual(len(self.series.read(start_ns=self.t + 4)), 0)
        with self.assertRaises(ValueError):
            self.series.read(start_ns=self.t + 3, end_ns=self.t)
        with self.assertRaises(ValueError):
            self.series.iter_batches(batch_size=0)
        batches = list(self.series.iter_batches(batch_size=2))
        self.assertEqual([len(batch) for batch in batches], [2, 2, 1])
        self.assertEqual([value for batch in batches for value in batch.values], samples.values)

    def test_unsigned_derived_and_quoted_columns(self):
        unsigned = self.db.series(5).read().values
        self.assertEqual(unsigned, [0, 2**63, None, 2**64 - 1, 42])
        self.assertEqual(self.db.series(6).read().values, [2**63 - 1, None])
        floats = self.db.series(7).read().values
        if self.engine == "sqlite":
            self.assertEqual(floats, [None, None])
        else:
            self.assertTrue(math.isnan(floats[0]))
            self.assertIsNone(floats[1])
        self.assertEqual(self.db.series(8).read().values, [True, None])
        self.assertIs(self.db.series(8).read().values[0], True)
        self.assertEqual(self.db.series(9).read().values, ["label", None])
        self.assertEqual(self.db.series(11).read().values, [10, 11, None, 12, 13])

    def test_nested_queries_and_closed_iterators(self):
        first = self.series.iter_batches(batch_size=2)
        second = self.series.iter_batches(batch_size=1)
        self.assertEqual(next(first).values, [10, 11])
        self.assertEqual(next(second).values, [10])
        self.db.flows().page()
        self.assertEqual(next(first).values, [11, 12])
        self.assertEqual(next(second).values, [11])
        first.close()
        self.assertEqual(len(self.db._cursors), 1)
        self.db.close()
        with self.assertRaises(tcbee.ClosedDatabase):
            next(second)
        with self.assertRaises(tcbee.ClosedDatabase):
            self.series.read()

    @unittest.skipUnless(importlib.util.find_spec("numpy"), "optional NumPy is absent")
    def test_numpy_and_native_numpy(self):
        import numpy as np

        for sid in (1, 5, 6, 7, 8, 9):
            with self.subTest(series=sid):
                series = self.db.series(sid)
                expected = series.read().to_numpy()
                actual = series.read_numpy()
                for column in expected:
                    self.assertEqual(len(expected[column]), len(actual[column]))
                    for left, right in zip(expected[column], actual[column]):
                        if isinstance(left, float) and math.isnan(left):
                            self.assertTrue(math.isnan(right))
                        else:
                            self.assertEqual(left, right)
                self.assertEqual(expected["ts_ns"].dtype, np.dtype("int64"))
        native = self.series.read_numpy(start_ns=self.t, end_ns=self.t + 1)
        self.assertEqual(native["value"].tolist(), [10])
        empty = self.series.read_numpy(end_ns=self.t)
        self.assertEqual(empty["ts_ns"].dtype, np.dtype("int64"))
        self.assertEqual(len(empty["value"]), 0)
        # Without a NULL the u64 adapter must not infer float or signed dtype.
        exact = tcbee.Samples([self.t], [0], [2**64 - 1], "u64").to_numpy()
        self.assertEqual(exact["value"].dtype, np.dtype("uint64"))
        self.assertEqual(int(exact["value"][0]), 2**64 - 1)

    @unittest.skipUnless(importlib.util.find_spec("pandas"), "optional pandas is absent")
    def test_pandas_preserves_integer_precision(self):
        frame = self.db.series(5).read().to_frame()
        self.assertEqual(str(frame["value"].dtype), "UInt64")
        self.assertEqual(int(frame["value"].iloc[3]), 2**64 - 1)
        self.assertEqual(int(frame["ts_ns"].iloc[0]), self.t)
        floats = self.db.series(7).read().to_frame()
        self.assertIsNone(floats["value"].iloc[1])
        if self.engine == "duckdb":
            self.assertTrue(math.isnan(floats["value"].iloc[0]))
        self.db.close()
        self.assertEqual(int(frame["value"].iloc[3]), 2**64 - 1)


class SQLiteSeries(SeriesTests, unittest.TestCase):
    engine = "sqlite"

    def test_range_uses_index_and_streams_one_query(self):
        sql, params = self.series._sample_query(self.t, self.t + 3)
        plan = self.db._rows("EXPLAIN QUERY PLAN " + sql, params)
        self.assertTrue(any("USING INDEX ev_sock_idx" in row[-1] for row in plan))
        queries = []
        self.db._connection.set_trace_callback(queries.append)
        list(self.series.iter_batches(batch_size=1))
        self.assertEqual(len(queries), 1)
        self.assertNotIn("OFFSET", queries[0])


@unittest.skipUnless(importlib.util.find_spec("duckdb"), "optional duckdb is absent")
class DuckDBSeries(SeriesTests, unittest.TestCase):
    engine = "duckdb"
