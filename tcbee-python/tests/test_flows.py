import importlib.util
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fixtures import create_database

import tcbee


class FlowTests:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "unusual # ?.file"
        self.t = create_database(self.path, self.engine)
        self.db = tcbee.open(self.path)
        self.addCleanup(self.db.close)

    def test_filters_and_summaries(self):
        self.assertEqual(self.db.engine, self.engine)
        self.assertEqual(self.db.metadata["schema_version"], "3")
        query = self.db.flows()
        self.assertEqual(query.count(), 4)
        self.assertEqual(query.filter(dport=5201).count(), 2)
        self.assertEqual([f.id for f in query.filter(host="10.0.0.1")], [1, 3])
        self.assertEqual(query.filter(port=443).one().id, 3)
        self.assertEqual(query.filter(l4proto=17).one().id, 10)
        self.assertEqual(query.filter(src="2001:0db8::1").one().id, 8)
        self.assertIn("[2001:db8::1]:40002", str(self.db.flow(8)))
        flow = self.db.flow(1)
        self.assertEqual((flow.series_count, flow.sample_count), (2, 5))
        self.assertEqual((flow.start_ns, flow.end_ns, flow.duration_ns), (self.t, self.t + 3, 3))
        self.assertIsNone(self.db.flow(10).start_ns)
        self.assertEqual(query.with_series(source="tcp_probe", direction="none").one().id, 3)
        self.assertEqual(query.filter(start_ns=self.t + 4).one().id, 3)
        self.assertEqual(query.filter(end_ns=self.t).count(), 0)
        self.assertEqual(query.filter(start_ns=self.t + 1, end_ns=self.t + 1).count(), 0)
        self.assertEqual(query.filter(min_duration_ns=4).one().id, 3)

    def test_paging_and_ranking(self):
        query = self.db.flows()
        page = query.page(size=2)
        self.assertEqual([f.id for f in page.items], [1, 3])
        other = query.page(size=2, after=page.next_cursor)
        self.assertEqual([f.id for f in other.items], [8, 10])
        self.assertIsNone(other.next_cursor)
        self.assertEqual([f.id for f in query], [1, 3, 8, 10])
        self.assertEqual([f.id for f in query.top(size=3)], [1, 8, 3])
        self.assertEqual(query.top(size=1, by="duration_ns")[0].id, 3)
        with self.assertRaises(ValueError):
            query.filter(dport=5201).page(after=page.next_cursor)
        with tcbee.open(self.path) as other_db, self.assertRaises(ValueError):
            other_db.flows().page(after=page.next_cursor)

    def test_selection_display_validation(self):
        query = self.db.flows()
        self.assertIsNone(query.filter(id=999).first())
        with self.assertRaises(tcbee.NotFound):
            self.db.flow(999)
        with self.assertRaises(tcbee.AmbiguousSelection):
            query.one()
        output = io.StringIO()
        query.show(limit=1, file=output)
        self.assertIn("Sample values", output.getvalue())
        self.assertIn("more flows", output.getvalue())
        self.assertNotIn("10.0.0.3", output.getvalue())
        for params in (
            {"dport": -1},
            {"port": 70000},
            {"l4proto": 256},
            {"id": True},
            {"src": "' OR 1=1"},
            {"start_ns": 1.2},
            {"start_ns": 3, "end_ns": 2},
        ):
            with self.subTest(params=params), self.assertRaises(ValueError):
                query.filter(**params)
        for size in (0, -1, 0.5, True):
            with self.assertRaises(ValueError):
                query.page(size=size)
        self.assertEqual(query.with_series(name="' OR 1=1 --").count(), 0)
        iterator = iter(query)
        next(iterator)
        self.db.close()
        with self.assertRaises(tcbee.ClosedDatabase):
            next(iterator)
        self.db.close()
        with self.assertRaises(tcbee.ClosedDatabase):
            query.page()


class SQLiteFlows(FlowTests, unittest.TestCase):
    engine = "sqlite"

    def test_browsing_does_not_read_event_tables(self):
        def authorize(action, table, *rest):
            if action == sqlite3.SQLITE_READ and table.startswith(("ev_", "derived_samples")):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self.db._connection.set_authorizer(authorize)
        self.db.flows().with_series(name="snd_cwnd").page()
        self.db.flows().count()
        self.db.flows().top()
        self.db.flows().show(file=io.StringIO())

    def test_small_page_does_not_scan_the_whole_catalog(self):
        self.db.close()
        with sqlite3.connect(self.path) as writer:
            writer.executemany(
                "INSERT INTO flows VALUES (?, '10.0.0.1', '10.0.0.2', ?, 5201, 6)",
                ((i, i) for i in range(100, 2100)),
            )
            writer.executemany(
                "INSERT INTO series VALUES (?, ?, 0, 'sock', 1, ?, 3, 'ev_sock', 'snd_cwnd', 1000000, 0, 100, 0, 100)",
                ((i * 10 + m, i, f"metric_{m}") for i in range(100, 2100) for m in range(10)),
            )
        self.db = tcbee.open(self.path)
        self.addCleanup(self.db.close)
        operations = 0

        def progress():
            nonlocal operations
            operations += 1
            return 0

        self.db._connection.set_progress_handler(progress, 1)
        page = self.db.flows().page(size=5)
        self.db._connection.set_progress_handler(None, 0)
        self.assertEqual([flow.id for flow in page.items], [1, 3, 8, 10, 100])
        # A full 20k-row catalog scan exceeds this by an order of magnitude.
        self.assertLess(operations, 10_000)

    def test_read_only(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.db._connection.execute("DELETE FROM flows")


@unittest.skipUnless(importlib.util.find_spec("duckdb"), "optional duckdb package is absent")
class DuckDBFlows(FlowTests, unittest.TestCase):
    engine = "duckdb"


class OpeningTests(unittest.TestCase):
    def test_bad_files_and_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file"
            with self.assertRaises(FileNotFoundError):
                tcbee.open(path)
            self.assertFalse(path.exists())
            path.write_bytes(b"not a database")
            with self.assertRaises(tcbee.UnsupportedDatabase):
                tcbee.open(path)
            path.unlink()
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE meta(key TEXT, value TEXT)")
            db.execute("INSERT INTO meta VALUES ('schema_version', '2')")
            db.commit()
            db.close()
            with self.assertRaises(tcbee.UnsupportedSchema):
                tcbee.open(path)
