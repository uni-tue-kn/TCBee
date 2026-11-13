import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fixtures import create_database

import tcbee


class RelationshipTests:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "flows.db"
        self.t = create_database(self.path, self.engine)
        self.db = tcbee.open(self.path)
        self.addCleanup(self.db.close)

    def test_owners_are_plural_and_filters_do_not_duplicate_flows(self):
        owners = self.db.flow(1).owners()
        self.assertEqual([owner.pid for owner in owners], [100, 200])
        self.assertEqual(owners[0].ts_ns, self.t)
        self.assertIs(owners[0].kthread, False)
        query = self.db.flows()
        self.assertEqual(query.owned_by().count(), 1)
        self.assertEqual(query.owned_by(comm="iperf3").one().id, 1)
        self.assertEqual(query.owned_by(pid=100, uid=1000).one().id, 1)
        self.assertEqual(query.owned_by(comm="curl", pid=100).count(), 0)
        self.assertEqual(query.owned_by(cmdline_contains="-c 10.0.0.2").one().id, 1)
        self.assertEqual(query.owned_by(cmdline_contains="% OR 1=1").count(), 0)
        # Tuple owner and time-overlap filters are independent historical matches.
        self.assertEqual(query.owned_by(comm="iperf3").filter(start_ns=self.t + 2).one().id, 1)

    def test_connection_memberships_preserve_intervals_and_metric_flow(self):
        self.assertEqual([c.id for c in self.db.flow(1).connections()], [7, 9])
        connection = self.db.connection(7)
        self.assertEqual((connection.kind, connection.key, connection.flow_id), ("mptcp", 123, 8))
        self.assertEqual([f.id for f in connection.flows()], [1, 8])
        self.assertEqual([f.id for f in connection.subflows()], [1])
        member = connection.memberships()[0]
        self.assertEqual(
            (member.flow_id, member.subflow_id, member.first_ns, member.last_ns),
            (1, 1, self.t, self.t + 3),
        )
        self.assertEqual([c.id for c in self.db.flow(8).connections()], [7])
        with self.assertRaises(tcbee.NotFound):
            self.db.connection(99)
        self.assertEqual(self.db.flows().with_connection(99).count(), 0)

    def test_absent_optional_tables(self):
        path = Path(self.temp.name) / "old.db"
        create_database(path, self.engine, owners=False)
        if self.engine == "duckdb":
            import duckdb

            writer = duckdb.connect(str(path))
        else:
            writer = sqlite3.connect(path)
        writer.execute("DROP TABLE connections")
        writer.execute("DROP TABLE connection_flows")
        writer.commit()
        writer.close()
        with tcbee.open(path) as db:
            self.assertEqual(db.flow(1).owners(), ())
            self.assertEqual(db.flow(1).connections(), ())
            self.assertEqual(db.flows().count(), 4)
            with self.assertRaises(tcbee.MissingCapability):
                db.flows().owned_by(pid=100)
            with self.assertRaises(tcbee.MissingCapability):
                db.flows().with_connection(7)
            with self.assertRaises(tcbee.MissingCapability):
                db.connection(7)
        with self.assertRaises(tcbee.ClosedDatabase):
            self.db.close()
            self.db.flow(1)


class SQLiteRelationships(RelationshipTests, unittest.TestCase):
    engine = "sqlite"


@unittest.skipUnless(importlib.util.find_spec("duckdb"), "optional duckdb is absent")
class DuckDBRelationships(RelationshipTests, unittest.TestCase):
    engine = "duckdb"
