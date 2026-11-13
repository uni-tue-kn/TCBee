"""Read-only connections to completed schema-v3 database files."""

import builtins
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .errors import ClosedDatabase, UnsupportedDatabase, UnsupportedSchema


class Database:
    """Owns the connection and cursors. Use :func:`tcbee.open` to construct it.

    Queries and sample iterators require this database to remain open. Instances
    are intended for a single thread; live database mutation is not supported.
    """

    def __init__(self, path):
        self.path = Path(path).expanduser().resolve()
        self._closed = False
        self._cursors = set()
        with builtins.open(self.path, "rb") as file:
            header = file.read(16)
        if header.startswith(b"SQLite format 3\0"):
            self.engine = "sqlite"
            self._connection = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)
            self._connection.execute("PRAGMA query_only = ON")
        elif header[8:12] == b"DUCK":
            import duckdb

            self.engine = "duckdb"
            self._connection = duckdb.connect(str(self.path), read_only=True)
        else:
            raise UnsupportedDatabase(f"{self.path} is neither SQLite nor DuckDB")
        try:
            try:
                version = self._rows("SELECT value FROM meta WHERE key = 'schema_version'")
            except Exception as error:
                raise UnsupportedSchema(
                    "Missing schema version; reprocess with tcbee-process"
                ) from error
            if version != [("3",)]:
                raise UnsupportedSchema(
                    "Only schema version 3 is supported; reprocess with tcbee-process"
                )
            if self.engine == "sqlite":
                rows = self._rows("SELECT name FROM sqlite_master WHERE type = 'table'")
            else:
                rows = self._rows("SELECT table_name FROM information_schema.tables")
            self.tables = frozenset(row[0] for row in rows)
            self.metadata = dict(self._rows("SELECT key, value FROM meta ORDER BY key"))
        except BaseException:
            self.close()
            raise

    def _check_open(self):
        if self._closed:
            raise ClosedDatabase(f"Database is closed: {self.path}")

    @contextmanager
    def _cursor(self, sql, params=()):
        self._check_open()
        cursor = self._connection.cursor()
        self._cursors.add(cursor)
        try:
            cursor.execute(sql, params)
            yield cursor
        finally:
            if cursor in self._cursors:
                self._cursors.remove(cursor)
                cursor.close()

    def _rows(self, sql, params=()):
        with self._cursor(sql, params) as cursor:
            return cursor.fetchall()

    def flows(self):
        """Return an immutable, lazy query of flow metadata."""
        from .flow import FlowQuery

        self._check_open()
        return FlowQuery(self)

    def flow(self, flow_id):
        """Look up a database-local flow ID; raise NotFound if absent."""
        return self.flows().filter(id=flow_id).one()

    def close(self):
        """Close active cursors and the connection; safe to call repeatedly."""
        if not self._closed:
            self._closed = True
            for cursor in tuple(self._cursors):
                cursor.close()
            self._cursors.clear()
            self._connection.close()

    def __enter__(self):
        self._check_open()
        return self

    def __exit__(self, *exc):
        self.close()


def open(path):
    """Open a completed SQLite or DuckDB file read-only, detecting its header."""
    return Database(path)
