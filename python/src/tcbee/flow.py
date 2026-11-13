"""Lazy catalog queries and bounded flow browsing."""

from dataclasses import dataclass, field, replace

from ._util import address, direction_code, integer, window
from .errors import AmbiguousSelection, NotFound

# These summaries count metric values, not packets or distinct event records.
_STATS = """
SELECT s.flow_id, COUNT(*) AS series_count, SUM(s.n) AS sample_count,
       MIN(s.t_min) AS start_ns, MAX(s.t_max) AS end_ns
FROM series s {selection} GROUP BY s.flow_id
"""
_SUMMARY = """
SELECT f.id, f.src, f.dst, f.sport, f.dport, f.l4proto,
       COALESCE(s.series_count, 0) AS series_count,
       COALESCE(s.sample_count, 0) AS sample_count,
       s.start_ns, s.end_ns, s.end_ns - s.start_ns AS duration_ns
FROM {flows} f LEFT JOIN ({stats}) s ON s.flow_id = f.id
"""


@dataclass(frozen=True)
class Flow:
    """A tuple in this database; it may cover several connection lifetimes."""

    _db: object = field(repr=False, compare=False)
    id: int
    src: str
    dst: str
    sport: int
    dport: int
    l4proto: int
    series_count: int
    sample_count: int
    start_ns: int | None
    end_ns: int | None
    duration_ns: int | None

    def series(self):
        """Discover available metrics without loading their samples."""
        from .series import SeriesQuery

        self._db._check_open()
        return SeriesQuery(self._db, self.id)

    def owners(self):
        """Ownership observations, preserving multiple owners and timestamps.

        Returns an empty tuple when the optional owner table is absent. Use
        db.tables to distinguish missing metadata from no recorded owners.
        """
        from .relationships import owners

        return owners(self._db, self.id)

    def connections(self):
        """Connections containing this tuple, possibly at different times."""
        from .relationships import connections

        return connections(self._db, self.id)

    def __str__(self):
        def endpoint(ip, port):
            return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

        return f"{self.id}: {endpoint(self.src, self.sport)} -> {endpoint(self.dst, self.dport)}"


@dataclass(frozen=True)
class _Cursor:
    """Opaque continuation token scoped to this open database and query."""

    db: object = field(repr=False)
    predicates: tuple
    params: tuple
    last_id: int


@dataclass(frozen=True)
class FlowPage:
    items: tuple[Flow, ...]
    next_cursor: _Cursor | None = field(repr=False)


@dataclass(frozen=True, repr=False)
class FlowQuery:
    _db: object
    _predicates: tuple = ()
    _params: tuple = ()
    _needs_summary: bool = False

    def _where(self, predicate, *params, needs_summary=False):
        self._db._check_open()
        return replace(
            self,
            _predicates=self._predicates + (predicate,),
            _params=self._params + params,
            _needs_summary=self._needs_summary or needs_summary,
        )

    def filter(
        self,
        *,
        id=None,
        src=None,
        dst=None,
        sport=None,
        dport=None,
        l4proto=None,
        host=None,
        port=None,
        start_ns=None,
        end_ns=None,
        min_duration_ns=None,
    ):
        """Combine exact tuple filters with AND; host/port match either endpoint.

        Time filters select flows whose catalog span overlaps [start_ns, end_ns).
        A span can contain gaps; this does not guarantee samples in that window.
        """
        result = self
        for name, value in (
            ("id", id),
            ("src", src),
            ("dst", dst),
            ("sport", sport),
            ("dport", dport),
            ("l4proto", l4proto),
        ):
            if value is None:
                continue
            if name in ("src", "dst"):
                value = address(value)
            else:
                integer(value, name)
                maximum = (
                    65535 if name in ("sport", "dport") else 255 if name == "l4proto" else None
                )
                if maximum is not None and value > maximum:
                    raise ValueError(f"{name} must be <= {maximum}")
            result = result._where(f"f.{name} = ?", value)
        if host is not None:
            host = address(host)
            result = result._where("(f.src = ? OR f.dst = ?)", host, host)
        if port is not None:
            integer(port, "port")
            if port > 65535:
                raise ValueError("port must be <= 65535")
            result = result._where("(f.sport = ? OR f.dport = ?)", port, port)
        window(start_ns, end_ns)
        if start_ns is not None:
            result = result._where("f.end_ns >= ?", start_ns, needs_summary=True)
        if end_ns is not None:
            result = result._where("f.start_ns < ?", end_ns, needs_summary=True)
        if start_ns is not None and start_ns == end_ns:
            result = result._where("1 = 0")
        if min_duration_ns is not None:
            integer(min_duration_ns, "min_duration_ns")
            result = result._where("f.duration_ns >= ?", min_duration_ns, needs_summary=True)
        return result

    def with_series(self, *, source=None, name=None, direction=None):
        """Select flows with a matching catalog entry, without reading samples."""
        clauses, params = ["s.flow_id = f.id"], []
        for column, value in (("source", source), ("name", name), ("dir", direction)):
            if value is not None:
                clauses.append(f"s.{column} = ?")
                params.append(direction_code(value) if column == "dir" else value)
        return self._where(
            "EXISTS (SELECT 1 FROM series s WHERE " + " AND ".join(clauses) + ")", *params
        )

    def owned_by(self, *, pid=None, uid=None, comm=None, cmdline_contains=None):
        """Match any recorded owner; supplied fields must match the same row.

        This selects owner observations at any time, not the owner of every
        sample in a subsequent read. Missing metadata raises MissingCapability.
        """
        from .errors import MissingCapability

        self._db._check_open()
        if "flow_owners" not in self._db.tables:
            raise MissingCapability("This database has no flow_owners table")
        clauses, params = ["o.flow_id = f.id"], []
        for column, value in (("pid", pid), ("uid", uid), ("comm", comm)):
            if value is not None:
                if column in ("pid", "uid"):
                    integer(value, column)
                clauses.append(f"o.{column} = ?")
                params.append(value)
        if cmdline_contains is not None:
            clauses.append("instr(o.cmdline, ?) > 0")
            params.append(cmdline_contains)
        return self._where(
            "EXISTS (SELECT 1 FROM flow_owners o WHERE " + " AND ".join(clauses) + ")", *params
        )

    def with_connection(self, connection_id, *, include_connection_flow=True):
        """Match connection members without duplicating flow rows."""
        from .relationships import require_connections

        require_connections(self._db)
        integer(connection_id, "connection_id")
        membership = (
            "EXISTS (SELECT 1 FROM connection_flows cf WHERE "
            "cf.connection_id = c.id AND cf.flow_id = f.id)"
        )
        if include_connection_flow:
            membership = "(c.flow_id = f.id OR " + membership + ")"
        return self._where(
            "EXISTS (SELECT 1 FROM connections c WHERE c.id = ? AND " + membership + ")",
            connection_id,
        )

    def _sql(self, *, force_summary=False):
        where = " AND ".join(self._predicates) or "1 = 1"
        source = "flows"
        if self._needs_summary or force_summary:
            stats = _STATS.format(selection="")
            source = "(" + _SUMMARY.format(flows="flows", stats=stats) + ")"
        return f"SELECT f.* FROM {source} f WHERE {where}"

    def _take(self, size, order="f.id", *, ranked=False):
        if self._needs_summary or ranked:
            # Time/duration filtering and ranking genuinely require global summaries.
            sql = self._sql(force_summary=True) + f" ORDER BY {order} LIMIT ?"
        else:
            # Limit tuple/EXISTS matches before grouping the catalog. DuckDB otherwise
            # decorrelates scalar summaries into whole-catalog work on every page.
            stats = _STATS.format(selection="WHERE s.flow_id IN (SELECT id FROM chosen)")
            summary = _SUMMARY.format(flows="chosen", stats=stats)
            sql = (
                "WITH chosen AS ("
                + self._sql()
                + " ORDER BY f.id LIMIT ?) "
                + summary
                + " ORDER BY f.id"
            )
        rows = self._db._rows(sql, self._params + (size,))
        return tuple(Flow(self._db, *row) for row in rows)

    def count(self):
        """Explicitly count matches; this can scan catalog metadata."""
        return self._db._rows("SELECT COUNT(*) FROM (" + self._sql() + ") q", self._params)[0][0]

    def first(self):
        rows = self._take(1)
        return rows[0] if rows else None

    def one(self):
        rows = self._take(2)
        if not rows:
            raise NotFound("No matching flow")
        if len(rows) > 1:
            raise AmbiguousSelection("Multiple matching flows; filter further or use page()")
        return rows[0]

    def page(self, *, size=50, after=None):
        """Fetch a bounded ID-ordered page. Tokens cannot be reused across queries."""
        integer(size, "size", 1)
        query = self
        if after is not None:
            if (
                not isinstance(after, _Cursor)
                or after.db is not self._db
                or (after.predicates, after.params) != (self._predicates, self._params)
            ):
                raise ValueError("Continuation cursor belongs to another database or query")
            query = self._where("f.id > ?", after.last_id)
        rows = query._take(size + 1)
        token = None
        if len(rows) > size:
            token = _Cursor(self._db, self._predicates, self._params, rows[size - 1].id)
        return FlowPage(rows[:size], token)

    def top(self, *, size=20, by="sample_count"):
        """Rank a bounded result; ranking can scan/sort the whole catalog."""
        integer(size, "size", 1)
        if by not in ("sample_count", "duration_ns"):
            raise ValueError("by must be 'sample_count' or 'duration_ns'")
        return self._take(size, f"f.{by} DESC NULLS LAST, f.id", ranked=True)

    def __iter__(self):
        token = None
        while True:
            page = self.page(size=256, after=token)
            for flow in page.items:
                self._db._check_open()
                yield flow
            token = page.next_cursor
            if token is None:
                break

    def show(self, *, limit=20, file=None):
        """Print a bounded plain-text table without an implicit full count."""
        page = self.page(size=limit)
        print("Flow | Series | Sample values | Duration (s)", file=file)
        for flow in page.items:
            duration = "-" if flow.duration_ns is None else f"{flow.duration_ns / 1e9:.6f}"
            print(f"{flow} | {flow.series_count} | {flow.sample_count} | {duration}", file=file)
        if page.next_cursor is not None:
            print("… more flows; use page() to continue", file=file)

    def __repr__(self):
        return "<FlowQuery; use show(), page(), count() or iterate>"
