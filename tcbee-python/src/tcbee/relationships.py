"""Optional process-owner histories and connection membership metadata."""

from dataclasses import dataclass, field

from .errors import MissingCapability


@dataclass(frozen=True)
class FlowOwner:
    """An ownership observation from ts_ns onward, not a complete lifetime."""

    flow_id: int
    ts_ns: int
    source: str
    pid: int
    uid: int | None
    comm: str
    cmdline: str | None
    start_time_ns: int | None
    cgroup_id: int | None
    cgroup: str | None
    netns: int | None
    kthread: bool


@dataclass(frozen=True)
class ConnectionMembership:
    """Stored association interval; last_ns is the last observation, inclusive."""

    connection_id: int
    flow_id: int
    subflow_id: int | None
    first_ns: int
    last_ns: int


@dataclass(frozen=True)
class Connection:
    _db: object = field(repr=False, compare=False)
    id: int
    kind: str
    key: int
    flow_id: int | None
    start_ns: int
    end_ns: int

    def flows(self):
        """Query member flows, including the connection's own metric flow."""
        return self._db.flows().with_connection(self.id)

    def subflows(self):
        """Query member flows without adding the connection's metric flow."""
        return self._db.flows().with_connection(self.id, include_connection_flow=False)

    def memberships(self):
        require_connections(self._db)
        rows = self._db._rows(
            "SELECT connection_id, flow_id, subflow_id, first_ts, last_ts "
            "FROM connection_flows WHERE connection_id = ? ORDER BY first_ts, flow_id",
            (self.id,),
        )
        return tuple(ConnectionMembership(*row) for row in rows)


def require_connections(db):
    db._check_open()
    if not {"connections", "connection_flows"} <= db.tables:
        raise MissingCapability("This database has no connection metadata tables")


def owners(db, flow_id):
    db._check_open()
    if "flow_owners" not in db.tables:
        return ()
    rows = db._rows(
        "SELECT flow_id, ts, source, pid, uid, comm, cmdline, start_time, cgroup_id, "
        "cgroup, netns, kthread FROM flow_owners WHERE flow_id = ? ORDER BY ts, pid",
        (flow_id,),
    )
    return tuple(FlowOwner(*row[:-1], bool(row[-1])) for row in rows)


def connections(db, flow_id):
    db._check_open()
    if not {"connections", "connection_flows"} <= db.tables:
        return ()
    rows = db._rows(
        "SELECT c.id, c.kind, c.key, c.flow_id, c.start_ts, c.end_ts "
        "FROM connections c WHERE c.flow_id = ? OR EXISTS ("
        "SELECT 1 FROM connection_flows cf WHERE cf.connection_id = c.id AND cf.flow_id = ?) "
        "ORDER BY c.start_ts, c.id",
        (flow_id, flow_id),
    )
    return tuple(Connection(db, *row) for row in rows)
