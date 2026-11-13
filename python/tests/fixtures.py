"""Small files with the same catalog layout as crates/ts-storage/src/schema.rs."""

import sqlite3


def create_database(path, engine, *, owners=True):
    if engine == "duckdb":
        import duckdb

        db = duckdb.connect(str(path))
    else:
        db = sqlite3.connect(path)
    db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("INSERT INTO meta VALUES ('schema_version', '3')")
    db.execute(
        "CREATE TABLE flows (id BIGINT PRIMARY KEY, src TEXT, dst TEXT, sport INTEGER, dport INTEGER, l4proto INTEGER)"
    )
    db.executemany(
        "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, "10.0.0.1", "10.0.0.2", 40000, 5201, 6),
            (3, "10.0.0.3", "10.0.0.1", 443, 40001, 6),
            (8, "2001:db8::1", "2001:db8::2", 40002, 5201, 6),
            (10, "10.0.0.5", "10.0.0.6", 1000, 1001, 17),
        ],
    )
    db.execute("""CREATE TABLE series (
        id BIGINT PRIMARY KEY, flow_id BIGINT, kind INTEGER, source TEXT, dir INTEGER,
        name TEXT, value_type INTEGER, tbl TEXT, col TEXT, n BIGINT,
        t_min BIGINT, t_max BIGINT, v_min DOUBLE, v_max DOUBLE,
        UNIQUE(flow_id, source, dir, name))""")
    # A large boot timestamp catches float-before-subtraction precision loss.
    t = 10_000_000_000_000_001
    rows = [
        (1, 1, 0, "sock", 1, "snd_cwnd", 3, "ev_sock", "snd_cwnd", 4, t, t + 3, 10, 13),
        (2, 1, 0, "sock", 2, "snd_cwnd", 3, "ev_sock", "snd_cwnd", 1, t + 2, t + 2, 20, 20),
        (3, 3, 0, "tcp_probe", 0, "SND_CWND", 3, "ev_tcp_probe", "SND_CWND", 2, t, t + 10, 4, 8),
        (4, 8, 0, "sock", 1, "snd_cwnd", 3, "ev_sock", "snd_cwnd", 4, t, t + 3, 10, 13),
    ]
    db.executemany("INSERT INTO series VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    db.execute("""CREATE TABLE derived_samples (
        series_id BIGINT, ts BIGINT, seq BIGINT, v_int BIGINT, v_float DOUBLE,
        v_bool BOOLEAN, v_text TEXT)""")
    unsigned = "UBIGINT" if engine == "duckdb" else "BIGINT"
    db.execute(f"""CREATE TABLE ev_sock (
        flow_id BIGINT, dir INTEGER, ts BIGINT, seq BIGINT,
        snd_cwnd INTEGER, max_pacing_rate {unsigned})""")
    db.executemany(
        "INSERT INTO ev_sock VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, 1, t + 3, 3, 13, 42),
            (1, 1, t, 0, 10, 0),
            (1, 1, t + 1, 2, 12, 2**64 - 1 if engine == "duckdb" else -1),
            (1, 1, t + 1, 1, 11, 2**63 if engine == "duckdb" else -(2**63)),
            (1, 2, t + 2, 0, 20, 10),
        ],
    )
    db.execute(
        'CREATE TABLE ev_tcp_probe (flow_id BIGINT, dir INTEGER, ts BIGINT, seq BIGINT, "SND_CWND" INTEGER)'
    )
    db.executemany(
        "INSERT INTO ev_tcp_probe VALUES (?, ?, ?, ?, ?)", [(3, 0, t, 0, 4), (3, 0, t + 10, 1, 8)]
    )
    if engine == "sqlite":
        db.execute("CREATE INDEX ev_sock_idx ON ev_sock(flow_id, dir, ts, seq)")
    if owners:
        db.execute("""CREATE TABLE flow_owners (
            flow_id BIGINT, ts BIGINT, source TEXT, pid BIGINT, uid BIGINT,
            comm TEXT, cmdline TEXT, start_time BIGINT, cgroup_id BIGINT,
            cgroup TEXT, netns BIGINT, kthread BOOLEAN)""")
        db.executemany(
            "INSERT INTO flow_owners VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    t,
                    "connect",
                    100,
                    1000,
                    "iperf3",
                    "iperf3 -c 10.0.0.2",
                    t - 10,
                    None,
                    None,
                    99,
                    False,
                ),
                (1, t + 2, "connect", 200, 1000, "curl", None, None, None, None, 99, False),
            ],
        )
    db.execute("""CREATE TABLE connections (id BIGINT PRIMARY KEY, kind TEXT, key BIGINT,
        flow_id BIGINT, start_ts BIGINT, end_ts BIGINT)""")
    db.execute("""CREATE TABLE connection_flows (connection_id BIGINT, flow_id BIGINT,
        subflow_id BIGINT, first_ts BIGINT, last_ts BIGINT)""")
    db.executemany(
        "INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?)",
        [
            (7, "mptcp", 123, 8, t, t + 3),
            (9, "mptcp", 456, None, t + 5, t + 10),
        ],
    )
    db.executemany(
        "INSERT INTO connection_flows VALUES (?, ?, ?, ?, ?)",
        [
            (7, 1, 1, t, t + 3),
            (9, 1, 2, t + 5, t + 10),
        ],
    )
    db.commit()
    db.close()
    return t
