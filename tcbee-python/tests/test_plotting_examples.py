"""Plot exports and the spike-preserving large-metric reduction."""

import importlib.util
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fixtures import create_database

import tcbee

ROOT = Path(__file__).resolve().parents[2]
PLOTTING_AVAILABLE = all(importlib.util.find_spec(name) for name in ("numpy", "matplotlib"))


@unittest.skipUnless(PLOTTING_AVAILABLE, "install numpy and matplotlib for plotting examples")
class PlottingExamples(unittest.TestCase):
    def test_exports_on_both_backends(self):
        engines = ["sqlite"] + (["duckdb"] if importlib.util.find_spec("duckdb") else [])
        with tempfile.TemporaryDirectory() as directory:
            for engine in engines:
                path = Path(directory) / f"flows.{engine}"
                t = create_database(path, engine)
                if engine == "sqlite":
                    writer = sqlite3.connect(path)
                else:
                    import duckdb

                    writer = duckdb.connect(str(path))
                writer.execute("INSERT INTO ev_sock VALUES (8, 1, ?, 0, 30, 42)", (t + 2,))
                writer.commit()
                writer.close()
                commands = [
                    (
                        "plot_metrics.py",
                        ["1", "--metric", "sock.snd_cwnd", "--dir", "send"],
                        ".png",
                    ),
                    (
                        "compare_flows.py",
                        ["1", "8", "--metric", "sock.snd_cwnd", "--dir", "send", "--align", "flow"],
                        ".svg",
                    ),
                    (
                        "plot_large_metric.py",
                        [
                            "1",
                            "--metric",
                            "sock.snd_cwnd",
                            "--dir",
                            "send",
                            "--bins",
                            "2",
                            "--batch-size",
                            "1",
                        ],
                        ".pdf",
                    ),
                ]
                for script, args, suffix in commands:
                    with self.subTest(engine=engine, script=script):
                        output = Path(directory) / (engine + script + suffix)
                        result = subprocess.run(
                            [
                                sys.executable,
                                str(ROOT / "examples/db" / script),
                                str(path),
                                *args,
                                "--output",
                                str(output),
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=60,
                            env={**os.environ, "MPLBACKEND": "Agg", "MPLCONFIGDIR": directory},
                        )
                        self.assertIn("Saved", result.stdout)
                        data = output.read_bytes()
                        self.assertGreater(len(data), 1000)
                        if suffix == ".png":
                            self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
                        elif suffix == ".pdf":
                            self.assertTrue(data.startswith(b"%PDF"))
                        else:
                            self.assertIn(b"<svg", data)

    def test_envelope_preserves_extrema_carries_gaps_and_end_boundary(self):
        import numpy as np

        sys.path.insert(0, str(ROOT / "examples/db"))
        try:
            from plot_large_metric import envelope
        finally:
            sys.path.pop(0)

        class Metric:
            def iter_batches(self, *, batch_size, start_ns, end_ns):
                rows = [(10, 1), (10, 100), (11, None), (15, float("nan")), (19, -5), (20, 999)]
                rows = [(t, v) for t, v in rows if start_ns <= t < end_ns]
                for offset in range(0, len(rows), batch_size):
                    batch = rows[offset : offset + batch_size]
                    yield tcbee.Samples(
                        [t for t, _ in batch], list(range(len(batch))), [v for _, v in batch], "f64"
                    )

        edges, low, high, seen = envelope(Metric(), start_ns=10, end_ns=20, bins=5, batch_size=1)
        self.assertEqual(edges, [10, 12, 14, 16, 18, 20])
        self.assertEqual(seen, 3)
        # Empty bins carry the last value forward, like a step plot
        np.testing.assert_equal(low, [1, 100, 100, 100, -5])
        np.testing.assert_equal(high, [100, 100, 100, 100, -5])
        # More requested bins than nanoseconds must not create zero-width bins.
        edges, _, _, _ = envelope(Metric(), start_ns=10, end_ns=12, bins=2000)
        self.assertEqual(edges, [10, 11, 12])
        with self.assertRaises(ValueError):
            envelope(Metric(), start_ns=10, end_ns=10)

    def test_invalid_time_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db"
            create_database(path, "sqlite")
            command = [
                sys.executable,
                str(ROOT / "examples/db/plot_metrics.py"),
                str(path),
                "1",
                "--metric",
                "sock.snd_cwnd",
                "--dir",
                "send",
                "--start",
                "2",
                "--end",
                "1",
            ]
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "MPLBACKEND": "Agg", "MPLCONFIGDIR": directory},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--start must precede --end", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_goodput_unwraps_sequence_numbers(self):
        import numpy as np

        sys.path.insert(0, str(ROOT / "examples/db"))
        try:
            from _plotting import goodput
        finally:
            sys.path.pop(0)
        # The last step wraps from 2**32 - 1000 to 1000, which is 2000 bytes
        times = np.array([0.0, 0.1, 0.6, 1.0])
        _, rates = goodput(times, [2**32 - 3000, 2**32 - 2000, 2**32 - 1000, 1000], 0.5)
        np.testing.assert_allclose(rates, [1000 * 8 / 0.5 / 1e6, 3000 * 8 / 0.5 / 1e6])
