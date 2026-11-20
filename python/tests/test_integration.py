"""Optional integration against the real trace processor and command-line examples."""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fixtures import create_database

import tcbee

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get("TCBEE_PROCESS"), "set TCBEE_PROCESS to a built processor")
class ProcessorIntegration(unittest.TestCase):
    def test_repository_trace(self):
        results = []
        with tempfile.TemporaryDirectory() as directory:
            for engine in os.environ.get("TCBEE_TEST_ENGINES", "sqlite").split(","):
                with self.subTest(engine=engine):
                    path = Path(directory) / (
                        "flows.sqlite" if engine == "sqlite" else "flows.duck"
                    )
                    subprocess.run(
                        [
                            os.environ["TCBEE_PROCESS"],
                            "-i",
                            str(ROOT / "crates/tcbee-process/tests/fixtures/tcbee_small"),
                            "-o",
                            str(path),
                            "-j",
                            "2",
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    with tcbee.open(path) as db:
                        query = db.flows().with_series(
                            source="sock", name="snd_cwnd", direction="send"
                        )
                        self.assertGreater(query.count(), 0)
                        if results:
                            src, dst, sport, dport, _ = results[0]
                            query = query.filter(src=src, dst=dst, sport=sport, dport=dport)
                        flow = query.first()
                        metric = flow.series().one(source="sock", name="snd_cwnd", direction="send")
                        samples = metric.read()
                        self.assertEqual(len(samples), metric.sample_count)
                        self.assertEqual(samples.ts_ns[0], metric.start_ns)
                        self.assertEqual(samples.ts_ns[-1], metric.end_ns)
                        self.assertEqual(
                            sum(len(batch) for batch in metric.iter_batches(batch_size=7)),
                            len(samples),
                        )
                        # Compare tuple identity, not processing-assigned IDs.
                        results.append((flow.src, flow.dst, flow.sport, flow.dport, samples))
            if len(results) == 2:
                self.assertEqual(results[0], results[1])


class ExampleIntegration(unittest.TestCase):
    def test_flow_listing_and_plot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows.sqlite"
            create_database(path, "sqlite")
            listed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/python/list_flows.py"),
                    str(path),
                    "--port",
                    "5201",
                    "--limit",
                    "1",
                    "--verbose",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertIn("Found 2 matching flows", listed.stdout)
            self.assertIn("More flows available", listed.stdout)
            self.assertIn("snd_cwnd", listed.stdout)
            if importlib.util.find_spec("matplotlib"):
                output = Path(directory) / "plot.png"
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "examples/python/plot_metrics.py"),
                        str(path),
                        "1",
                        "--metric",
                        "sock.snd_cwnd",
                        "--dir",
                        "send",
                        "--output",
                        str(output),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env={**os.environ, "MPLBACKEND": "Agg", "MPLCONFIGDIR": directory},
                )
                self.assertEqual(output.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
