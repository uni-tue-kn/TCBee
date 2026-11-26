"""The data script that tcbee-viz exports must run against the tcbee package."""

import runpy
import tempfile
import unittest
from pathlib import Path

from fixtures import create_database

TEMPLATE = Path(__file__).resolve().parents[2] / "crates/tcbee-viz/assets/view_template.py"


@unittest.skipUnless(TEMPLATE.exists(), "the tcbee-viz sources are absent")
class ViewTemplateTests(unittest.TestCase):
    def test_filled_template_loads_data_and_gaps(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "flow.db"
            t = create_database(db, "sqlite")
            # Filled in as export/script.rs does
            script = (
                TEMPLATE.read_text()
                .replace("{{DB}}", repr(str(db)))
                .replace("{{START_NS}}", str(t))
                .replace("{{END_NS}}", str(t + 4))
                .replace("{{ORIGIN_NS}}", str(t))
                .replace("{{YLIM}}", "None")
                .replace(
                    "{{SERIES}}",
                    '    (1, "sock", "snd_cwnd", "send", "cwnd", "#0072b2"),\n'
                    '    (3, "tcp_probe", "SND_CWND", "none", "probe", "#e69f00"),\n',
                )
            )
            self.assertNotIn("{{", script)
            path = Path(temp) / "view.py"
            path.write_text(script)
            result = runpy.run_path(str(path))
        self.assertEqual(result["data"]["cwnd"].values, [10, 11, 12, 13])
        self.assertEqual(result["data"]["probe"].values, [4])
        # The fixture numbers its rows from 0: gaps unknown
        self.assertEqual(result["gaps"], {"cwnd": None, "probe": None})
