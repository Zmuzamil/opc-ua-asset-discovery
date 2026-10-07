from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from generate_dashboard_report import generate_report


class ReportWorkflowTests(unittest.TestCase):
    def test_report_generator_embeds_json_and_updates_stable_dashboard(self) -> None:
        source_text = json.dumps(
            {
                "runtime_summary": {"capture_mode": "runtime", "total_packets_observed": 17},
                "passive": {"assets": []},
                "active": [],
                "warnings": ["literal <script> content remains JSON data"],
            },
            ensure_ascii=False,
            indent=2,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "latest.json"
            timestamped = root / "live_nic_test.html"
            stable = root / "OPEN_LATEST_RESULT.html"
            source.write_text(source_text, encoding="utf-8")
            persisted_source_text = source.read_bytes().decode("utf-8")

            generate_report(source, timestamped, stable)

            generated_html = timestamped.read_text(encoding="utf-8")
            stable_html = stable.read_text(encoding="utf-8")
            marker = 'const embeddedReportBase64 = "'
            encoded = generated_html.split(marker, 1)[1].split('";', 1)[0]
            embedded_text = base64.b64decode(encoded).decode("utf-8")

            self.assertEqual(embedded_text, persisted_source_text)
            self.assertEqual(stable_html, generated_html)
            self.assertNotIn("__OPCUA_REPORT_BASE64__", generated_html)
            self.assertIn('<section id="overview"', generated_html)
            self.assertIn('<section id="packets"', generated_html)
            self.assertIn('<section id="active"', generated_html)


if __name__ == "__main__":
    unittest.main()