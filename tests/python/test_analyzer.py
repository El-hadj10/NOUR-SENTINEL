
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "python-brain")
)

from analyzer import analyze_events


class TestAnalyzer(unittest.TestCase):

    def test_analysis_summary(self):

        data = {
            "source": "test-engine",

            "devices": [
                {"ip": "127.0.0.1"}
            ],

            "events": [
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 443,
                    "state": "open"
                },
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 22,
                    "state": "closed"
                }
            ],

            "analysis_config": {
                "sensitive_ports": [3389],
                "known_services": {
                    "443": "HTTPS"
                }
            }
        }

        result = analyze_events(data)

        self.assertEqual(
            result["network"]["ports_observed"],
            2
        )

        self.assertEqual(
            result["network"]["open_ports"],
            1
        )

        self.assertEqual(
            result["network"]["neighbors_discovered"],
            1
        )

        self.assertEqual(
            result["findings_count"],
            1
        )

        self.assertEqual(
            result["findings"][0]["service"],
            "HTTPS"
        )

        self.assertEqual(
            result["status"],
            "analysis_completed"
        )


if __name__ == "__main__":
    unittest.main()
