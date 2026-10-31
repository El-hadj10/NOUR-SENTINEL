
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "python-brain")
)

from detector import detect_threats


ANALYSIS_CONFIG = {
    "sensitive_ports": [23, 3389, 5900],
    "known_services": {
        "22": "SSH",
        "80": "HTTP",
        "443": "HTTPS"
    }
}


class TestDetector(unittest.TestCase):

    def test_sensitive_port_detection(self):
        events = [{
            "type": "port_observed",
            "ip": "127.0.0.1",
            "port": 3389,
            "state": "open"
        }]

        results = detect_threats(events, ANALYSIS_CONFIG)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "warning")

    def test_normal_port(self):
        events = [{
            "type": "port_observed",
            "ip": "127.0.0.1",
            "port": 443,
            "state": "open"
        }]

        results = detect_threats(events, ANALYSIS_CONFIG)

        self.assertEqual(results[0]["service"], "HTTPS")
        self.assertEqual(results[0]["severity"], "info")

    def test_closed_port(self):
        events = [{
            "type": "port_observed",
            "ip": "127.0.0.1",
            "port": 3389,
            "state": "closed"
        }]

        results = detect_threats(events, ANALYSIS_CONFIG)

        self.assertEqual(len(results), 0)

    def test_unknown_port(self):
        events = [{
            "type": "port_observed",
            "ip": "127.0.0.1",
            "port": 45678,
            "state": "open"
        }]

        results = detect_threats(events, ANALYSIS_CONFIG)

        self.assertEqual(results[0]["service"], "Unknown")
        self.assertEqual(results[0]["severity"], "info")

    def test_custom_sensitive_port(self):
        custom_config = {
            "sensitive_ports": [8080],
            "known_services": {"8080": "Custom HTTP"}
        }

        events = [{
            "type": "port_observed",
            "ip": "127.0.0.1",
            "port": 8080,
            "state": "open"
        }]

        results = detect_threats(events, custom_config)

        self.assertEqual(results[0]["severity"], "warning")

    def test_invalid_port(self):
        events = [{
            "type": "port_observed",
            "ip": "127.0.0.1",
            "port": True,
            "state": "open"
        }]

        results = detect_threats(events, ANALYSIS_CONFIG)

        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
