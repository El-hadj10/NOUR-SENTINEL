
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "python-brain")
)

from detector import detect_threats


class TestDetector(unittest.TestCase):

    def test_sensitive_port_detection(self):

        events = [
            {
                "type": "port_observed",
                "port": 3389,
                "state": "open"
            }
        ]

        results = detect_threats(events)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["port"], 3389)

    def test_normal_port(self):

        events = [
            {
                "type": "port_observed",
                "port": 443,
                "state": "open"
            }
        ]

        results = detect_threats(events)

        self.assertEqual(len(results), 0)

    def test_closed_port(self):

        events = [
            {
                "type": "port_observed",
                "port": 3389,
                "state": "closed"
            }
        ]

        results = detect_threats(events)

        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
