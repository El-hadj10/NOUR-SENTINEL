import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from security_intelligence import VERSION


def load_canonical_versions():
    spec = importlib.util.spec_from_file_location(
        "nour_canonical_versions", PROJECT_ROOT / "python-brain" / "version.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


class TestVersionConsistency(unittest.TestCase):
    def setUp(self):
        self.versions = load_canonical_versions()
        self.launcher = (PROJECT_ROOT / "lancer-nour-sentinel.sh").read_text(
            encoding="utf-8"
        )

    def test_launcher_constants_match_python_source(self):
        expected = {
            "VERSION": self.versions.LAB_VERSION,
            "CORE_VERSION": self.versions.CORE_VERSION,
            "PROTOCOL_VERSION": self.versions.PROTOCOL_VERSION,
        }

        for name, value in expected.items():
            match = re.search(rf'^{name}="([^"]+)"$', self.launcher, re.MULTILINE)
            self.assertIsNotNone(match, f"{name} absent du lanceur")
            self.assertEqual(match.group(1), value, name)

        self.assertIn(self.versions.LAB_VERSION, self.launcher.splitlines()[1])

    def test_protocol_document_matches_python_source(self):
        document = json.loads(
            (PROJECT_ROOT / "communication" / "protocol.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(document["protocol_version"], self.versions.PROTOCOL_VERSION)
        self.assertEqual(document["version"], self.versions.PROTOCOL_VERSION)
        self.assertEqual(document["core_version"], self.versions.CORE_VERSION)
        self.assertEqual(document["lab_version"], self.versions.LAB_VERSION)
        self.assertEqual(self.versions.LAB_VERSION, VERSION)


if __name__ == "__main__":
    unittest.main()
