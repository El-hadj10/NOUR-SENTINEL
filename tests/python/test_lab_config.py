import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from security_intelligence import VERSION
from security_intelligence import config as lab_config


class TestLabConfig(unittest.TestCase):
    def load_document(self):
        return json.loads(
            (PROJECT_ROOT / "config" / "security_intelligence.json").read_text(
                encoding="utf-8"
            )
        )

    def test_repository_config_is_valid_and_local_only(self):
        config = lab_config.load_config()

        self.assertEqual(config["version"], VERSION)
        self.assertEqual(config["authorized_targets"], ("127.0.0.1", "localhost"))
        self.assertTrue(
            str(config["reports_dir"]).startswith(str(PROJECT_ROOT / "data"))
        )
        self.assertTrue(
            str(config["database"]).startswith(str(PROJECT_ROOT / "data"))
        )

    def test_wrong_lab_version_is_rejected(self):
        document = self.load_document()
        document["application"]["version"] = "0.5.0"

        with self.assertRaises(lab_config.ConfigError):
            lab_config.validate_config(document)

    def test_non_ip_target_is_rejected(self):
        document = self.load_document()
        document["authorized_targets"] = ["example.com"]

        with self.assertRaises(lab_config.ConfigError):
            lab_config.validate_config(document)

    def test_empty_target_list_is_rejected(self):
        document = self.load_document()
        document["authorized_targets"] = []

        with self.assertRaises(lab_config.ConfigError):
            lab_config.validate_config(document)

    def test_report_path_outside_data_is_rejected(self):
        document = self.load_document()
        document["reports"]["directory"] = "/tmp/nour-elsewhere"

        with self.assertRaises(lab_config.ConfigError):
            lab_config.validate_config(document)

    def test_targets_are_deduplicated(self):
        document = self.load_document()
        document["authorized_targets"] = ["127.0.0.1", "127.0.0.1", "localhost"]

        config = lab_config.validate_config(document)

        self.assertEqual(config["authorized_targets"], ("127.0.0.1", "localhost"))

    def test_resolve_target_enforces_whitelist(self):
        self.assertEqual(
            lab_config.resolve_target("localhost", ("localhost",)), ["127.0.0.1"]
        )
        self.assertEqual(
            lab_config.resolve_target("127.0.0.1", ("127.0.0.1",)), ["127.0.0.1"]
        )

        with self.assertRaises(PermissionError):
            lab_config.resolve_target("10.0.0.1", ("127.0.0.1",))

    def test_bounds_are_enforced(self):
        document = self.load_document()
        document["online"]["max_requests"] = 1000

        with self.assertRaises(lab_config.ConfigError):
            lab_config.validate_config(document)


if __name__ == "__main__":
    unittest.main()
