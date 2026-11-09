import json
import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

import authz
from security_intelligence import VERSION
from security_intelligence import config as lab_config


class TestLabConfig(unittest.TestCase):
    def load_document(self):
        return json.loads(
            (PROJECT_ROOT / "config" / "security_intelligence.json").read_text(
                encoding="utf-8"
            )
        )

    def test_repository_config_defers_default_gateway_resolution(self):
        with mock.patch.object(
            lab_config, "resolve_default_gateway"
        ) as resolve_gateway:
            config = lab_config.load_config()

        self.assertEqual(config["version"], VERSION)
        self.assertEqual(
            config["authorized_targets"], (lab_config.DEFAULT_GATEWAY,)
        )
        resolve_gateway.assert_not_called()
        self.assertTrue(
            str(config["reports_dir"]).startswith(str(PROJECT_ROOT / "data"))
        )
        self.assertTrue(
            str(config["database"]).startswith(str(PROJECT_ROOT / "data"))
        )

    def test_default_gateway_route_is_parsed_strictly(self):
        self.assertEqual(
            lab_config.parse_default_gateway(
                "default via 10.23.45.1 dev test0 proto dhcp metric 600\n"
            ),
            "10.23.45.1",
        )

        for route in (
            "",
            "default dev wlp2s0\n",
            "default via 10.23.45.1 dev test0\ndefault via 10.0.0.1 dev test1\n",
            "default via 8.8.8.8 dev wlp2s0\n",
            "default via 192.0.0.1 dev test0\n",
            "default via ::1 dev wlp2s0\n",
        ):
            with self.subTest(route=route), self.assertRaises(lab_config.ConfigError):
                lab_config.parse_default_gateway(route)

    def test_gateway_resolver_uses_literal_route_command(self):
        result = mock.Mock(
            returncode=0,
            stdout="default via 10.23.45.1 dev test0\n",
        )

        with mock.patch.object(authz, "require"), mock.patch.object(
            lab_config.subprocess, "run", return_value=result
        ) as run:
            self.assertEqual(
                lab_config.resolve_default_gateway(),
                "10.23.45.1",
            )

        run.assert_called_once_with(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )

    def test_gateway_resolver_fails_closed_when_route_command_fails(self):
        result = mock.Mock(returncode=2, stdout="")

        with mock.patch.object(authz, "require"), mock.patch.object(
            lab_config.subprocess, "run", return_value=result
        ):
            with self.assertRaises(lab_config.ConfigError):
                lab_config.resolve_default_gateway()

    def test_resolving_the_default_gateway_requires_authorization(self):
        result = mock.Mock(returncode=0, stdout="default via 10.23.45.1 dev test0\n")

        with mock.patch.object(lab_config.subprocess, "run", return_value=result) as run:
            with self.assertRaises(authz.AuthorizationError):
                lab_config.resolve_default_gateway()

        run.assert_not_called()

    def test_default_gateway_is_the_only_allowed_dynamic_target(self):
        document = self.load_document()
        document["authorized_targets"] = ["default_gateway"]

        with mock.patch.object(
            lab_config, "resolve_default_gateway", return_value="10.23.45.1"
        ):
            config = lab_config.validate_config(document)

        self.assertEqual(config["authorized_targets"], ("default_gateway",))

        document["authorized_targets"] = ["default_gateway", "127.0.0.1"]
        with self.assertRaises(lab_config.ConfigError):
            lab_config.validate_config(document)

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

    def test_default_gateway_is_resolved_only_when_target_is_used(self):
        with mock.patch.object(
            lab_config, "resolve_default_gateway", return_value="192.168.1.1"
        ) as resolve_gateway:
            self.assertEqual(
                lab_config.resolve_target(
                    "192.168.1.1", (lab_config.DEFAULT_GATEWAY,)
                ),
                ["192.168.1.1"],
            )
            resolve_gateway.assert_called_once_with()

    def test_bounds_are_enforced(self):
        document = self.load_document()
        document["online"]["max_requests"] = 1000

        with self.assertRaises(lab_config.ConfigError):
            lab_config.validate_config(document)


if __name__ == "__main__":
    unittest.main()
