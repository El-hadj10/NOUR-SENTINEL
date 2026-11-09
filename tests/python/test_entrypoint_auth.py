import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import authz
from intelligence import engine
from lab_helpers import make_config
from security_intelligence import lab
from security_intelligence.applications import docker
from security_intelligence.fingerprinting import inventory, service_probe
from security_intelligence.intrusion import journal
from security_intelligence.passwords import policy
from security_intelligence.tls import analyzer as tls_analyzer
from security_intelligence.vulnerabilities import online


class TestDirectEntrypoints(unittest.TestCase):
    def setUp(self):
        authz.reset()

    def tearDown(self):
        authz.reset()

    def test_lab_collection_is_refused_without_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)

            with mock.patch.object(inventory, "collect") as collect:
                with self.assertRaises(authz.AuthorizationError):
                    lab.run_inventory(config)

                collect.assert_not_called()

    def test_engine_analysis_is_refused_without_authorization(self):
        with self.assertRaises(authz.AuthorizationError):
            engine.analyze({})

    def test_all_lab_operations_refuse_before_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            calls = {
                "full-local": lambda: lab.run_full_local(config),
                "fingerprint": lambda: lab.run_fingerprint(
                    config, "127.0.0.1", 22, "ssh"
                ),
                "tls": lambda: lab.run_tls(config, "127.0.0.1", 443),
                "cve-online": lambda: lab.run_cve_online(
                    config, "openssh-server", "9.6"
                ),
                "finalize": lambda: lab.finalize("inventory", config, [], []),
            }

            with mock.patch.object(inventory, "collect") as collect:
                for name, call in calls.items():
                    with self.subTest(operation=name):
                        with self.assertRaises(authz.AuthorizationError):
                            call()

                collect.assert_not_called()

    def test_external_tools_are_refused_without_authorization(self):
        with mock.patch.object(
            engine.adapters, "available", return_value=True
        ), mock.patch.object(engine.adapters, "run_tool") as run_tool:
            with self.assertRaises(authz.AuthorizationError):
                engine.collect_tool_findings(
                    {"enabled": True, "nmap": True},
                    {
                        "listeners": [
                            {"address": "127.0.0.1", "port": 22}
                        ]
                    },
                    ["127.0.0.1"],
                    "lab-host",
                )

            run_tool.assert_not_called()

    def test_low_level_collectors_are_refused_without_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            calls = {
                "inventory": lambda: inventory.collect(config),
                "policy": lambda: policy.collect(config, "localhost"),
                "journal": lambda: journal.collect(config, "localhost"),
                "docker": lambda: docker.collect(config, "localhost"),
                "tls": lambda: tls_analyzer.audit(
                    "127.0.0.1", 443, allowed=("127.0.0.1",)
                ),
                "ssh": lambda: service_probe.probe_ssh(
                    "127.0.0.1", 22, allowed=("127.0.0.1",)
                ),
                "http": lambda: service_probe.probe_http(
                    "127.0.0.1", 80, allowed=("127.0.0.1",)
                ),
                "online": lambda: online.OnlineIntel(config).query_osv(
                    "openssh-server", "9.6"
                ),
            }

            for name, call in calls.items():
                authz.reset()
                with self.subTest(collector=name):
                    with self.assertRaises(authz.AuthorizationError):
                        call()

    def test_lab_accepts_after_test_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            data = {
                "host": {"hostname": "lab-host"},
                "os_release": {},
                "package_manager": None,
                "package_count": 0,
                "packages": [],
                "products": [],
                "services": [],
                "listeners": [],
                "errors": [],
            }

            with mock.patch.object(authz, "require"), mock.patch.object(
                inventory, "collect", return_value=data
            ):
                report = lab.run_inventory(config)

            self.assertEqual(report["mode"], "inventory")
            self.assertEqual(report["findings_count"], 0)


if __name__ == "__main__":
    unittest.main()
