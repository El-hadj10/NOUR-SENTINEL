import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import make_config
from intelligence.models import make_finding
import authz
from security_intelligence import (
    BASE_VERSION,
    LAB_VERSION,
    PROTOCOL_VERSION,
    VERSION,
    lab,
)
from security_intelligence.store import IntelStore


def inventory_fixture():
    return {
        "host": {
            "hostname": "lab-host",
            "kernel": "6.8.0",
            "distribution": "Ubuntu 26.04 LTS",
        },
        "os_release": {"PRETTY_NAME": "Ubuntu 26.04 LTS"},
        "package_manager": "dpkg",
        "package_count": 2,
        "packages": [
            {"package": "openssh-server", "version": "9.6p1-3", "manager": "dpkg"},
            {"package": "nginx", "version": "1.24.0-1", "manager": "dpkg"},
        ],
        "products": [
            {
                "service": "ssh",
                "product": "OpenSSH",
                "version": "9.6p1-3",
                "confidence": "confirmed",
            }
        ],
        "services": ["ssh.service"],
        "listeners": [{"address": "0.0.0.0", "port": 22, "family": "ipv4"}],
        "errors": [],
    }


class TestOrchestration(unittest.TestCase):
    def setUp(self):
        authorization = mock.patch.object(authz, "require")
        authorization.start()
        self.addCleanup(authorization.stop)

    def test_inventory_report_is_persisted_privately(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)

            with mock.patch.object(
                lab.inventory, "collect", return_value=inventory_fixture()
            ):
                report = lab.run_inventory(config)

            self.assertEqual(report["version"], VERSION)
            self.assertEqual(report["lab_version"], LAB_VERSION)
            self.assertEqual(report["core_version"], BASE_VERSION)
            self.assertEqual(report["protocol_version"], PROTOCOL_VERSION)
            self.assertEqual(report["mode"], "inventory")
            self.assertEqual(report["inventory"]["package_count"], 2)
            self.assertEqual(report["findings"], [])

            report_path = Path(report["report_path"])
            self.assertTrue(report_path.exists())
            self.assertEqual(stat.S_IMODE(os.stat(report_path).st_mode), 0o600)

            store = IntelStore(config["database"])
            self.assertEqual(store.count_runs(), 1)
            store.close()

    def test_full_local_combines_policy_and_docker(self):
        finding = make_finding(
            asset="lab-host",
            check="ssh_policy.root_login",
            component="OpenSSH",
            observation="Connexion root autorisée",
            evidence="sshd_config:PermitRootLogin yes",
            confidence="confirmed",
            severity="high",
            exposure="local",
        )

        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)

            with mock.patch.object(
                lab.inventory, "collect", return_value=inventory_fixture()
            ), mock.patch.object(
                lab.policy, "collect", return_value=([finding], {}, [])
            ), mock.patch.object(
                lab.docker_inventory, "collect", return_value=([], {"containers": []}, [])
            ):
                report = lab.run_full_local(config)

            self.assertEqual(report["mode"], "full-local")
            self.assertEqual(report["findings_count"], 1)
            self.assertEqual(report["findings"][0]["check"], "ssh_policy.root_login")
            self.assertEqual(
                report["details"]["policies"], {}
            )

    def test_tls_outside_whitelist_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)

            with self.assertRaises(PermissionError):
                lab.run_tls(config, "10.0.0.1", 443)

    def test_online_cve_requires_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            config["online"]["enabled"] = False

            with self.assertRaises(PermissionError):
                lab.run_cve_online(config, package="openssh-server", version="9.6")

    def test_fingerprint_rejects_unknown_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)

            with self.assertRaises(ValueError):
                lab.run_fingerprint(config, "127.0.0.1", 80, protocol="smtp")


if __name__ == "__main__":
    unittest.main()
