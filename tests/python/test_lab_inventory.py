import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import make_config
from security_intelligence.fingerprinting import inventory


def make_runner(dpkg_rc=0, rpm_rc=0):
    def runner(argv, timeout=15):
        if argv[0] == "dpkg-query":
            return {
                "returncode": dpkg_rc,
                "stdout": (
                    "openssh-server\t1:9.6p1-3ubuntu13\n"
                    "apache2\t2.4.58-1ubuntu4\n"
                    "nginx\t1.24.0-1\n"
                    "libssl3t64\t3.0.13-1\n"
                ),
                "stderr": "",
            }

        if argv[0] == "rpm":
            return {
                "returncode": rpm_rc,
                "stdout": "openssh-server\t9.6p1-1\n",
                "stderr": "",
            }

        if argv[0] == "systemctl":
            return {
                "returncode": 0,
                "stdout": (
                    "ssh.service loaded active running OpenBSD Secure Shell server\n"
                    "nginx.service loaded active running A high performance web server\n"
                ),
                "stderr": "",
            }

        if argv[0] == "ss":
            return {
                "returncode": 0,
                "stdout": (
                    "LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\n"
                    "LISTEN 0 4096 [::]:22 [::]:*\n"
                    "LISTEN 0 4096 *:80 *:*\n"
                ),
                "stderr": "",
            }

        return {"returncode": -1, "stdout": "", "stderr": "inconnu"}

    return runner


class TestInventoryParsers(unittest.TestCase):
    def test_os_release(self):
        values = inventory.parse_os_release(
            'NAME="Ubuntu"\nVERSION_ID="26.04"\n# commentaire\nPRETTY_NAME=Ubuntu 26.04 LTS\n'
        )

        self.assertEqual(values["NAME"], "Ubuntu")
        self.assertEqual(values["PRETTY_NAME"], "Ubuntu 26.04 LTS")
        self.assertNotIn("# commentaire", values)

    def test_dpkg_and_rpm_outputs(self):
        packages = inventory.parse_package_output(
            "openssh-server\t1:9.6p1-3\nligne-invalide\n", "dpkg"
        )

        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["package"], "openssh-server")
        self.assertEqual(packages[0]["manager"], "dpkg")

    def test_package_manager_fallback_to_rpm(self):
        manager, packages = inventory.list_packages(make_runner(dpkg_rc=1))

        self.assertEqual(manager, "rpm")
        self.assertEqual(packages[0]["manager"], "rpm")

    def test_ss_parsing_ipv4_ipv6_wildcard(self):
        listeners = inventory.parse_ss_output(
            "LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\n"
            "LISTEN 0 4096 [::]:22 [::]:*\n"
            "LISTEN 0 4096 *:80 *:*\n"
            "ligne-courte\n"
        )

        self.assertEqual(len(listeners), 3)
        self.assertIn(
            {"address": "127.0.0.1", "port": 631, "family": "ipv4"}, listeners
        )
        self.assertIn({"address": "::", "port": 22, "family": "ipv6"}, listeners)
        self.assertIn(
            {"address": "0.0.0.0", "port": 80, "family": "ipv4"}, listeners
        )

    def test_systemd_units(self):
        units = inventory.parse_systemd_units(
            "ssh.service loaded active running OpenSSH\n"
            "nginx.service loaded active running nginx\n"
            "session-1.scope loaded active running session\n"
        )

        self.assertEqual(units, ["ssh.service", "nginx.service"])

    def test_known_package_fingerprints(self):
        products = inventory.fingerprint_packages(
            [
                {"package": "openssh-server", "version": "9.6", "manager": "dpkg"},
                {"package": "docker.io", "version": "29.1", "manager": "dpkg"},
                {"package": "libssl3t64", "version": "3.0", "manager": "dpkg"},
            ]
        )

        names = {product["product"] for product in products}

        self.assertEqual(names, {"OpenSSH", "Docker Engine", "OpenSSL"})
        self.assertTrue(all(item["confidence"] == "confirmed" for item in products))


class TestInventoryCollect(unittest.TestCase):
    def test_collect_with_fake_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)

            with mock.patch.object(
                inventory, "run_command", make_runner()
            ):
                data = inventory.collect(config)

            self.assertEqual(data["package_manager"], "dpkg")
            self.assertEqual(data["package_count"], 4)
            self.assertEqual(len(data["services"]), 2)
            self.assertEqual(len(data["listeners"]), 3)
            self.assertIn("OpenSSH", {p["product"] for p in data["products"]})
            self.assertIn("hostname", data["host"])
            self.assertEqual(data["errors"], [])

    def test_collect_reports_package_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)

            with mock.patch.object(
                inventory, "run_command", make_runner(dpkg_rc=1, rpm_rc=1)
            ):
                data = inventory.collect(config)

            self.assertEqual(data["package_count"], 0)
            self.assertTrue(
                any("paquets" in error for error in data["errors"])
            )


if __name__ == "__main__":
    unittest.main()
