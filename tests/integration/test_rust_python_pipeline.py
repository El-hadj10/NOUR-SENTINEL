import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


# Racine du projet NOUR-SENTINEL
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PYTHON_MAIN = PROJECT_ROOT / "python-brain" / "main.py"

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

import authz  # noqa: E402
from intelligence.engine import analyze  # noqa: E402


class TestRustPythonPipeline(unittest.TestCase):

    def setUp(self):
        authz.reset()

    def tearDown(self):
        authz.reset()

    def run_python_engine(self, payload):
        """Analyse le payload après autorisation explicite du processus."""

        try:
            data = json.loads(payload)
        except json.JSONDecodeError as error:
            return SimpleNamespace(returncode=1, stdout="", stderr=str(error))

        try:
            with mock.patch.object(authz, "require"):
                result = analyze(data)
        except Exception as error:
            return SimpleNamespace(returncode=1, stdout="", stderr=str(error))

        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(result),
            stderr="",
        )

    def test_valid_json_pipeline(self):
        """Vérifie la réception JSON et la production du rapport."""

        payload = {
            "source": "rust-network-engine",
            "devices": [
                {
                    "ip": "127.0.0.1",
                    "mac": "00:00:00:00:00:01",
                    "interface": "lo"
                }
            ],
            "events": [
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 22,
                    "state": "open"
                },
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 80,
                    "state": "closed"
                }
            ],
            "analysis_config": {
                "sensitive_ports": [23, 3389, 5900],
                "known_services": {
                    "22": "SSH",
                    "80": "HTTP"
                }
            }
        }

        process = self.run_python_engine(json.dumps(payload))

        self.assertEqual(
            process.returncode,
            0,
            msg=process.stderr
        )

        report = json.loads(process.stdout)

        self.assertEqual(report["engine"], "NOUR SENTINEL")
        self.assertEqual(report["version"], "0.5.0")
        self.assertEqual(report["core_version"], "0.5.0")
        self.assertEqual(report["lab_version"], "0.6.0-beta.4")
        self.assertEqual(report["protocol_version"], "3.0")
        self.assertEqual(report["source"], "rust-network-engine")
        self.assertEqual(report["status"], "analysis_completed")

        self.assertEqual(report["network"]["neighbors_discovered"], 1)
        self.assertEqual(report["network"]["ports_observed"], 2)
        self.assertEqual(report["network"]["open_ports"], 1)

        self.assertEqual(report["findings_count"], 1)

        finding = report["findings"][0]

        self.assertEqual(finding["port"], 22)
        self.assertEqual(finding["service"], "SSH")
        self.assertEqual(finding["check"], "exposure.port.22")
        self.assertTrue(finding["finding_id"].startswith("f-"))
        self.assertEqual(finding["exposure"], "local")

        self.assertEqual(report["risk_summary"]["total"], 1)

    def test_sensitive_port_detection(self):
        """Vérifie qu'un port sensible ouvert génère une alerte."""

        payload = {
            "source": "rust-network-engine",
            "devices": [],
            "events": [
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 3389,
                    "state": "open"
                }
            ],
            "analysis_config": {
                "sensitive_ports": [3389],
                "known_services": {
                    "3389": "RDP"
                }
            }
        }

        process = self.run_python_engine(json.dumps(payload))

        self.assertEqual(process.returncode, 0)

        report = json.loads(process.stdout)

        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["severity"], "medium")
        self.assertEqual(report["findings"][0]["service"], "RDP")

    def test_closed_ports_generate_no_findings(self):
        """Vérifie qu'un port fermé ne produit aucune alerte."""

        payload = {
            "source": "rust-network-engine",
            "devices": [],
            "events": [
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 22,
                    "state": "closed"
                }
            ],
            "analysis_config": {
                "sensitive_ports": [22],
                "known_services": {
                    "22": "SSH"
                }
            }
        }

        process = self.run_python_engine(json.dumps(payload))

        self.assertEqual(process.returncode, 0)

        report = json.loads(process.stdout)

        self.assertEqual(report["network"]["open_ports"], 0)
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["findings"], [])

    def test_inventory_is_identified_and_exposed(self):
        """Vérifie l'inventaire local : service confirmé et écoute générique."""

        payload = {
            "source": "rust-network-engine",
            "devices": [],
            "events": [
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 22,
                    "state": "open"
                }
            ],
            "analysis_config": {
                "sensitive_ports": [],
                "known_services": {"22": "SSH"}
            },
            "inventory": {
                "hostname": "kali",
                "kernel": "6.8.0-kali1-amd64",
                "distribution": "Kali GNU/Linux Rolling",
                "interfaces": [],
                "listeners": [
                    {
                        "address": "0.0.0.0",
                        "port": 22,
                        "family": "ipv4",
                        "state": "listen",
                        "pid": 4242,
                        "process": "sshd",
                        "exe": "/usr/sbin/sshd",
                        "unit": "ssh.service",
                        "container": None,
                        "confidence": "confirmed"
                    }
                ]
            },
            "authorized_targets": ["127.0.0.1"],
            "intelligence_config": {},
            "tools_config": {}
        }

        report = json.loads(self.run_python_engine(json.dumps(payload)).stdout)

        self.assertEqual(report["inventory"]["hostname"], "kali")
        self.assertEqual(report["inventory"]["listeners_count"], 1)

        services = report["services"]

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["product"], "OpenSSH")
        self.assertEqual(services[0]["confidence"], "confirmed")

        identified = [
            finding
            for finding in report["findings"]
            if finding["check"] == "service.identified"
        ]
        wildcard = [
            finding
            for finding in report["findings"]
            if finding["check"] == "exposure.wildcard.22"
        ]

        self.assertEqual(len(identified), 1)
        self.assertEqual(identified[0]["severity"], "info")
        self.assertEqual(len(wildcard), 1)
        self.assertEqual(wildcard[0]["severity"], "medium")

        self.assertIn("host_intrusion_detection", report["capabilities"])

    def test_invalid_json_is_rejected(self):
        """Vérifie que le moteur rejette une entrée JSON invalide."""

        process = self.run_python_engine("{invalid-json}")

        self.assertNotEqual(process.returncode, 0)
        self.assertNotEqual(process.stderr.strip(), "")

    def test_direct_main_without_terminal_is_refused(self):
        """L'entrée main.py ne collecte rien sans terminal et sans Auth Gate."""

        process = subprocess.run(
            [sys.executable, str(PYTHON_MAIN)],
            input="{}",
            text=True,
            capture_output=True,
            cwd=PROJECT_ROOT,
            timeout=10,
            start_new_session=True,
        )

        self.assertEqual(process.returncode, 2)
        self.assertIn("AUTH ERROR", process.stderr)
        self.assertEqual(process.stdout, "")

    def test_stdout_contains_only_json(self):
        """Vérifie que stdout ne contient aucun message parasite."""

        payload = {
            "source": "rust-network-engine",
            "devices": [],
            "events": [],
            "analysis_config": {
                "sensitive_ports": [],
                "known_services": {}
            }
        }

        process = self.run_python_engine(json.dumps(payload))

        self.assertEqual(process.returncode, 0)

        # Si stdout contient des messages parasites,
        # json.loads échouera.
        report = json.loads(process.stdout)

        self.assertIsInstance(report, dict)
        self.assertEqual(report["status"], "analysis_completed")


if __name__ == "__main__":
    unittest.main()
