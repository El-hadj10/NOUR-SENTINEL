import json
import subprocess
import sys
import unittest
from pathlib import Path


# Racine du projet NOUR-SENTINEL
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PYTHON_MAIN = PROJECT_ROOT / "python-brain" / "main.py"


class TestRustPythonPipeline(unittest.TestCase):

    def run_python_engine(self, payload):
        """Envoie un JSON au moteur Python et récupère sa réponse."""

        process = subprocess.run(
            [sys.executable, str(PYTHON_MAIN)],
            input=payload,
            text=True,
            capture_output=True,
            cwd=PROJECT_ROOT,
            timeout=10
        )

        return process

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
        self.assertEqual(report["version"], "0.4.0")
        self.assertEqual(report["source"], "rust-network-engine")
        self.assertEqual(report["status"], "analysis_completed")

        self.assertEqual(report["network"]["neighbors_discovered"], 1)
        self.assertEqual(report["network"]["ports_observed"], 2)
        self.assertEqual(report["network"]["open_ports"], 1)

        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["port"], 22)
        self.assertEqual(report["findings"][0]["service"], "SSH")

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
        self.assertEqual(report["findings"][0]["severity"], "warning")
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

    def test_invalid_json_is_rejected(self):
        """Vérifie que le moteur rejette une entrée JSON invalide."""

        process = self.run_python_engine("{invalid-json}")

        self.assertNotEqual(process.returncode, 0)
        self.assertNotEqual(process.stderr.strip(), "")

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
