import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = PROJECT_ROOT / "rust-engine" / "Cargo.toml"
BINARY = PROJECT_ROOT / "rust-engine" / "target" / "debug" / "nour-sentinel"


class TestEndToEnd(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Compile le véritable exécutable Rust."""

        subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(MANIFEST)
            ],
            cwd=PROJECT_ROOT,
            check=True,
            timeout=120
        )

        if not BINARY.exists():
            raise RuntimeError("Exécutable Rust introuvable.")

    def test_rust_to_python_complete_pipeline(self):
        """Vérifie Rust, TCP local, Python et le rapport final."""

        # Création d'un serveur TCP local temporaire.
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        test_port = server.getsockname()[1]

        try:
            # Configuration isolée du test.
            test_config = {
                "application": {
                    "name": "NOUR SENTINEL",
                    "version": "0.4.1",
                    "environment": "integration-test"
                },
                "engines": {
                    "rust": {
                        "enabled": True
                    },
                    "python": {
                        "enabled": True,
                        "executable": sys.executable
                    }
                },
                "network": {
                    "targets": ["127.0.0.1"],
                    "discover_arp": False,
                    "scan_discovered_devices": False,
                    "ports": [test_port],
                    "timeout_ms": 1000,
                    "max_concurrency": 2
                },
                "analysis": {
                    "sensitive_ports": [],
                    "known_services": {
                        str(test_port): "TEST-SERVICE"
                    }
                },
                "security": {
                    "authorized_scanning_only": True,
                    "automatic_actions": False
                }
            }

            with tempfile.TemporaryDirectory() as temp_dir:

                config_path = Path(temp_dir) / "settings.json"

                config_path.write_text(
                    json.dumps(test_config),
                    encoding="utf-8"
                )

                # Transmission du chemin de configuration au moteur Rust.
                environment = os.environ.copy()
                environment["NOUR_SENTINEL_CONFIG"] = str(config_path)

                # Isolation stricte de l'historique : la base du développeur
                # n'est jamais utilisée ni modifiée par les tests.
                history_dir = Path(temp_dir) / "history"
                environment["NOUR_SENTINEL_HISTORY_DIR"] = str(history_dir)

                # Exécution du véritable moteur Rust.
                process = subprocess.run(
                    [str(BINARY)],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                self.assertEqual(
                    process.returncode,
                    0,
                    msg=(
                        "Échec du moteur Rust.\n"
                        f"STDOUT:\n{process.stdout}\n"
                        f"STDERR:\n{process.stderr}"
                    )
                )

                # Extraction du rapport JSON dans la sortie Rust.
                marker = "[RUST] Security report:"
                self.assertIn(marker, process.stdout)

                report_text = process.stdout.split(marker, 1)[1].lstrip()

                report, _ = json.JSONDecoder().raw_decode(report_text)

                # Vérification du rapport produit par Python.
                self.assertEqual(report["engine"], "NOUR SENTINEL")
                self.assertEqual(report["version"], "0.4.1")
                self.assertEqual(
                    report["status"],
                    "analysis_completed"
                )

                self.assertEqual(
                    report["network"]["ports_observed"],
                    1
                )

                self.assertEqual(
                    report["network"]["open_ports"],
                    1
                )

                self.assertEqual(report["findings_count"], 1)

                finding = report["findings"][0]

                self.assertEqual(finding["ip"], "127.0.0.1")
                self.assertEqual(finding["port"], test_port)
                self.assertEqual(finding["service"], "TEST-SERVICE")
                self.assertEqual(finding["severity"], "info")

                self.assertIn(
                    "[SUCCESS] NOUR SENTINEL v0.4.1 operational.",
                    process.stdout
                )

                # L'historique a bien été enregistré, dans le répertoire isolé.
                self.assertEqual(report["history"]["status"], "recorded")
                self.assertTrue(
                    (history_dir / "nour_sentinel.db").exists()
                )

        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
