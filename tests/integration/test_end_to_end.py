import json
import os
import socket
import sqlite3
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

    def build_config(self, ports, known_services=None):
        """Configuration isolée, de périmètre identique d'un scan à l'autre."""

        return {
            "application": {
                "name": "NOUR SENTINEL",
                "version": "0.5.0",
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
                "ports": ports,
                "timeout_ms": 1000,
                "max_concurrency": 2
            },
            "analysis": {
                "sensitive_ports": [],
                "known_services": known_services or {}
            },
            "security": {
                "authorized_scanning_only": True,
                "automatic_actions": False
            }
        }

    def write_config(self, temp_dir, ports, known_services=None):
        config_path = Path(temp_dir) / "settings.json"

        config_path.write_text(
            json.dumps(self.build_config(ports, known_services)),
            encoding="utf-8"
        )

        return config_path

    def run_engine(self, config_path, history_dir):
        """Exécute le moteur avec configuration et historique isolés."""

        environment = os.environ.copy()
        environment["NOUR_SENTINEL_CONFIG"] = str(config_path)

        # Isolation stricte de l'historique : la base du développeur
        # n'est jamais utilisée ni modifiée par les tests.
        environment["NOUR_SENTINEL_HISTORY_DIR"] = str(history_dir)

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

        return process

    def parse_report(self, process):
        """Extrait le rapport JSON produit par Python dans la sortie Rust."""

        marker = "[RUST] Security report:"
        self.assertIn(marker, process.stdout)

        report_text = process.stdout.split(marker, 1)[1].lstrip()

        report, _ = json.JSONDecoder().raw_decode(report_text)

        return report

    def test_rust_to_python_complete_pipeline(self):
        """Vérifie Rust, TCP local, Python et le rapport final."""

        # Création d'un serveur TCP local temporaire.
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        test_port = server.getsockname()[1]

        try:
            with tempfile.TemporaryDirectory() as temp_dir:

                config_path = self.write_config(
                    temp_dir,
                    [test_port],
                    {str(test_port): "TEST-SERVICE"}
                )

                history_dir = Path(temp_dir) / "history"

                process = self.run_engine(config_path, history_dir)
                report = self.parse_report(process)

                # Vérification du rapport produit par Python.
                self.assertEqual(report["engine"], "NOUR SENTINEL")
                self.assertEqual(report["version"], "0.5.0")
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

                self.assertGreaterEqual(report["findings_count"], 1)

                # Le constat réseau est retrouvé par son contrôle : depuis la
                # v0.5.0, l'inventaire local peut ajouter d'autres constats.
                finding = next(
                    item
                    for item in report["findings"]
                    if item["check"] == f"exposure.port.{test_port}"
                )

                self.assertEqual(finding["ip"], "127.0.0.1")
                self.assertEqual(finding["port"], test_port)
                self.assertEqual(finding["service"], "TEST-SERVICE")
                self.assertEqual(finding["severity"], "info")
                self.assertEqual(finding["confidence"], "low")

                # Inventaire local : le socket du serveur de test est attribué
                # au processus Python (même utilisateur).
                self.assertGreaterEqual(
                    report["inventory"]["listeners_count"],
                    1
                )

                self.assertIn(
                    "[SUCCESS] NOUR SENTINEL v0.5.0 operational.",
                    process.stdout
                )

                # L'historique a bien été enregistré, dans le répertoire isolé.
                self.assertEqual(report["history"]["status"], "recorded")
                self.assertTrue(
                    (history_dir / "nour_sentinel.db").exists()
                )

        finally:
            server.close()

    def test_second_scan_detects_newly_open_port(self):
        """Vérifie la persistance réelle et la détection comportementale.

        Le port est déjà dans le périmètre du premier scan : son ouverture est
        un changement d'état (`closed` -> `open`), pas une apparition.
        """

        # Port libre mais fermé pour le premier scan.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        test_port = probe.getsockname()[1]
        probe.close()

        with tempfile.TemporaryDirectory() as temp_dir:

            config_path = self.write_config(
                temp_dir,
                [test_port],
                {str(test_port): "TEST-SERVICE"}
            )

            history_dir = Path(temp_dir) / "history"

            # Premier scan : le port est fermé.
            first = self.parse_report(
                self.run_engine(config_path, history_dir)
            )

            self.assertEqual(first["network"]["open_ports"], 0)
            self.assertEqual(first["history"]["status"], "recorded")
            self.assertIsNone(first["history"]["previous_scan_id"])
            self.assertFalse(first["history"]["scope_changed"])
            self.assertEqual(first["behavioral_changes"], [])

            # Deuxième scan, périmètre identique : le port est ouvert.
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", test_port))
            server.listen(1)

            try:
                second = self.parse_report(
                    self.run_engine(config_path, history_dir)
                )
            finally:
                server.close()

            self.assertEqual(second["network"]["open_ports"], 1)

            # Comparaison effective avec le scan précédent, même périmètre.
            self.assertEqual(
                second["history"]["previous_scan_id"],
                first["history"]["scan_id"]
            )
            self.assertFalse(second["history"]["scope_changed"])

            self.assertEqual(len(second["behavioral_changes"]), 1)

            change = second["behavioral_changes"][0]

            self.assertEqual(change["port"], test_port)
            self.assertEqual(change["ip"], "127.0.0.1")
            self.assertEqual(change["change_type"], "state_changed")
            self.assertEqual(change["previous_state"], "closed")
            self.assertEqual(change["current_state"], "open")

            # Persistance vérifiée directement dans la base isolée.
            connection = sqlite3.connect(str(history_dir / "nour_sentinel.db"))

            try:
                scans_count = connection.execute(
                    "SELECT COUNT(*) FROM scans"
                ).fetchone()[0]

                events_count = connection.execute(
                    "SELECT COUNT(*) FROM scan_events"
                ).fetchone()[0]
            finally:
                connection.close()

            self.assertEqual(scans_count, 2)
            self.assertEqual(events_count, 2)


if __name__ == "__main__":
    unittest.main()
