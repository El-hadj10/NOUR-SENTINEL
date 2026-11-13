import errno
import importlib.util
import json
import os
import pty
import select
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = PROJECT_ROOT / "rust-engine" / "Cargo.toml"
BINARY = PROJECT_ROOT / "rust-engine" / "target" / "debug" / "nour-sentinel"
SECRET = "phrase secrete e2e beta2 2026"

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from security_intelligence import auth_gate  # noqa: E402

ARGON2_AVAILABLE = importlib.util.find_spec("argon2") is not None


@unittest.skipUnless(
    ARGON2_AVAILABLE, "argon2-cffi absent; exécutez ./lancer-nour-sentinel.sh --setup-deps"
)
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

    def build_config(self, ports, known_services=None, discover_arp=False):
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
                    "enabled": True
                }
            },
            "network": {
                "targets": ["127.0.0.1"],
                "discover_arp": discover_arp,
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

    def write_config(self, temp_dir, ports, known_services=None, discover_arp=False):
        config_path = Path(temp_dir) / "settings.json"

        config_path.write_text(
            json.dumps(self.build_config(ports, known_services, discover_arp)),
            encoding="utf-8"
        )

        return config_path

    def prepare_auth(self, temp_dir):
        """Crée un HOME isolé, un hash Argon2id et un ancien session.json forgé."""

        home = Path(temp_dir) / "home"
        home.mkdir(mode=0o700)

        config_dir = home / ".config" / "nour-sentinel"
        config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(config_dir, 0o700)

        auth_gate.setup(SECRET, path=config_dir / "auth.phc")

        # Cette donnée ne doit plus jamais ouvrir l'accès : elle sert de
        # régression explicite contre la session forgeable de beta.1.
        forged = config_dir / "session.json"
        forged.write_text(
            json.dumps({"expires_at": int(time.time()) + 3600}),
            encoding="utf-8"
        )
        os.chmod(forged, 0o600)

        return home

    def run_engine_pty(self, config_path, history_dir, home, secrets):
        """Exécute le binaire sous PTY et fournit les secrets aux invites."""

        environment = os.environ.copy()

        for name in (
            "NOUR_SENTINEL_SESSION",
            "NOUR_SENTINEL_AUTH_FILE",
            "NOUR_SENTINEL_PYTHON",
            "NOUR_SENTINEL_VENV",
        ):
            environment.pop(name, None)

        environment["HOME"] = str(home)
        environment["NOUR_SENTINEL_CONFIG"] = str(config_path)
        environment["NOUR_SENTINEL_HISTORY_DIR"] = str(history_dir)

        pid, master = pty.fork()

        if pid == 0:
            try:
                os.execvpe(str(BINARY), [str(BINARY)], environment)
            finally:
                os._exit(127)

        os.set_blocking(master, False)

        pending = [secret.encode("utf-8") for secret in secrets]
        answered = 0
        output = bytearray()
        deadline = time.monotonic() + 60
        status = None

        try:
            while True:
                if time.monotonic() > deadline:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                    self.fail("délai PTY dépassé")

                ready, _, _ = select.select([master], [], [], 0.1)

                if ready:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise

                    if not chunk:
                        break

                    output.extend(chunk)

                prompts = bytes(output).count(b"Phrase secr")

                while answered < len(pending) and prompts > answered:
                    try:
                        os.write(master, pending[answered] + b"\n")
                    except OSError:
                        pass

                    answered += 1

            _, raw_status = os.waitpid(pid, 0)
            status = os.waitstatus_to_exitcode(raw_status)
        finally:
            os.close(master)

        return subprocess.CompletedProcess(
            [str(BINARY)],
            status,
            bytes(output).decode("utf-8", errors="replace"),
            "",
        )

    def parse_report(self, process):
        """Extrait le rapport JSON produit par Python dans la sortie Rust."""

        marker = "[RUST] Security report:"
        self.assertIn(marker, process.stdout)

        report_text = process.stdout.split(marker, 1)[1].lstrip()

        report, _ = json.JSONDecoder().raw_decode(report_text)

        return report

    def test_rust_to_python_complete_pipeline_with_forged_session(self):
        """Vérifie le pipeline complet et ignore un ancien session.json forgé."""

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
                home = self.prepare_auth(temp_dir)

                process = self.run_engine_pty(
                    config_path,
                    history_dir,
                    home,
                    [SECRET],
                )

                self.assertEqual(process.returncode, 0, msg=process.stdout)
                self.assertIn("Phrase secr", process.stdout)

                report = self.parse_report(process)

                self.assertEqual(report["engine"], "NOUR SENTINEL")
                self.assertEqual(report["version"], "0.5.0")
                self.assertEqual(report["core_version"], "0.5.0")
                self.assertEqual(report["lab_version"], "0.6.0-beta.4")
                self.assertEqual(report["protocol_version"], "3.0")
                self.assertEqual(report["status"], "analysis_completed")
                self.assertEqual(report["network"]["ports_observed"], 1)
                self.assertEqual(report["network"]["open_ports"], 1)
                self.assertGreaterEqual(report["findings_count"], 1)

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

                self.assertGreaterEqual(
                    report["inventory"]["listeners_count"],
                    1
                )

                self.assertIn(
                    "core v0.5.0 / lab v0.6.0-beta.4 operational.",
                    process.stdout
                )
                self.assertIn("moteur (core)  : v0.5.0", process.stdout)
                self.assertIn("laboratoire    : v0.6.0-beta.4", process.stdout)
                self.assertIn("protocole JSON : v3.0", process.stdout)

                self.assertEqual(report["history"]["status"], "recorded")
                self.assertTrue(
                    (history_dir / "nour_sentinel.db").exists()
                )

        finally:
            server.close()

    def test_second_scan_detects_newly_open_port_through_pty(self):
        """Vérifie la persistance réelle et la détection comportementale."""

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
            home = self.prepare_auth(temp_dir)

            first = self.parse_report(
                self.run_engine_pty(
                    config_path,
                    history_dir,
                    home,
                    [SECRET],
                )
            )

            self.assertEqual(first["network"]["open_ports"], 0)
            self.assertEqual(first["history"]["status"], "recorded")
            self.assertIsNone(first["history"]["previous_scan_id"])
            self.assertFalse(first["history"]["scope_changed"])
            self.assertEqual(first["behavioral_changes"], [])

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", test_port))
            server.listen(1)

            try:
                second = self.parse_report(
                    self.run_engine_pty(
                        config_path,
                        history_dir,
                        home,
                        [SECRET],
                    )
                )
            finally:
                server.close()

            self.assertEqual(second["network"]["open_ports"], 1)
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

    def test_wrong_secret_locks_and_never_starts_network(self):
        """Trois mauvais secrets verrouillent, malgré une session forgée."""

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        test_port = probe.getsockname()[1]
        probe.close()

        with tempfile.TemporaryDirectory() as temp_dir:

            config_path = self.write_config(temp_dir, [test_port])
            history_dir = Path(temp_dir) / "history"
            home = self.prepare_auth(temp_dir)
            attempts = home / ".config" / "nour-sentinel" / "auth.attempts.json"

            process = self.run_engine_pty(
                config_path,
                history_dir,
                home,
                ["mauvais secret 1", "mauvais secret 2", "mauvais secret 3"],
            )

            self.assertNotEqual(process.returncode, 0)
            self.assertNotIn("[RUST] Security report:", process.stdout)
            self.assertIn("authentification refusée", process.stdout)
            self.assertFalse((history_dir / "nour_sentinel.db").exists())

            state = json.loads(attempts.read_text(encoding="utf-8"))

            self.assertEqual(state["failures"], 3)
            self.assertGreater(state["locked_until"], int(time.time()))
    def test_pre_auth_never_starts_arp_tcp_report_or_sqlite(self):
        """Preuve P0.3 : le refus précède ARP, TCP, rapport et historique."""

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        test_port = server.getsockname()[1]

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                config_path = self.write_config(
                    temp_dir,
                    [test_port],
                    discover_arp=True,
                )
                history_dir = Path(temp_dir) / "history"
                reports_dir = Path(temp_dir) / "reports"
                home = self.prepare_auth(temp_dir)

                process = self.run_engine_pty(
                    config_path,
                    history_dir,
                    home,
                    [
                        "mauvais secret 1",
                        "mauvais secret 2",
                        "mauvais secret 3",
                    ],
                )

                self.assertNotEqual(process.returncode, 0)

                for marker in (
                    "AUTH_OK",
                    "[RUST] Configuration validated.",
                    "[RUST] Passive ARP discovery",
                    "[RUST] Concurrent TCP verification",
                    "[RUST] Security report:",
                ):
                    self.assertNotIn(marker, process.stdout)

                self.assertFalse(history_dir.exists())
                self.assertFalse(reports_dir.exists())

                # Aucune connexion TCP n'a été tentée vers le port configuré.
                server.setblocking(False)

                with self.assertRaises(BlockingIOError):
                    server.accept()

                attempts = (
                    home / ".config" / "nour-sentinel" / "auth.attempts.json"
                )
                state = json.loads(attempts.read_text(encoding="utf-8"))

                self.assertEqual(state["failures"], 3)
                self.assertGreater(state["locked_until"], int(time.time()))
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
