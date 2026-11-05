import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from security_intelligence import VERSION, auth_gate, cli, lab
from security_intelligence import config as config_module


class TestCli(unittest.TestCase):
    def test_operational_command_requires_authentication_before_config(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(
            auth_gate,
            "authenticate",
            side_effect=auth_gate.AuthError("authentification refusée"),
        ):
            with mock.patch.object(config_module, "load_config") as load_config:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    stderr
                ):
                    status = cli.main(["inventory"])

        self.assertEqual(status, 2)
        self.assertIn("AUTH ERROR", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")
        load_config.assert_not_called()

    def test_inventory_command_returns_json_after_authentication(self):
        report = {
            "version": VERSION,
            "mode": "inventory",
            "findings": [],
            "findings_count": 0,
            "risk_summary": {"total": 0, "with_evidence": 0},
            "errors": [],
        }

        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with mock.patch.object(lab, "run_inventory", return_value=report):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    stderr
                ):
                    status = cli.main(["inventory"])

        self.assertEqual(status, 0)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["version"], VERSION)
        self.assertIn("[LAB] mode=inventory", stderr.getvalue())

    def test_cve_without_online_is_refused(self):
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with contextlib.redirect_stderr(stderr):
                status = cli.main(["cve"])

        self.assertEqual(status, 3)
        self.assertIn("--online", stderr.getvalue())

    def test_invalid_port_is_refused(self):
        stderr = io.StringIO()

        with mock.patch.object(auth_gate, "authenticate", return_value=True):
            with contextlib.redirect_stderr(stderr):
                status = cli.main(["tls", "--target", "127.0.0.1", "--port", "0"])

        self.assertEqual(status, 1)
        self.assertIn("port TCP invalide", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
