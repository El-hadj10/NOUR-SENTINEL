import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import make_config, write_session
from security_intelligence import VERSION, cli, lab


class TestCli(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.environment = mock.patch.dict(os.environ, {}, clear=False)
        self.environment.start()

        os.environ["NOUR_SENTINEL_SESSION"] = str(self.root / "missing-session.json")
        os.environ["NOUR_SENTINEL_AUTH_FILE"] = str(self.root / "missing-auth.phc")

    def tearDown(self):
        self.environment.stop()
        self.directory.cleanup()

    def test_operational_command_requires_authentication(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = cli.main(["inventory"])

        self.assertEqual(status, 2)
        self.assertIn("AUTH ERROR", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_inventory_command_returns_json_with_valid_session(self):
        session = write_session(self.root)
        os.environ["NOUR_SENTINEL_SESSION"] = str(session)

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

        with mock.patch.object(lab, "run_inventory", return_value=report):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = cli.main(["inventory"])

        self.assertEqual(status, 0)
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["version"], VERSION)
        self.assertIn("[LAB] mode=inventory", stderr.getvalue())

    def test_cve_without_online_is_refused(self):
        session = write_session(self.root)
        os.environ["NOUR_SENTINEL_SESSION"] = str(session)
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            status = cli.main(["cve"])

        self.assertEqual(status, 3)
        self.assertIn("--online", stderr.getvalue())

    def test_invalid_port_is_refused(self):
        session = write_session(self.root)
        os.environ["NOUR_SENTINEL_SESSION"] = str(session)
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            status = cli.main(["tls", "--target", "127.0.0.1", "--port", "0"])

        self.assertEqual(status, 1)
        self.assertIn("port TCP invalide", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
