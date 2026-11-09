import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import AuthorizedTestCase
from security_intelligence import VERSION
from security_intelligence import reports
from security_intelligence.store import IntelStore


def sample_report():
    return {
        "version": VERSION,
        "mode": "inventory",
        "generated_at": "2026-11-05T12:00:00+00:00",
        "risk_summary": {"total": 1, "by_severity": {"info": 1}},
        "findings": [
            {
                "finding_id": "f-abc123",
                "asset_id": "localhost",
                "check": "service.banner",
                "severity": "info",
                "confidence": "probable",
                "priority": "P4",
                "status": "open",
                "cve": None,
            }
        ],
    }


class TestIntelStore(AuthorizedTestCase):
    def test_store_roundtrip_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history" / "intel.db"
            store = IntelStore(path)

            run_id = store.save_run(sample_report())
            self.assertGreater(run_id, 0)
            self.assertEqual(store.count_runs(), 1)

            store.attach_report(run_id, "/tmp/report.json")
            row = store.connection.execute(
                "SELECT report_path FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            self.assertEqual(row[0], "/tmp/report.json")

            stored = store.connection.execute(
                "SELECT check_name, severity FROM findings"
            ).fetchall()
            self.assertEqual(stored, [("service.banner", "info")])
            store.close()

            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(path.parent).st_mode), 0o700)

            reopened = IntelStore(path)
            self.assertEqual(reopened.count_runs(), 1)
            reopened.close()

    def test_foreign_key_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IntelStore(Path(directory) / "intel.db")

            with self.assertRaises(Exception):
                with store.connection:
                    store.connection.execute(
                        "INSERT INTO findings (run_id, check_name, severity, confidence, status) "
                        "VALUES (9999, 'x', 'info', 'low', 'open')"
                    )

            store.close()


class TestReports(AuthorizedTestCase):
    def test_report_is_private_and_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = reports.write_report(sample_report(), Path(directory) / "reports")

            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE(os.stat(path.parent).st_mode), 0o700
            )
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["mode"], "inventory")

    def test_same_second_reports_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "reports"
            first = reports.write_report(sample_report(), target)
            second = reports.write_report(sample_report(), target)

            self.assertNotEqual(first, second)
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())


if __name__ == "__main__":
    unittest.main()
