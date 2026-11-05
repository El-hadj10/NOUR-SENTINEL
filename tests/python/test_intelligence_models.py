import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.models import (
    build_finding_id,
    cap_severity,
    make_finding,
    normalize_confidence,
    normalize_severity,
)


class TestFindingModel(unittest.TestCase):

    def test_critical_without_evidence_is_capped(self):
        severity, capped = cap_severity("critical", "confirmed", "")

        self.assertEqual(severity, "medium")
        self.assertTrue(capped)

    def test_critical_with_weak_confidence_is_capped(self):
        severity, capped = cap_severity(
            "critical", "probable", "banner:SSH-2.0-OpenSSH_9.7"
        )

        self.assertEqual(severity, "medium")
        self.assertTrue(capped)

    def test_critical_with_evidence_and_confirmation_is_kept(self):
        severity, capped = cap_severity(
            "critical", "confirmed", "sshd_config:PermitEmptyPasswords yes"
        )

        self.assertEqual(severity, "critical")
        self.assertFalse(capped)

    def test_severity_aliases_are_normalized(self):
        self.assertEqual(normalize_severity("warning"), "medium")
        self.assertEqual(normalize_severity("CRITICAL"), "critical")
        self.assertEqual(normalize_severity("nonsense"), "info")

    def test_confidence_aliases_are_normalized(self):
        self.assertEqual(normalize_confidence("high"), "corroborated")
        self.assertEqual(normalize_confidence("low"), "low")
        self.assertEqual(normalize_confidence("bogus"), "unknown")

    def test_finding_id_is_stable_and_distinct(self):
        first = build_finding_id("kali", "ssh_policy.root_login", "OpenSSH")
        second = build_finding_id("kali", "ssh_policy.root_login", "OpenSSH")
        other = build_finding_id("kali", "ssh_policy.password_auth", "OpenSSH")

        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(first.startswith("f-"))

    def test_make_finding_flags_capped_severity(self):
        finding = make_finding(
            asset="kali",
            check="cve.CVE-2024-6387",
            component="OpenSSH",
            observation="Version candidate",
            evidence="version=9.7",
            confidence="probable",
            severity="critical",
            exposure="lan",
            recommendation="Vérifier",
        )

        self.assertEqual(finding["severity"], "medium")
        self.assertTrue(finding["severity_capped"])
        self.assertEqual(finding["status"], "open")
        self.assertIn("finding_id", finding)

    def test_invalid_exposure_falls_back_to_unknown(self):
        finding = make_finding(
            asset="kali",
            check="test",
            component="x",
            exposure="internet",
        )

        self.assertEqual(finding["exposure"], "unknown")


if __name__ == "__main__":
    unittest.main()
