import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.vulnerabilities.correlator import (
    compare_versions,
    correlate,
    parse_version,
    version_in_range,
)


class TestVersionComparison(unittest.TestCase):

    def test_parse_version_stops_at_suffix(self):
        self.assertEqual(parse_version("9.7p1"), (9, 7))
        self.assertEqual(parse_version("2.4.58-1ubuntu4"), (2, 4, 58))

    def test_compare_versions(self):
        self.assertEqual(compare_versions("9.6", "9.5"), 1)
        self.assertEqual(compare_versions("9.5p1", "9.5"), 0)
        self.assertEqual(compare_versions("8.9", "9.0"), -1)

    def test_version_in_range(self):
        self.assertTrue(version_in_range("9.7p1", "8.5", "9.7"))
        self.assertFalse(version_in_range("9.8", "8.5", "9.7"))


class TestCorrelation(unittest.TestCase):

    def test_openssh_candidate_is_capped_and_to_verify(self):
        findings = correlate(
            [
                {
                    "asset": "kali",
                    "ip": "0.0.0.0",
                    "port": 22,
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.7p1",
                    "confidence": "probable",
                    "exposure": "lan",
                    "evidence": "banner:SSH-2.0-OpenSSH_9.7p1",
                }
            ]
        )

        self.assertTrue(findings)
        regreSSHion = next(
            finding for finding in findings if finding["cve"] == "CVE-2024-6387"
        )

        self.assertEqual(regreSSHion["status"], "to_verify")
        self.assertEqual(regreSSHion["severity"], "medium")
        self.assertTrue(regreSSHion["severity_capped"])
        self.assertIn("correctifs", regreSSHion["confidence_reason"])

    def test_fixed_version_does_not_match(self):
        findings = correlate(
            [
                {
                    "asset": "kali",
                    "product": "OpenSSH",
                    "version": "9.8",
                    "confidence": "confirmed",
                    "evidence": "local_process:/usr/sbin/sshd",
                }
            ]
        )

        self.assertEqual(findings, [])

    def test_apache_exact_version_with_local_proof_keeps_critical(self):
        findings = correlate(
            [
                {
                    "asset": "kali",
                    "port": 80,
                    "product": "Apache httpd",
                    "version": "2.4.49",
                    "confidence": "confirmed",
                    "exposure": "lan",
                    "evidence": "local_process:/usr/sbin/apache2",
                }
            ]
        )

        target = next(
            finding for finding in findings if finding["cve"] == "CVE-2021-41773"
        )

        self.assertEqual(target["severity"], "critical")
        self.assertFalse(target["severity_capped"])

    def test_missing_version_is_not_speculated(self):
        self.assertEqual(
            correlate([{"product": "OpenSSH", "confidence": "confirmed"}]), []
        )

    def test_unknown_product_is_ignored(self):
        self.assertEqual(
            correlate([{"product": "CustomAgent", "version": "1.0"}]), []
        )


if __name__ == "__main__":
    unittest.main()
