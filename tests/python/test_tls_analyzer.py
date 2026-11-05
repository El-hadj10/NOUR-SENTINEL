import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.tls.analyzer import analyze_certificate, analyze_protocol


class TestTlsAnalyzer(unittest.TestCase):

    def test_weak_protocol_is_high(self):
        findings = analyze_protocol("TLSv1", "ECDHE-RSA-AES256-GCM-SHA384", 256)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["confidence"], "confirmed")

    def test_weak_cipher_is_high(self):
        findings = analyze_protocol("TLSv1.2", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 112)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "tls.cipher")

    def test_strong_protocol_produces_no_finding(self):
        self.assertEqual(
            analyze_protocol("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256), []
        )

    def test_expired_certificate(self):
        findings = analyze_certificate(
            {"not_after": "2020-01-01T00:00:00Z", "self_signed": False}
        )

        self.assertTrue(any(f["check"] == "tls.certificate_expired" for f in findings))
        self.assertTrue(all(f["severity"] == "high" for f in findings))

    def test_expiring_certificate_is_medium(self):
        findings = analyze_certificate({"not_after": "2026-11-20T00:00:00Z"})

        self.assertTrue(
            any(f["check"] == "tls.certificate_expiring" for f in findings)
        )

    def test_weak_key_and_signature(self):
        findings = analyze_certificate(
            {
                "not_after": "2030-01-01T00:00:00Z",
                "key_size": 1024,
                "signature_algorithm": "sha1WithRSAEncryption",
            }
        )

        checks = {finding["check"] for finding in findings}

        self.assertIn("tls.weak_key", checks)
        self.assertIn("tls.weak_signature", checks)

    def test_none_certificate_is_ignored(self):
        self.assertEqual(analyze_certificate(None), [])


if __name__ == "__main__":
    unittest.main()
