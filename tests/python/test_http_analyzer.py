import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.applications.http_analyzer import (
    analyze_cookies,
    analyze_headers,
    analyze_methods,
    analyze_response,
)


class TestHttpHeaders(unittest.TestCase):

    def test_all_security_headers_missing(self):
        findings = analyze_headers({})

        self.assertEqual(len(findings), 5)
        self.assertTrue(
            any(finding["check"] == "http.header.content-security-policy" for finding in findings)
        )

    def test_present_headers_are_not_reported(self):
        headers = {
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
        }

        self.assertEqual(analyze_headers(headers), [])

    def test_server_version_disclosure(self):
        findings = analyze_headers({"server": "Apache/2.4.58 (Debian)"})

        disclosure = [
            finding
            for finding in findings
            if finding["check"] == "http.server_version_disclosure"
        ]

        self.assertEqual(len(disclosure), 1)
        self.assertEqual(disclosure[0]["severity"], "info")

    def test_cors_wildcard_with_credentials_is_high(self):
        findings = analyze_headers(
            {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }
        )

        wildcard = [
            finding
            for finding in findings
            if finding["check"] == "http.cors_wildcard_credentials"
        ]

        self.assertEqual(len(wildcard), 1)
        self.assertEqual(wildcard[0]["severity"], "high")


class TestHttpCookies(unittest.TestCase):

    def test_cookie_without_security_attributes(self):
        findings = analyze_cookies("session=abc123; Path=/")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_secure_cookie_is_ignored(self):
        findings = analyze_cookies(
            "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
        )

        self.assertEqual(findings, [])


class TestHttpMethods(unittest.TestCase):

    def test_trace_is_medium(self):
        findings = analyze_methods(["GET", "TRACE"])

        self.assertEqual(findings[0]["check"], "http.method.trace")
        self.assertEqual(findings[0]["severity"], "medium")

    def test_safe_methods_are_ignored(self):
        self.assertEqual(analyze_methods(["GET", "HEAD", "POST"]), [])


class TestComposite(unittest.TestCase):

    def test_analyze_response_combines_sources(self):
        findings = analyze_response(
            {
                "status": 200,
                "headers": {"server": "nginx/1.24.0"},
                "set_cookie": "id=1; Path=/",
                "methods": ["GET", "PUT"],
            }
        )

        checks = {finding["check"] for finding in findings}

        self.assertIn("http.server_version_disclosure", checks)
        self.assertIn("http.cookie.id", checks)
        self.assertIn("http.method.write", checks)


if __name__ == "__main__":
    unittest.main()
