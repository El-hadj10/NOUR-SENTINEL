import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import AuthorizedTestCase, make_config
from security_intelligence.vulnerabilities import online


OSV_PAYLOAD = {
    "vulns": [
        {
            "id": "CVE-2026-0001",
            "aliases": ["CVE-2026-0001"],
            "summary": "Faille de démonstration",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"ranges": [{"events": [{"fixed": "9.6p1-4"}]}]}],
            "references": [{"url": "https://example.invalid/advisory"}],
        }
    ]
}

NVD_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-0002",
                "descriptions": [{"lang": "en", "value": "Description NVD"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8}}
                    ]
                },
            }
        }
    ]
}

KEV_PAYLOAD = {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
EPSS_PAYLOAD = {"data": [{"cve": "CVE-2026-0001", "epss": "0.97"}]}


class FakeTransport:
    def __init__(self):
        self.calls = []

    def fetch(self, method, url, body=None, headers=None, timeout=10.0):
        self.calls.append((method, url))

        if url == online.OSV_URL:
            return json.dumps(OSV_PAYLOAD).encode("utf-8")

        if url.startswith(online.NVD_URL):
            return json.dumps(NVD_PAYLOAD).encode("utf-8")

        if url == online.KEV_URL:
            return json.dumps(KEV_PAYLOAD).encode("utf-8")

        if url.startswith(online.EPSS_URL):
            return json.dumps(EPSS_PAYLOAD).encode("utf-8")

        raise AssertionError(f"URL inattendue: {url}")


class TestOnlineIntel(AuthorizedTestCase):
    def test_assess_packages_enriches_kev_and_epss(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            transport = FakeTransport()
            client = online.OnlineIntel(
                config, transport=transport, cache_dir=Path(directory) / "cache"
            )
            findings, metadata, errors = client.assess_packages(
                "localhost",
                [{"package": "openssh-server", "version": "9.6p1-3"}],
                limit=1,
            )

            self.assertEqual(len(findings), 1)
            finding = findings[0]

            self.assertEqual(finding["check"], "cve.CVE-2026-0001")
            self.assertEqual(finding["severity"], "high")
            self.assertEqual(finding["status"], "to_verify")
            self.assertTrue(finding["kev"])
            self.assertEqual(finding["epss"], 0.97)
            self.assertIn("to_verify", finding["status"])
            self.assertEqual(metadata["packages_queried"], 1)
            self.assertEqual(metadata["kev_matches"], ["CVE-2026-0001"])
            self.assertEqual(errors, [])

            # OSV + KEV + EPSS, sans NVD.
            self.assertEqual(len(transport.calls), 3)

    def test_cache_avoids_second_network_call(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            transport = FakeTransport()
            cache_dir = Path(directory) / "cache"

            first = online.OnlineIntel(config, transport=transport, cache_dir=cache_dir)
            first.query_osv("openssh-server", "9.6p1-3")

            second_transport = FakeTransport()
            second = online.OnlineIntel(
                config, transport=second_transport, cache_dir=cache_dir
            )
            second.query_osv("openssh-server", "9.6p1-3")

            self.assertEqual(len(transport.calls), 1)
            self.assertEqual(second_transport.calls, [])

    def test_budget_stops_further_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            config["online"]["max_requests"] = 1
            client = online.OnlineIntel(
                config,
                transport=FakeTransport(),
                cache_dir=Path(directory) / "cache",
            )
            findings, metadata, errors = client.assess_packages(
                "localhost",
                [{"package": "openssh-server", "version": "9.6p1-3"}],
                limit=1,
            )

            self.assertEqual(len(findings), 1)
            self.assertEqual(metadata["requests_used"], 1)
            self.assertTrue(any("budget" in error for error in errors))

    def test_nvd_findings_are_explicitly_to_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            client = online.OnlineIntel(
                config,
                transport=FakeTransport(),
                cache_dir=Path(directory) / "cache",
            )
            findings = client.nvd_findings("localhost", "OpenSSH", limit=5)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["cve"], "CVE-2026-0002")
            self.assertEqual(findings[0]["severity"], "critical")
            self.assertEqual(findings[0]["status"], "to_verify")
            self.assertEqual(
                findings[0]["metadata"]["source"], "NVD"
            )

    def test_urllib_transport_refuses_redirect(self):
        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://example.invalid/")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            with self.assertRaises(online.LookupFailed):
                online.UrllibTransport().fetch(
                    "GET", f"http://127.0.0.1:{server.server_port}/", timeout=2
                )
        finally:
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
