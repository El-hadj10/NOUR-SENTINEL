import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import AuthorizedTestCase
from security_intelligence.fingerprinting import service_probe


class TestSshProbe(AuthorizedTestCase):
    def test_banner_is_probable(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            connection, _ = server.accept()

            with connection:
                connection.sendall(
                    b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
                )

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        try:
            findings, errors = service_probe.probe_ssh(
                "127.0.0.1", port, timeout=2.0, allowed=("127.0.0.1",)
            )
        finally:
            server.close()
            thread.join(timeout=3)

        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["component"], "OpenSSH")
        self.assertEqual(findings[0]["confidence"], "probable")
        self.assertEqual(findings[0]["port"], port)

    def test_whitelist_is_enforced(self):
        findings, errors = service_probe.probe_ssh(
            "10.0.0.1", 22, allowed=("127.0.0.1",)
        )

        self.assertEqual(findings, [])
        self.assertIn("non autorisée", errors[0])


class TestHttpProbe(AuthorizedTestCase):
    def test_head_response_is_analyzed(self):
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Server", "nginx/1.24.0")
                self.send_header("Content-Type", "text/html")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            findings, errors = service_probe.probe_http(
                "localhost",
                server.server_port,
                timeout=2.0,
                allowed=("localhost",),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

        checks = {finding["check"] for finding in findings}

        self.assertEqual(errors, [])
        self.assertIn("http.header.content-security-policy", checks)
        self.assertIn("http.server_version_disclosure", checks)
        self.assertIn("service.banner", checks)
        self.assertTrue(
            all(finding["confidence"] == "probable" for finding in findings if finding["check"] == "service.banner")
        )


if __name__ == "__main__":
    unittest.main()
