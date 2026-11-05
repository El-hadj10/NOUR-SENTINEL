import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from security_intelligence.tls import analyzer


OPENSSL_AVAILABLE = shutil.which("openssl") is not None


class TestCertificateParsing(unittest.TestCase):
    def test_openssl_output_is_parsed(self):
        certificate = analyzer.parse_openssl_output(
            "subject=CN = localhost\n"
            "issuer=CN = localhost\n"
            "notBefore=Nov  5 10:00:00 2026 GMT\n"
            "notAfter=Nov  5 10:00:00 2027 GMT\n"
            "X509v3 Subject Alternative Name:\n"
            "    DNS:localhost, IP Address:127.0.0.1\n"
        )

        self.assertEqual(certificate["subject"], "CN = localhost")
        self.assertTrue(certificate["self_signed"])
        self.assertEqual(certificate["san"], ["DNS:localhost", "IP Address:127.0.0.1"])
        self.assertTrue(certificate["not_after"].startswith("2027-11-05T10:00:00"))

    def test_expired_certificate_is_high(self):
        findings = analyzer.stable_analyzer.analyze_certificate(
            {"not_after": "2020-01-01T00:00:00+00:00", "self_signed": True},
            asset="localhost",
            port=443,
            exposure="local",
        )

        checks = {finding["check"] for finding in findings}

        self.assertIn("tls.certificate_expired", checks)
        self.assertIn("tls.self_signed", checks)


class TestTlsAudit(unittest.TestCase):
    def test_target_outside_whitelist_is_refused(self):
        findings, metadata, errors = analyzer.audit(
            "10.0.0.1", 443, allowed=("127.0.0.1",)
        )

        self.assertEqual(findings, [])
        self.assertEqual(metadata, {})
        self.assertIn("non autorisée", errors[0])

    def test_closed_port_reports_negotiation_failure(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        findings, metadata, errors = analyzer.audit(
            "127.0.0.1", port, timeout=0.5, allowed=("127.0.0.1",)
        )

        self.assertTrue(
            any(finding["check"] == "tls.negotiation_failed" for finding in findings)
        )
        self.assertEqual(metadata["protocols"]["tls1.2"]["supported"], False)
        self.assertEqual(errors, [])

    @unittest.skipUnless(OPENSSL_AVAILABLE, "openssl absent")
    def test_local_tls_server_is_audited(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "cert.pem"
            key = Path(directory) / "key.pem"

            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(certificate),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                ],
                check=True,
                capture_output=True,
                timeout=60,
            )

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(certificate), str(key))
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen(8)
            server.settimeout(0.2)
            port = server.getsockname()[1]
            stop = threading.Event()

            def serve():
                while not stop.is_set():
                    try:
                        connection, _ = server.accept()
                    except (socket.timeout, OSError):
                        continue

                    try:
                        with context.wrap_socket(connection, server_side=True) as tls:
                            tls.settimeout(0.2)
                            tls.recv(1)
                    except (OSError, ssl.SSLError):
                        pass

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()

            try:
                findings, metadata, errors = analyzer.audit(
                    "127.0.0.1", port, timeout=2.0, allowed=("127.0.0.1",)
                )
            finally:
                stop.set()
                server.close()
                thread.join(timeout=3)

            checks = {finding["check"] for finding in findings}

            self.assertTrue(
                metadata["protocols"]["tls1.2"]["supported"]
                or metadata["protocols"]["tls1.3"]["supported"]
            )
            self.assertIn("tls.self_signed", checks)
            self.assertIn("tls.certificate_expiring", checks)
            self.assertEqual(errors, [])
            self.assertTrue(metadata["certificate"]["subject"].endswith("localhost"))


if __name__ == "__main__":
    unittest.main()
