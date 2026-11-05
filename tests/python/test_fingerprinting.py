import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.fingerprinting.services import identify_banner, identify_listener


class TestFingerprinting(unittest.TestCase):

    def test_identifies_openssh_banner(self):
        results = identify_banner("SSH-2.0-OpenSSH_9.7p1 Debian-7\r\n")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["product"], "OpenSSH")
        self.assertEqual(results[0]["version"], "9.7p1")
        self.assertEqual(results[0]["confidence"], "probable")

    def test_identifies_apache_header(self):
        results = identify_banner("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Debian)")

        products = [result["product"] for result in results]

        self.assertIn("Apache httpd", products)
        self.assertEqual(
            next(r for r in results if r["product"] == "Apache httpd")["version"],
            "2.4.58",
        )

    def test_identifies_nginx_header(self):
        results = identify_banner("HTTP/1.1 200 OK\nServer: nginx/1.24.0")

        self.assertEqual(results[0]["product"], "nginx")
        self.assertEqual(results[0]["version"], "1.24.0")

    def test_identifies_local_process_as_confirmed(self):
        identity = identify_listener(
            {
                "process": "sshd",
                "exe": "/usr/sbin/sshd",
                "unit": "ssh.service",
            }
        )

        self.assertEqual(identity["product"], "OpenSSH")
        self.assertEqual(identity["confidence"], "confirmed")
        self.assertIn("local_process:", identity["evidence"])

    def test_unknown_process_returns_none(self):
        self.assertIsNone(identify_listener({"process": "custom-agent"}))

    def test_empty_banner_returns_nothing(self):
        self.assertEqual(identify_banner(""), [])
        self.assertEqual(identify_banner(None), [])


if __name__ == "__main__":
    unittest.main()
