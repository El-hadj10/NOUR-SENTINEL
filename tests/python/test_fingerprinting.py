import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.fingerprinting.services import (
    describe_listener,
    identify_banner,
    identify_listener,
)


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

    def test_udp_bound_socket_is_not_a_verified_service(self):
        described = describe_listener(
            {
                "address": "0.0.0.0",
                "port": 5353,
                "family": "ipv4",
                "protocol": "udp",
                "state": "closed",
            }
        )

        self.assertTrue(described["socket_bound"])
        self.assertEqual(described["state"], "bound")
        self.assertFalse(described["process_identified"])
        self.assertFalse(described["application_identified"])
        self.assertFalse(described["application_verified"])

    def test_identified_application_is_still_not_response_verified(self):
        described = describe_listener(
            {
                "address": "127.0.0.1",
                "port": 22,
                "protocol": "tcp",
                "state": "listen",
                "pid": 42,
                "process": "sshd",
            }
        )

        self.assertTrue(described["socket_bound"])
        self.assertTrue(described["process_identified"])
        self.assertTrue(described["application_identified"])
        self.assertEqual(described["application_service"], "OpenSSH")
        self.assertFalse(described["application_verified"])


if __name__ == "__main__":
    unittest.main()
