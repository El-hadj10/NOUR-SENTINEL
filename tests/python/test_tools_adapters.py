import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from intelligence.tools import adapters
from lab_helpers import AuthorizedTestCase


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.7p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

TRIVY_JSON = {
    "Results": [
        {
            "Target": "nginx:1.24",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.1",
                    "FixedVersion": "3.0.2",
                    "Severity": "HIGH",
                    "Title": "Test vulnerability",
                    "PrimaryURL": "https://example.invalid/CVE-2024-0001",
                }
            ],
        }
    ]
}


class TestCommands(unittest.TestCase):

    def test_nmap_command_is_argument_list(self):
        command = adapters.build_nmap_command("127.0.0.1", [22, 80])

        self.assertEqual(command[0], "nmap")
        self.assertIn("-sV", command)
        self.assertEqual(command[-1], "127.0.0.1")
        self.assertEqual(command[-2], "22,80")

    def test_testssl_command_contains_output_path(self):
        command = adapters.build_testssl_command("127.0.0.1", 443, "/tmp/out.json")

        self.assertEqual(command[0], "testssl.sh")
        self.assertIn("/tmp/out.json", command)
        self.assertEqual(command[-1], "127.0.0.1:443")

    def test_trivy_commands(self):
        self.assertEqual(
            adapters.build_trivy_image_command("nginx:1.24")[:3],
            ["trivy", "image", "--quiet"],
        )
        self.assertIn("vuln,config", adapters.build_trivy_fs_command("/tmp"))


class TestParsers(AuthorizedTestCase):

    def test_nmap_keeps_only_open_services(self):
        services = adapters.parse_nmap_xml(NMAP_XML)

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["port"], 22)
        self.assertEqual(services[0]["product"], "OpenSSH")

    def test_nmap_findings_are_informational(self):
        findings = adapters.findings_from_nmap(
            adapters.parse_nmap_xml(NMAP_XML), asset="kali"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "info")
        self.assertEqual(findings[0]["confidence"], "corroborated")

    def test_nmap_invalid_xml_is_empty(self):
        self.assertEqual(adapters.parse_nmap_xml("<not-xml"), [])

    def test_testssl_severity_mapping_and_ok_skipped(self):
        document = [
            {"id": "cert_expired", "severity": "CRITICAL", "finding": "expired"},
            {"id": "tls_ok", "severity": "OK", "finding": "fine"},
            {"id": "hsts", "severity": "WARN", "finding": "missing"},
        ]

        findings = adapters.findings_from_testssl(document, asset="kali", port=443)

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertEqual(findings[0]["check"], "tls.testssl.cert_expired")

    def test_testssl_accepts_json_string(self):
        findings = adapters.findings_from_testssl(
            json.dumps([{"id": "cipher", "severity": "HIGH", "finding": "weak"}])
        )

        self.assertEqual(findings[0]["severity"], "high")

    def test_trivy_findings(self):
        findings = adapters.findings_from_trivy(
            TRIVY_JSON, asset="kali", target="nginx:1.24"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cve"], "CVE-2024-0001")
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["confidence"], "confirmed")
        self.assertIn("3.0.2", findings[0]["recommendation"])

    def test_missing_binary_is_reported(self):
        result = adapters.run_tool(["nour-sentinel-does-not-exist"], timeout=5)

        self.assertEqual(result["returncode"], -1)
        self.assertNotEqual(result["stderr"], "")


if __name__ == "__main__":
    unittest.main()
