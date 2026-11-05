import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.intrusion.detector import detect, parse_journal_lines

BASE = 1_700_000_000_000_000


def entry(message, offset_seconds=0, identifier="sshd"):
    return {
        "MESSAGE": message,
        "__REALTIME_TIMESTAMP": str(BASE + offset_seconds * 1_000_000),
        "SYSLOG_IDENTIFIER": identifier,
    }


class TestJournalParsing(unittest.TestCase):

    def test_skips_invalid_lines(self):
        lines = [
            '{"MESSAGE": "ok"}',
            "not json",
            "",
            '["array"]',
            '{"MESSAGE": "second"}',
        ]

        entries = parse_journal_lines(lines)

        self.assertEqual(len(entries), 2)


class TestIntrusionDetection(unittest.TestCase):

    def test_failure_burst_is_detected_once(self):
        entries = [
            entry(
                "Failed password for invalid user admin from 10.0.0.66 port 22",
                offset,
            )
            for offset in range(5)
        ]

        findings = detect(entries, host="kali")
        bursts = [
            finding
            for finding in findings
            if finding["check"] == "intrusion.ssh_failure_burst"
        ]

        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["severity"], "medium")
        self.assertIn("10.0.0.66", bursts[0]["evidence"])

    def test_four_failures_are_not_a_burst(self):
        entries = [
            entry("Failed password for root from 10.0.0.66 port 22", offset)
            for offset in range(4)
        ]

        findings = detect(entries)

        self.assertFalse(
            any(f["check"] == "intrusion.ssh_failure_burst" for f in findings)
        )

    def test_success_after_failures_is_prioritized(self):
        entries = [
            entry("Failed password for root from 10.0.0.66 port 22", 0),
            entry("Failed password for root from 10.0.0.66 port 22", 10),
            entry("Accepted publickey for root from 10.0.0.66 port 22 ssh2", 20),
        ]

        findings = detect(entries)
        successes = [
            finding
            for finding in findings
            if finding["check"] == "intrusion.ssh_success_after_failures"
        ]

        self.assertEqual(len(successes), 1)
        self.assertEqual(successes[0]["severity"], "high")

    def test_account_creation_and_firewall_change(self):
        entries = [
            entry("new user: name=backdoor, UID=0", 0, "useradd"),
            entry("ufw: rule added", 5, "ufw"),
        ]

        checks = {finding["check"] for finding in detect(entries)}

        self.assertIn("intrusion.account_change", checks)
        self.assertIn("intrusion.firewall_change", checks)

    def test_sudo_command_and_service_start(self):
        entries = [
            entry("pam_unix(sudo:session): user=root ; COMMAND=/bin/bash", 0, "sudo"),
            entry("Started ssh.service - OpenBSD Secure Shell server.", 1, "systemd"),
        ]

        checks = {finding["check"] for finding in detect(entries)}

        self.assertIn("intrusion.sudo_command", checks)
        self.assertIn("intrusion.service_started", checks)

    def test_quiet_journal_produces_nothing(self):
        self.assertEqual(detect([entry("session opened for user root", 0)]), [])


if __name__ == "__main__":
    unittest.main()
