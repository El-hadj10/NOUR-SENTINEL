
import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "python-brain")
)

from analyzer import analyze_events
from intelligence.engine import (
    CAPABILITIES,
    _journal_findings,
    analyze_inventory,
    capability_status,
    classify_exposure,
)
import authz


class TestAnalyzer(unittest.TestCase):

    def test_analysis_summary(self):

        data = {
            "source": "test-engine",

            "devices": [
                {"ip": "127.0.0.1"}
            ],

            "events": [
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 443,
                    "state": "open"
                },
                {
                    "type": "port_observed",
                    "ip": "127.0.0.1",
                    "port": 22,
                    "state": "closed"
                }
            ],

            "analysis_config": {
                "sensitive_ports": [3389],
                "known_services": {
                    "443": "HTTPS"
                }
            }
        }

        with mock.patch.object(authz, "require"):
            result = analyze_events(data)

        self.assertEqual(
            result["network"]["ports_observed"],
            2
        )

        self.assertEqual(
            result["network"]["open_ports"],
            1
        )

        self.assertEqual(
            result["network"]["neighbors_discovered"],
            1
        )

        self.assertEqual(
            result["findings_count"],
            1
        )

        self.assertEqual(
            result["findings"][0]["service"],
            "HTTPS"
        )

        self.assertEqual(
            result["status"],
            "analysis_completed"
        )

        self.assertEqual(
            set(result["capability_status"]), set(CAPABILITIES)
        )


class TestExposureClassification(unittest.TestCase):

    def test_ipv4_and_ipv6_wildcards_are_lan(self):
        for address in (
            "0.0.0.0",
            "::",
            "[::]",
            "0:0:0:0:0:0:0:0",
            "::0",
            "::ffff:0.0.0.0",
        ):
            with self.subTest(address=address):
                self.assertEqual(classify_exposure(address), "lan")

    def test_loopback_forms_are_local(self):
        for address in (
            "127.0.0.1",
            "::1",
            "[::1]",
            "0:0:0:0:0:0:0:1",
            "::ffff:127.0.0.1",
        ):
            with self.subTest(address=address):
                self.assertEqual(classify_exposure(address), "local")

    def test_expanded_wildcard_triggers_exposure_finding(self):
        findings, _ = analyze_inventory(
            {
                "listeners": [
                    {"address": "0:0:0:0:0:0:0:0", "port": 3389}
                ]
            },
            "lab-host",
        )

        self.assertIn(
            "exposure.wildcard.3389",
            {finding["check"] for finding in findings},
        )


class TestCapabilityStatus(unittest.TestCase):

    def test_default_configuration_reports_real_statuses(self):
        status = capability_status(
            {
                "active_probing": False,
                "ssh_policy_audit": True,
                "journal_audit": False,
            },
            {"listeners": [{"address": "0.0.0.0", "port": 22}]},
            ["0.0.0.0"],
            [],
            [],
        )

        self.assertEqual(status["service_fingerprinting"]["status"], "completed")
        self.assertEqual(status["password_policy_audit"]["status"], "completed")
        self.assertEqual(status["tls_audit"]["status"], "disabled")
        self.assertEqual(
            status["application_security_analysis"]["status"], "disabled"
        )
        self.assertEqual(status["host_intrusion_detection"]["status"], "disabled")
        self.assertEqual(
            status["vulnerability_intelligence"]["status"], "no_data"
        )

    def test_active_probes_started_until_proof_of_completion(self):
        status = capability_status(
            {
                "active_probing": True,
                "tls_probe": True,
                "http_probe": True,
                "ssh_policy_audit": False,
            },
            {
                "listeners": [
                    {"address": "127.0.0.1", "port": 443},
                    {"address": "127.0.0.1", "port": 8080},
                ]
            },
            ["127.0.0.1"],
            [{"product": "nginx"}],
            [],
        )

        # Une sonde lancée n'est pas une collecte terminée.
        self.assertEqual(status["tls_audit"]["status"], "started")
        self.assertEqual(
            status["application_security_analysis"]["status"], "started"
        )
        self.assertEqual(
            status["vulnerability_intelligence"]["status"], "completed"
        )
        self.assertEqual(status["password_policy_audit"]["status"], "disabled")

    def test_completed_requires_a_real_result(self):
        status = capability_status(
            {
                "active_probing": True,
                "tls_probe": True,
                "http_probe": True,
                "ssh_policy_audit": False,
            },
            {
                "listeners": [
                    {"address": "127.0.0.1", "port": 443},
                    {"address": "127.0.0.1", "port": 8080},
                ]
            },
            ["127.0.0.1"],
            [],
            [],
            findings=[
                {"check": "tls.protocol.obsolete"},
                {"check": "http.header.missing"},
            ],
        )

        self.assertEqual(status["tls_audit"]["status"], "completed")
        self.assertEqual(
            status["application_security_analysis"]["status"], "completed"
        )

    def test_failed_and_blocked_missing_permission_are_distinct(self):
        failed = capability_status(
            {"ssh_policy_audit": True, "journal_audit": True},
            {"listeners": []},
            [],
            [],
            [],
            errors=["sshd -T: command failed", "journalctl: failed"],
        )

        self.assertEqual(failed["password_policy_audit"]["status"], "failed")
        self.assertEqual(failed["host_intrusion_detection"]["status"], "failed")

        blocked = capability_status(
            {"ssh_policy_audit": True, "journal_audit": True},
            {"listeners": []},
            [],
            [],
            [],
            errors=[
                "sshd -T: Permission denied",
                "journalctl: Operation not permitted",
            ],
        )

        self.assertEqual(
            blocked["password_policy_audit"]["status"],
            "blocked_missing_permission",
        )
        self.assertEqual(
            blocked["host_intrusion_detection"]["status"],
            "blocked_missing_permission",
        )

    def test_journal_completed_requires_exploitable_entries(self):
        status = capability_status(
            {"journal_audit": True},
            {"listeners": []},
            [],
            [],
            [],
            journal_entries=3,
        )

        self.assertEqual(
            status["host_intrusion_detection"]["status"], "completed"
        )
        self.assertIn("3", status["host_intrusion_detection"]["reason"])

    def test_journal_without_entry_count_is_not_a_success(self):
        # Un appelant qui ne transmet pas le nombre d'entrées ne peut pas
        # prétendre que la lecture a produit un résultat.
        status = capability_status(
            {"journal_audit": True}, {"listeners": []}, [], [], []
        )

        self.assertEqual(
            status["host_intrusion_detection"]["status"], "started"
        )

    def test_journal_zero_entries_is_no_data_not_completed(self):
        status = capability_status(
            {"journal_audit": True},
            {"listeners": []},
            [],
            [],
            [],
            journal_entries=0,
        )

        self.assertEqual(
            status["host_intrusion_detection"]["status"], "no_data"
        )

    def test_journal_errors_win_over_zero_entries(self):
        failed = capability_status(
            {"journal_audit": True},
            {"listeners": []},
            [],
            [],
            [],
            errors=["journalctl: command failed"],
            journal_entries=0,
        )

        self.assertEqual(
            failed["host_intrusion_detection"]["status"], "failed"
        )

        blocked = capability_status(
            {"journal_audit": True},
            {"listeners": []},
            [],
            [],
            [],
            errors=["journalctl: Permission denied"],
            journal_entries=0,
        )

        self.assertEqual(
            blocked["host_intrusion_detection"]["status"],
            "blocked_missing_permission",
        )

    def test_journal_collection_reports_entry_count(self):
        populated = mock.Mock(
            returncode=0,
            stdout='{"MESSAGE": "session opened"}\n{"MESSAGE": "Accepted password"}\n',
            stderr="",
        )

        with mock.patch.object(authz, "require"), mock.patch(
            "intelligence.engine.subprocess.run", return_value=populated
        ), mock.patch("intelligence.engine.intrusion.detect", return_value=[]):
            findings, errors, entries = _journal_findings(
                {"journal_audit": True}, "lab-host"
            )

        self.assertEqual(findings, [])
        self.assertEqual(errors, [])
        self.assertEqual(entries, 2)

        empty = mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(authz, "require"), mock.patch(
            "intelligence.engine.subprocess.run", return_value=empty
        ), mock.patch("intelligence.engine.intrusion.detect", return_value=[]):
            findings, errors, entries = _journal_findings(
                {"journal_audit": True}, "lab-host"
            )

        self.assertEqual((findings, errors, entries), ([], [], 0))

    def test_all_statuses_belong_to_the_documented_set(self):
        status = capability_status(
            {}, {"listeners": []}, [], [], []
        )
        allowed = {
            "started",
            "completed",
            "failed",
            "disabled",
            "no_data",
            "blocked_missing_permission",
        }

        self.assertEqual(set(status), set(CAPABILITIES))
        self.assertTrue(
            all(item["status"] in allowed for item in status.values())
        )


if __name__ == "__main__":
    unittest.main()
