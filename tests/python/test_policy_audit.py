import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from intelligence.passwords.policy_audit import (
    audit_login_defs,
    audit_ssh_policy,
    audit_sudoers,
    parse_sshd_config,
)


class TestSshPolicy(unittest.TestCase):

    def test_parser_keeps_last_value_and_ignores_match_blocks(self):
        directives = parse_sshd_config(
            """
            # commentaire
            PasswordAuthentication yes
            PermitRootLogin no
            Match User backup
                PermitRootLogin yes
            Match all
            MaxAuthTries 3
            """
        )

        self.assertEqual(directives["passwordauthentication"], "yes")
        self.assertEqual(directives["permitrootlogin"], "no")
        self.assertEqual(directives["maxauthtries"], "3")

    def test_root_login_is_high(self):
        findings = audit_ssh_policy({"permitrootlogin": "yes"})

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("PermitRootLogin yes", findings[0]["evidence"])

    def test_empty_passwords_is_critical_with_evidence(self):
        findings = audit_ssh_policy({"permitemptypasswords": "yes"})

        self.assertEqual(findings[0]["severity"], "critical")
        self.assertFalse(findings[0]["severity_capped"])

    def test_password_auth_is_medium(self):
        findings = audit_ssh_policy({"passwordauthentication": "yes"})

        self.assertEqual(findings[0]["severity"], "medium")
        self.assertEqual(findings[0]["check"], "ssh_policy.password_auth")

    def test_disabled_pubkey_is_high(self):
        findings = audit_ssh_policy({"pubkeyauthentication": "no"})

        self.assertEqual(findings[0]["severity"], "high")

    def test_high_max_auth_tries_is_low(self):
        findings = audit_ssh_policy({"maxauthtries": "10"})

        self.assertEqual(findings[0]["severity"], "low")


class TestLoginDefs(unittest.TestCase):

    def test_weak_password_policy(self):
        findings = audit_login_defs(
            """
            PASS_MAX_DAYS 99999
            PASS_MIN_LEN 6
            PASS_WARN_AGE 3
            ENCRYPT_METHOD MD5
            """
        )

        checks = {finding["check"] for finding in findings}

        self.assertIn("password_policy.password_expiration", checks)
        self.assertIn("password_policy.password_length", checks)
        self.assertIn("password_policy.password_warning", checks)
        self.assertIn("password_policy.password_hash", checks)

    def test_strong_policy_produces_nothing(self):
        findings = audit_login_defs(
            """
            PASS_MAX_DAYS 90
            PASS_MIN_LEN 14
            PASS_WARN_AGE 7
            ENCRYPT_METHOD YESCRYPT
            """
        )

        self.assertEqual(findings, [])


class TestSudoers(unittest.TestCase):

    def test_nopasswd_rule_is_reported(self):
        findings = audit_sudoers("deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("NOPASSWD", findings[0]["evidence"])

    def test_comment_is_ignored(self):
        self.assertEqual(audit_sudoers("# NOPASSWD: test\n"), [])


if __name__ == "__main__":
    unittest.main()
