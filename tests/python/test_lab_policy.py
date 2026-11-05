import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import make_config, write_private
from security_intelligence.passwords import policy


def sshd_runner(rc=0):
    def runner(argv, timeout=10):
        return {
            "returncode": rc,
            "stdout": (
                "permitrootlogin yes\n"
                "passwordauthentication yes\n"
                "pubkeyauthentication yes\n"
                "maxauthtries 3\n"
                "x11forwarding no\n"
            ),
            "stderr": "" if rc == 0 else "sshd: erreur",
        }

    return runner


class TestSshdEffective(unittest.TestCase):
    def test_parses_effective_directives(self):
        directives = policy.parse_sshd_effective(
            "permitrootlogin no\npasswordauthentication yes\n"
        )

        self.assertEqual(directives["permitrootlogin"], "no")
        self.assertEqual(directives["passwordauthentication"], "yes")

    def test_read_effective_sshd(self):
        directives, error = policy.read_effective_sshd(runner=sshd_runner())

        self.assertIsNone(error)
        self.assertEqual(directives["permitrootlogin"], "yes")

    def test_read_effective_sshd_failure(self):
        directives, error = policy.read_effective_sshd(runner=sshd_runner(rc=1))

        self.assertEqual(directives, {})
        self.assertIn("sshd -T", error)


class TestPamPolicy(unittest.TestCase):
    def test_parses_pam_options(self):
        parsed = policy.parse_pam_common_password(
            "password requisite pam_pwquality.so retry=3 minlen=8\n"
            "password [success=1 default=ignore] pam_unix.so obscure yescrypt\n"
        )

        self.assertEqual(parsed["pwquality"]["minlen"], "8")
        self.assertEqual(parsed["unix"]["yescrypt"], True)

    def test_weak_pam_options_produce_findings(self):
        findings = policy.audit_pam(
            "password requisite pam_pwquality.so retry=3 minlen=8\n"
            "password [success=1 default=ignore] pam_unix.so obscure md5 remember=3\n"
        )

        checks = {finding["check"] for finding in findings}

        self.assertIn("password_policy.pam_min_length", checks)
        self.assertIn("password_policy.pam_hash_md5", checks)
        self.assertIn("password_policy.pam_history", checks)
        self.assertTrue(all(finding["evidence"] for finding in findings))

    def test_absent_pam_policy_is_to_verify(self):
        findings = policy.audit_pam("# fichier vide\n")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "to_verify")
        self.assertEqual(findings[0]["confidence"], "low")

    def test_collect_uses_effective_ssh_and_files(self):
        with tempfile.TemporaryDirectory() as directory:
            login_defs = Path(directory) / "login.defs"
            pam = Path(directory) / "common-password"

            login_defs.write_text("PASS_MAX_DAYS 99999\n", encoding="utf-8")
            pam.write_text(
                "password requisite pam_pwquality.so minlen=8\n",
                encoding="utf-8",
            )

            with mock.patch.object(policy, "LOGIN_DEFS", str(login_defs)), \
                    mock.patch.object(policy, "PAM_COMMON_PASSWORD", str(pam)):
                findings, metadata, errors = policy.collect(
                    make_config(directory), "localhost", runner=sshd_runner()
                )

            checks = {finding["check"] for finding in findings}

            self.assertTrue(metadata["sshd_effective"])
            self.assertTrue(metadata["login_defs"])
            self.assertTrue(metadata["pam"])
            self.assertIn("ssh_policy.root_login", checks)
            self.assertIn("password_policy.password_expiration", checks)
            self.assertIn("password_policy.pam_min_length", checks)
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
