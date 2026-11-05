import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from security_intelligence import auth_gate

ARGON2_AVAILABLE = importlib.util.find_spec("argon2") is not None


@unittest.skipUnless(
    ARGON2_AVAILABLE, "argon2-cffi absent; exécutez ./lancer-nour-sentinel.sh --setup-deps"
)
class TestAuthGate(unittest.TestCase):
    SECRET = "phrase secrete de laboratoire 2026"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.auth = self.root / "nour-sentinel" / "auth.phc"
        self.session = self.root / "nour-sentinel" / "session.json"

    def tearDown(self):
        self.directory.cleanup()

    def test_setup_creates_argon2id_phc_in_private_file(self):
        path = auth_gate.setup(self.SECRET, path=self.auth)

        content = Path(path).read_text(encoding="utf-8")

        self.assertTrue(content.startswith("$argon2id$"))
        self.assertNotIn(self.SECRET, content)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(Path(path).parent).st_mode), 0o700)

    def test_verify_accepts_and_rejects(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        self.assertTrue(auth_gate.verify(self.SECRET, path=self.auth))
        self.assertFalse(auth_gate.verify("mauvais secret", path=self.auth))

    def test_short_secret_is_rejected(self):
        with self.assertRaises(auth_gate.AuthError):
            auth_gate.setup("court", path=self.auth)

    def test_overwrite_requires_explicit_force(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        with self.assertRaises(auth_gate.AuthError):
            auth_gate.setup("une autre phrase secrete", path=self.auth)

    def test_change_requires_previous_secret(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        with self.assertRaises(auth_gate.AuthError):
            auth_gate.change("mauvais", "nouvelle phrase secrete 2026", path=self.auth)

        auth_gate.change(self.SECRET, "nouvelle phrase secrete 2026", path=self.auth)

        self.assertTrue(
            auth_gate.verify("nouvelle phrase secrete 2026", path=self.auth)
        )
        self.assertFalse(auth_gate.verify(self.SECRET, path=self.auth))

    def test_loose_permissions_are_refused(self):
        auth_gate.setup(self.SECRET, path=self.auth)
        os.chmod(self.auth, 0o644)

        with self.assertRaises(auth_gate.AuthError):
            auth_gate.verify(self.SECRET, path=self.auth)

    def test_login_non_interactive_with_three_attempts(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        self.assertTrue(
            auth_gate.login(
                path=self.auth,
                require_tty=False,
                getpass_fn=lambda _: self.SECRET,
            )
        )

        with self.assertRaises(auth_gate.AuthError):
            auth_gate.login(
                path=self.auth,
                require_tty=False,
                getpass_fn=lambda _: "incorrect",
                sleep_fn=lambda _: None,
            )

    def test_session_expires_and_is_private(self):
        path = auth_gate.create_session(self.session, ttl=60)

        self.assertTrue(auth_gate.session_valid(path))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertFalse(auth_gate.session_valid(path, now=int(time.time()) + 61))

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertGreater(payload["expires_at"], payload["created_at"])

    def test_session_symlink_is_refused(self):
        path = auth_gate.create_session(self.session, ttl=60)
        link = self.root / "nour-sentinel" / "link.json"
        link.symlink_to(path)

        self.assertFalse(auth_gate.session_valid(link))

    def test_session_permissions_are_refused(self):
        path = auth_gate.create_session(self.session, ttl=60)
        os.chmod(path, 0o644)

        self.assertFalse(auth_gate.session_valid(path))


if __name__ == "__main__":
    unittest.main()
