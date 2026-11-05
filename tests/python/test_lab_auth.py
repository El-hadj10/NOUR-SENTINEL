import fcntl
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
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
        self.attempts = self.auth.parent / "auth.attempts.json"
        self.lock = self.auth.parent / "auth.lock"
        self.clock = 1_000_000

    def tearDown(self):
        self.directory.cleanup()

    def authenticate(self, secret, **kwargs):
        return auth_gate.authenticate(
            secret=secret,
            path=self.auth,
            require_tty=False,
            now_fn=lambda: self.clock,
            **kwargs,
        )

    def state(self):
        return json.loads(self.attempts.read_text(encoding="utf-8"))

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

    def test_hash_symlink_is_refused(self):
        auth_gate.setup(self.SECRET, path=self.auth)
        target = self.auth.parent / "hash-target"
        os.replace(self.auth, target)
        self.auth.symlink_to(target)

        with self.assertRaises(auth_gate.AuthError):
            auth_gate.verify(self.SECRET, path=self.auth)

    def test_non_interactive_authentication_is_refused(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        with self.assertRaisesRegex(auth_gate.AuthError, "terminal interactif"):
            auth_gate.authenticate(
                self.SECRET,
                path=self.auth,
                require_tty=True,
                input_stream=io.StringIO(),
            )

    def test_successful_authentication_resets_failure_counter(self):
        auth_gate.setup(self.SECRET, path=self.auth)
        auth_gate._write_attempts(
            self.auth,
            {"version": 1, "failures": 2, "locked_until": 0},
        )

        self.assertTrue(self.authenticate(self.SECRET))

        self.assertEqual(self.state()["failures"], 0)
        self.assertEqual(self.state()["locked_until"], 0)

    def test_three_failures_lock_for_thirty_seconds(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillé pendant 30"):
            self.authenticate("mauvais secret", max_attempts=3)

        state = self.state()

        self.assertEqual(state["failures"], 3)
        self.assertEqual(state["locked_until"], self.clock + 30)

        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillée"):
            auth_gate.authenticate(
                path=self.auth,
                require_tty=False,
                getpass_fn=lambda _: self.fail("la saisie ne doit pas être demandée"),
                now_fn=lambda: self.clock,
            )

    def test_lockout_expires_then_progresses(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillé pendant 30"):
            self.authenticate("mauvais secret", max_attempts=3)

        self.clock += 30

        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillé pendant 60"):
            self.authenticate("mauvais secret", max_attempts=1)

        state = self.state()

        self.assertEqual(state["failures"], 4)
        self.assertEqual(state["locked_until"], self.clock + 60)

    def test_lockout_is_capped_at_fifteen_minutes(self):
        auth_gate.setup(self.SECRET, path=self.auth)
        auth_gate._write_attempts(
            self.auth,
            {
                "version": 1,
                "failures": 10,
                "locked_until": self.clock - 1,
            },
        )

        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillé pendant 900"):
            self.authenticate("mauvais secret", max_attempts=1)

        state = self.state()

        self.assertEqual(state["failures"], 11)
        self.assertEqual(state["locked_until"], self.clock + 900)

    def test_attempts_file_is_private_and_persistent(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        with self.assertRaises(auth_gate.AuthError):
            self.authenticate("mauvais secret", max_attempts=1)

        info = os.stat(self.attempts)

        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(self.state()["failures"], 1)

    def test_attempts_symlink_is_refused(self):
        auth_gate.setup(self.SECRET, path=self.auth)
        self.attempts.unlink()

        target = self.auth.parent / "attempts-target.json"
        target.write_text(
            json.dumps({"version": 1, "failures": 0, "locked_until": 0}),
            encoding="utf-8",
        )
        os.chmod(target, 0o600)
        self.attempts.symlink_to(target)

        with self.assertRaises(auth_gate.AuthError):
            self.authenticate(self.SECRET, max_attempts=1)

    def test_lock_file_is_private_and_exclusive(self):
        auth_gate.setup(self.SECRET, path=self.auth)

        with auth_gate._auth_lock(self.auth):
            self.assertEqual(stat.S_IMODE(os.stat(self.lock).st_mode), 0o600)

            descriptor = os.open(self.lock, os.O_RDWR)

            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
