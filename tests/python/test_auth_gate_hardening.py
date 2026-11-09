"""P0.4 — preuves du compteur d'échecs persistant et de son verrouillage.

Ces tests exercent plusieurs processus réels, des états de limitation
malformés ou altérés, des permissions incorrectes, puis vérifient que
``verify()`` respecte toujours le verrouillage et que la politique reste
cohérente après fermeture et redémarrage.
"""

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_helpers import write_private
from security_intelligence import auth_gate

ARGON2_AVAILABLE = importlib.util.find_spec("argon2") is not None
BRAIN = str(PROJECT_ROOT / "python-brain")

AUTHENTICATE_CHILD = f"""
import sys

sys.path.insert(0, {BRAIN!r})

from security_intelligence import auth_gate

path, secret = sys.argv[1], sys.argv[2]

try:
    auth_gate.authenticate(
        secret=secret,
        path=path,
        require_tty=False,
        max_attempts=1,
    )
except auth_gate.AuthError as error:
    print("DENIED:" + str(error))
    sys.exit(0)

print("GRANTED")
"""

VERIFY_CHILD = f"""
import sys

sys.path.insert(0, {BRAIN!r})

from security_intelligence import auth_gate

print("VERIFIED", auth_gate.verify(sys.argv[1], path=sys.argv[2]))
"""

HOLD_LOCK_CHILD = f"""
import sys

sys.path.insert(0, {BRAIN!r})

from security_intelligence import auth_gate

with auth_gate._auth_lock(sys.argv[1]):
    print("HELD", flush=True)
    sys.stdin.readline()
"""


@unittest.skipUnless(
    ARGON2_AVAILABLE,
    "argon2-cffi absent; exécutez ./lancer-nour-sentinel.sh --setup-deps",
)
class TestAttemptCounterHardening(unittest.TestCase):
    SECRET = "phrase secrete de laboratoire 2026"
    WRONG = "mauvais secret de laboratoire 2026"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.auth = self.root / "nour-sentinel" / "auth.phc"
        self.attempts = self.auth.parent / "auth.attempts.json"
        self.lock = self.auth.parent / "auth.lock"
        auth_gate.setup(self.SECRET, path=self.auth)

    def tearDown(self):
        self.directory.cleanup()

    def state(self):
        return json.loads(self.attempts.read_text(encoding="utf-8"))

    def run_child(self, code, *arguments, timeout=120):
        return subprocess.run(
            [sys.executable, "-c", code, *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def authenticate(self, secret, **kwargs):
        return auth_gate.authenticate(
            secret=secret,
            path=self.auth,
            require_tty=False,
            **kwargs,
        )

    def test_verify_respects_lockout_and_does_not_touch_counter(self):
        auth_gate._write_attempts(
            self.auth,
            {
                "version": 1,
                "failures": 3,
                "locked_until": int(time.time()) + 120,
            },
        )

        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillée"):
            auth_gate.verify(self.SECRET, path=self.auth)

        state = self.state()

        self.assertEqual(state["failures"], 3)
        self.assertGreater(state["locked_until"], int(time.time()))

    def test_verify_counts_failures_like_authenticate(self):
        self.assertFalse(auth_gate.verify(self.WRONG, path=self.auth))

        state = self.state()

        self.assertEqual(state["failures"], 1)
        self.assertEqual(state["locked_until"], 0)

    def test_verify_locks_after_three_failures(self):
        for _ in range(2):
            self.assertFalse(auth_gate.verify(self.WRONG, path=self.auth))

        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillé pendant 30"):
            auth_gate.verify(self.WRONG, path=self.auth)

        self.assertEqual(self.state()["failures"], 3)

        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillée"):
            auth_gate.verify(self.SECRET, path=self.auth)

    def test_verify_success_resets_failure_counter(self):
        auth_gate._write_attempts(
            self.auth,
            {"version": 1, "failures": 2, "locked_until": 0},
        )

        self.assertTrue(auth_gate.verify(self.SECRET, path=self.auth))

        self.assertEqual(self.state()["failures"], 0)

    def test_verify_refuses_malformed_state(self):
        write_private(self.attempts, "{pas du json")

        with self.assertRaises(auth_gate.AuthError):
            auth_gate.verify(self.SECRET, path=self.auth)

    def test_malformed_attempts_states_are_refused(self):
        now = int(time.time())
        payloads = {
            "not-json": "pas du json",
            "array": "[]",
            "null": "null",
            "wrong-version": json.dumps(
                {"version": 2, "failures": 0, "locked_until": 0}
            ),
            "boolean-failures": json.dumps(
                {"version": 1, "failures": True, "locked_until": 0}
            ),
            "string-failures": json.dumps(
                {"version": 1, "failures": "3", "locked_until": 0}
            ),
            "negative-failures": json.dumps(
                {"version": 1, "failures": -1, "locked_until": 0}
            ),
            "string-locked": json.dumps(
                {"version": 1, "failures": 0, "locked_until": "demain"}
            ),
            "negative-locked": json.dumps(
                {"version": 1, "failures": 0, "locked_until": -1}
            ),
            "missing-locked": json.dumps({"version": 1, "failures": 0}),
            "absurd-locked": json.dumps(
                {
                    "version": 1,
                    "failures": 3,
                    "locked_until": now + 10**6,
                }
            ),
            "oversized": json.dumps(
                {"version": 1, "failures": 0, "locked_until": 0}
            )
            + " " * 5000,
            "truncated": '{"version": 1, "failures": 2',
        }

        for name, payload in payloads.items():
            with self.subTest(state=name):
                write_private(self.attempts, payload)

                with self.assertRaises(auth_gate.AuthError):
                    self.authenticate(self.SECRET)

    def test_attempts_file_permissions_must_be_0600(self):
        for mode in (0o644, 0o400, 0o640):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.attempts, mode)

                with self.assertRaisesRegex(
                    auth_gate.AuthError, "permissions trop larges"
                ):
                    self.authenticate(self.SECRET)

    def test_attempts_directory_is_refused(self):
        self.attempts.unlink()
        self.attempts.mkdir(mode=0o700)

        with self.assertRaises(auth_gate.AuthError):
            self.authenticate(self.SECRET)

    def test_lock_file_permissions_must_be_0600(self):
        os.chmod(self.lock, 0o644)

        with self.assertRaisesRegex(
            auth_gate.AuthError, "permissions trop larges"
        ):
            self.authenticate(self.SECRET)

    def test_lock_symlink_is_refused(self):
        target = self.auth.parent / "lock-target"
        write_private(target, "")
        self.lock.unlink()
        self.lock.symlink_to(target)

        with self.assertRaises(auth_gate.AuthError):
            self.authenticate(self.SECRET)

    def test_concurrent_failures_are_counted_exactly_once(self):
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", AUTHENTICATE_CHILD, str(self.auth), self.WRONG],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(6)
        ]
        outputs = [process.communicate(timeout=120) for process in processes]

        for process, (stdout, stderr) in zip(processes, outputs):
            with self.subTest(pid=process.pid):
                self.assertEqual(process.returncode, 0, msg=stderr)
                self.assertIn("DENIED", stdout)

        state = self.state()

        # Trois échecs déclenchent le verrou : les processus suivants sont
        # refusés avant vérification et n'incrémentent donc plus le compteur.
        self.assertEqual(state["failures"], 3)
        self.assertGreater(state["locked_until"], int(time.time()) - 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.attempts).st_mode), 0o600)

    def test_concurrent_successes_keep_counter_integral(self):
        processes = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    AUTHENTICATE_CHILD,
                    str(self.auth),
                    self.SECRET,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(4)
        ]
        outputs = [process.communicate(timeout=120) for process in processes]

        for process, (stdout, stderr) in zip(processes, outputs):
            with self.subTest(pid=process.pid):
                self.assertEqual(process.returncode, 0, msg=stderr)
                self.assertIn("GRANTED", stdout)

        state = self.state()

        self.assertEqual(state["failures"], 0)
        self.assertEqual(state["locked_until"], 0)

    def test_lockout_policy_survives_process_restart(self):
        with self.assertRaisesRegex(auth_gate.AuthError, "verrouillé pendant 30"):
            self.authenticate(self.WRONG, max_attempts=3)

        locked = self.state()

        child = self.run_child(
            AUTHENTICATE_CHILD, str(self.auth), self.SECRET
        )

        self.assertEqual(child.returncode, 0, msg=child.stderr)
        self.assertIn("DENIED", child.stdout)
        self.assertIn("verrouillée", child.stdout)
        self.assertEqual(self.state()["failures"], locked["failures"])
        self.assertEqual(
            self.state()["locked_until"], locked["locked_until"]
        )

    def test_expired_lockout_after_restart_is_coherent(self):
        auth_gate._write_attempts(
            self.auth,
            {
                "version": 1,
                "failures": 3,
                "locked_until": int(time.time()) - 1,
            },
        )

        child = self.run_child(
            AUTHENTICATE_CHILD, str(self.auth), self.SECRET
        )

        self.assertEqual(child.returncode, 0, msg=child.stderr)
        self.assertIn("GRANTED", child.stdout)

        state = self.state()

        self.assertEqual(state["failures"], 0)
        self.assertEqual(state["locked_until"], 0)

    def test_verify_blocks_while_another_process_holds_the_lock(self):
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                HOLD_LOCK_CHILD,
                str(self.auth),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            self.assertEqual(holder.stdout.readline().strip(), "HELD")

            # Délai volontairement court : il est consommé en entier par la
            # preuve de blocage. subprocess.run tue l'enfant avant de lever
            # TimeoutExpired, donc aucun processus ne survit avec le verrou.
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_child(
                    VERIFY_CHILD,
                    self.SECRET,
                    str(self.auth),
                    timeout=3,
                )
        finally:
            holder.stdin.write("\n")
            holder.stdin.flush()
            holder.communicate(timeout=30)

        self.assertTrue(auth_gate.verify(self.SECRET, path=self.auth))


if __name__ == "__main__":
    unittest.main()
