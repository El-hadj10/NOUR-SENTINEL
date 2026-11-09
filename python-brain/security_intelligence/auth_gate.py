"""Auth Gate propriétaire — Argon2id direct, verrou et permissions strictes.

Aucune session locale n'est créée ni acceptée : chaque lancement
opérationnel vérifie la phrase secrète contre le hash PHC. Le compteur
d'échecs est persistant et un verrou ``flock`` sérialise les tentatives.

Modèle de sécurité assumé : une protection logicielle locale ne résiste pas à
un compte Linux compromis ni à root. Elle complète le chiffrement du disque,
les permissions du compte et les mises à jour ; elle ne les remplace pas.

Aucun secret en clair n'est stocké : seul un hash PHC Argon2id est écrit,
dans un fichier 0600 appartenant à l'utilisateur courant.
"""

import argparse
import contextlib
import fcntl
import getpass
import json
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

try:
    import authz
except ModuleNotFoundError:  # exécution directe du script, sans PYTHONPATH
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import authz

MIN_SECRET_LENGTH = 16
MAX_ATTEMPTS = 3
LOCKOUT_BASE_SECONDS = 30
LOCKOUT_MAX_SECONDS = 900
ATTEMPTS_VERSION = 1
MAX_ATTEMPTS_BYTES = 4096

DEFAULT_AUTH_FILE = Path.home() / ".config" / "nour-sentinel" / "auth.phc"
ATTEMPTS_FILENAME = "auth.attempts.json"
LOCK_FILENAME = "auth.lock"


class AuthError(RuntimeError):
    """Erreur d'authentification ou de stockage du secret."""


def auth_path(path=None):
    """Chemin fixe du hash ; aucun environnement ne peut le rediriger."""

    return Path(path) if path is not None else DEFAULT_AUTH_FILE


def attempts_path(path=None):
    return auth_path(path).parent / ATTEMPTS_FILENAME


def lock_path(path=None):
    return auth_path(path).parent / LOCK_FILENAME


def _open_private_directory(directory):
    """Ouvre un dossier dédié sans suivre de lien et valide ses métadonnées."""

    directory = Path(directory)

    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise AuthError(
            f"dossier d'authentification absent ou refusé: {directory}"
        ) from error

    try:
        info = os.fstat(descriptor)

        if not stat.S_ISDIR(info.st_mode):
            raise AuthError(f"dossier d'authentification non ordinaire: {directory}")

        if info.st_uid != os.getuid():
            raise AuthError(
                "le dossier d'authentification n'appartient pas à l'utilisateur courant"
            )

        if stat.S_IMODE(info.st_mode) != 0o700:
            raise AuthError(
                f"permissions trop larges sur le dossier: {directory} (0700 requis)"
            )
    except Exception:
        os.close(descriptor)
        raise

    return descriptor


def _ensure_directory(directory):
    directory = Path(directory)

    if not directory.exists():
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)

    descriptor = _open_private_directory(directory)
    os.close(descriptor)


def _write_private(path, content):
    """Écrit atomiquement un fichier 0600 dans un dossier dédié 0700."""

    path = Path(path)
    _ensure_directory(path.parent)

    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
    )

    try:
        os.fchmod(descriptor, 0o600)

        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise AuthError(f"écriture du secret impossible: {path}")


def _read_private(path, label="secret", missing_ok=False, max_bytes=None):
    """Lit un fichier sensible via un descripteur O_NOFOLLOW et fstat."""

    path = Path(path)

    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except FileNotFoundError:
        if missing_ok:
            return None
        raise AuthError(
            f"aucun {label} configuré ({path}); exécutez --setup-auth"
        )
    except OSError as error:
        raise AuthError(f"{label} refusé ou illisible ({path}): {error}") from error

    try:
        info = os.fstat(descriptor)

        if not stat.S_ISREG(info.st_mode):
            raise AuthError(f"{label} non ordinaire refusé: {path}")

        if info.st_uid != os.getuid():
            raise AuthError(
                f"le {label} n'appartient pas à l'utilisateur courant"
            )

        if stat.S_IMODE(info.st_mode) != 0o600:
            raise AuthError(
                f"permissions trop larges sur le {label}: {path} (0600 requis)"
            )

        chunks = []
        total = 0

        while True:
            chunk = os.read(descriptor, 65536)

            if not chunk:
                break

            total += len(chunk)

            if max_bytes is not None and total > max_bytes:
                raise AuthError(f"{label} trop volumineux: {path}")

            chunks.append(chunk)

        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as error:
            raise AuthError(f"{label} illisible: encodage UTF-8 attendu") from error
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def _auth_lock(path=None):
    """Verrou exclusif inter-processus, fichier ordinaire 0600."""

    target = lock_path(path)
    _ensure_directory(target.parent)

    try:
        descriptor = os.open(
            target,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
    except OSError as error:
        raise AuthError(f"verrou d'authentification impossible: {error}") from error

    try:
        info = os.fstat(descriptor)

        if not stat.S_ISREG(info.st_mode):
            raise AuthError("verrou d'authentification non ordinaire refusé")

        if info.st_uid != os.getuid():
            raise AuthError(
                "le verrou d'authentification n'appartient pas à l'utilisateur courant"
            )

        if stat.S_IMODE(info.st_mode) != 0o600:
            raise AuthError(
                f"permissions trop larges sur le verrou: {target} (0600 requis)"
            )

        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _argon2():
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import InvalidHashError, VerificationError
        from argon2.exceptions import VerifyMismatchError
    except ImportError as error:
        raise AuthError(
            "argon2-cffi est requis pour l'Auth Gate; "
            "exécutez ./lancer-nour-sentinel.sh --setup-deps"
        ) from error

    hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )

    return hasher, VerifyMismatchError, InvalidHashError, VerificationError


def validate_secret(secret, minimum=MIN_SECRET_LENGTH):
    """Une phrase secrète est obligatoire ; aucun secret n'est journalisé."""

    if not isinstance(secret, str):
        raise AuthError("la phrase secrète doit être une chaîne")

    if len(secret) < minimum:
        raise AuthError(
            f"la phrase secrète doit contenir au moins {minimum} caractères"
        )

    if not secret.strip():
        raise AuthError("la phrase secrète ne peut pas être vide")

    if "\x00" in secret:
        raise AuthError("la phrase secrète contient un caractère interdit")

    return secret


def _empty_attempts():
    return {"version": ATTEMPTS_VERSION, "failures": 0, "locked_until": 0}


def _read_attempts(path=None):
    text = _read_private(
        attempts_path(path),
        "état de limitation",
        missing_ok=True,
        max_bytes=MAX_ATTEMPTS_BYTES,
    )

    if text is None:
        return _empty_attempts()

    try:
        data = json.loads(text)
    except ValueError as error:
        raise AuthError("état de limitation illisible") from error

    if not isinstance(data, dict):
        raise AuthError("état de limitation invalide")

    failures = data.get("failures")
    locked_until = data.get("locked_until")

    if (
        data.get("version") != ATTEMPTS_VERSION
        or isinstance(failures, bool)
        or not isinstance(failures, int)
        or failures < 0
        or isinstance(locked_until, bool)
        or not isinstance(locked_until, int)
        or locked_until < 0
    ):
        raise AuthError("état de limitation invalide")

    # Un état altéré ne doit pas pouvoir verrouiller le compte indéfiniment.
    if locked_until > int(time.time()) + LOCKOUT_MAX_SECONDS:
        raise AuthError("état de limitation invalide")

    return {
        "version": ATTEMPTS_VERSION,
        "failures": failures,
        "locked_until": locked_until,
    }


def _write_attempts(path, state):
    _write_private(
        attempts_path(path),
        json.dumps(state, sort_keys=True) + "\n",
    )


def _failure_delay(failures):
    """30 s après 3 échecs, puis doublement plafonné à 15 minutes."""

    if failures < MAX_ATTEMPTS:
        return 0

    exponent = min(failures - MAX_ATTEMPTS, 5)
    return min(LOCKOUT_BASE_SECONDS * (2**exponent), LOCKOUT_MAX_SECONDS)


def _record_failure(path, state, moment):
    failures = state["failures"] + 1
    delay = _failure_delay(failures)
    locked_until = moment + delay if delay else 0

    _write_attempts(
        path,
        {
            "version": ATTEMPTS_VERSION,
            "failures": failures,
            "locked_until": locked_until,
        },
    )

    return delay


def _lockout_remaining(state, moment):
    return max(0, int(state["locked_until"]) - int(moment))


def _verify_unlocked(secret, path=None):
    """Vérification bas niveau ; l'appelant doit détenir le verrou."""

    target = auth_path(path)
    stored = _read_private(target).strip()
    hasher, mismatch, invalid, verification = _argon2()

    try:
        hasher.verify(stored, secret)
    except mismatch:
        return False
    except invalid as error:
        raise AuthError(f"hash Argon2id invalide: {error}") from error
    except verification as error:
        raise AuthError(f"vérification Argon2id impossible: {error}") from error

    # Mise à niveau silencieuse si les paramètres ont évolué : le secret en
    # clair n'existe que pendant cette vérification.
    if hasher.check_needs_rehash(stored):
        _write_private(target, hasher.hash(secret) + "\n")

    return True


def verify(secret, path=None, now_fn=time.time):
    """Vérifie un secret en respectant la limitation des tentatives.

    Un échec est enregistré dans le même compteur persistant que
    ``authenticate`` ; au seuil, le compte est verrouillé. Aucun chemin public
    ne permet donc d'essayer des secrets à un rythme illimité. Un succès
    remet le compteur à zéro, comme l'authentification opérationnelle.
    """

    target = auth_path(path)

    with _auth_lock(target):
        moment = int(now_fn())
        state = _read_attempts(target)
        remaining = _lockout_remaining(state, moment)

        if remaining:
            raise AuthError(
                f"authentification verrouillée; réessayez dans {remaining} s"
            )

        if _verify_unlocked(secret, target):
            _write_attempts(target, _empty_attempts())
            return True

        delay = _record_failure(target, state, moment)

    if delay:
        raise AuthError(
            f"authentification refusée; compte verrouillé pendant {delay} s"
        )

    return False


def setup(secret, path=None, force=False, minimum=MIN_SECRET_LENGTH):
    """Crée le hash Argon2id initial. Refuse d'écraser sans ``force``."""

    validate_secret(secret, minimum)
    target = auth_path(path)

    with _auth_lock(target):
        if target.exists() and not force:
            raise AuthError(
                "un secret existe déjà; utilisez --change-auth pour le remplacer"
            )

        hasher, _, _, _ = _argon2()
        _write_private(target, hasher.hash(secret) + "\n")
        _write_attempts(target, _empty_attempts())

    return target


def change(old_secret, new_secret, path=None, minimum=MIN_SECRET_LENGTH):
    """Vérifie l'ancien secret avant de remplacer le hash."""

    validate_secret(new_secret, minimum)

    if old_secret == new_secret:
        raise AuthError("la nouvelle phrase secrète doit être différente")

    target = auth_path(path)

    with _auth_lock(target):
        now = int(time.time())
        state = _read_attempts(target)
        remaining = _lockout_remaining(state, now)

        if remaining:
            raise AuthError(
                f"authentification verrouillée; réessayez dans {remaining} s"
            )

        if not _verify_unlocked(old_secret, target):
            delay = _record_failure(target, state, now)

            if delay:
                raise AuthError(
                    "ancienne phrase secrète incorrecte; "
                    f"compte verrouillé pendant {delay} s"
                )

            raise AuthError("ancienne phrase secrète incorrecte")

        hasher, _, _, _ = _argon2()
        _write_private(target, hasher.hash(new_secret) + "\n")
        _write_attempts(target, _empty_attempts())

    return target


def authenticate(
    secret=None,
    path=None,
    require_tty=True,
    getpass_fn=None,
    input_stream=None,
    max_attempts=MAX_ATTEMPTS,
    now_fn=time.time,
):
    """Vérifie Argon2id directement, avec verrou et limitation persistante.

    Aucune session n'est créée. Un échec répété est enregistré dans
    ``auth.attempts.json`` ; trois échecs consécutifs déclenchent un
    verrouillage de 30 s, doublé progressivement jusqu'à 15 minutes.
    """

    target = auth_path(path)
    authz.reset()
    _read_private(target)

    stream = input_stream or sys.stdin

    if require_tty and not getattr(stream, "isatty", lambda: False)():
        raise AuthError(
            "terminal interactif requis; lancez ./lancer-nour-sentinel.sh"
        )

    prompt = getpass_fn or getpass.getpass
    attempts = max(1, int(max_attempts))

    for attempt in range(1, attempts + 1):
        moment = int(now_fn())

        with _auth_lock(target):
            state = _read_attempts(target)
            remaining = _lockout_remaining(state, moment)

            if remaining:
                raise AuthError(
                    f"authentification verrouillée; réessayez dans {remaining} s"
                )

        candidate = secret if secret is not None else prompt(
            "Phrase secrète NOUR SENTINEL : "
        )

        moment = int(now_fn())

        with _auth_lock(target):
            state = _read_attempts(target)
            remaining = _lockout_remaining(state, moment)

            if remaining:
                raise AuthError(
                    f"authentification verrouillée; réessayez dans {remaining} s"
                )

            if _verify_unlocked(candidate, target):
                _write_attempts(target, _empty_attempts())
                authz._grant()
                return True

            delay = _record_failure(target, state, moment)

        if delay:
            raise AuthError(
                f"authentification refusée; compte verrouillé pendant {delay} s"
            )

        print(
            f"Authentification refusée ({attempt}/{attempts}).",
            file=sys.stderr,
        )

    raise AuthError(f"authentification refusée après {attempts} tentative(s)")


def _prompt_new_secret(minimum=MIN_SECRET_LENGTH):
    first = getpass.getpass("Nouvelle phrase secrète (16 caractères minimum) : ")
    second = getpass.getpass("Confirmation : ")

    if first != second:
        raise AuthError("les deux saisies ne correspondent pas")

    validate_secret(first, minimum)

    return first


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="auth_gate",
        description="Authentification propriétaire NOUR SENTINEL (Argon2id).",
    )
    parser.add_argument("--version", action="version", version="0.6.0-beta.3")

    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("setup", help="créer le secret initial")
    commands.add_parser("change", help="changer le secret")
    commands.add_parser(
        "authenticate", help="vérifier la phrase secrète pour ce lancement"
    )

    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "setup":
            if not sys.stdin.isatty():
                raise AuthError("terminal interactif requis pour créer le secret")

            target = setup(_prompt_new_secret())
            print(f"Secret Argon2id créé: {target}")
            return 0

        if arguments.command == "change":
            if not sys.stdin.isatty():
                raise AuthError("terminal interactif requis pour changer le secret")

            old = getpass.getpass("Ancienne phrase secrète : ")
            new = _prompt_new_secret()
            target = change(old, new)
            print(f"Secret Argon2id remplacé: {target}")
            return 0

        if arguments.command == "authenticate":
            authenticate()
            return 0

    except AuthError as error:
        print(f"[AUTH ERROR] {error}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("[AUTH ERROR] saisie interrompue", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
