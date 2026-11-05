"""Auth Gate propriétaire — Argon2id, PHC et permissions strictes.

Modèle de sécurité assumé : une protection logicielle locale ne résiste pas à
un compte Linux compromis ni à root. Elle complète le chiffrement du disque,
les permissions du compte et les mises à jour ; elle ne les remplace pas.

Aucun secret en clair n'est stocké : seul un hash PHC Argon2id est écrit,
dans un fichier 0600 appartenant à l'utilisateur courant.
"""

import argparse
import getpass
import json
import os
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path

MIN_SECRET_LENGTH = 16
MAX_ATTEMPTS = 3
SESSION_TTL_SECONDS = 300

DEFAULT_AUTH_FILE = Path.home() / ".config" / "nour-sentinel" / "auth.phc"
DEFAULT_SESSION_FILE = Path.home() / ".config" / "nour-sentinel" / "session.json"


class AuthError(RuntimeError):
    """Erreur d'authentification ou de stockage du secret."""


def auth_path(path=None):
    return Path(
        path or os.environ.get("NOUR_SENTINEL_AUTH_FILE") or DEFAULT_AUTH_FILE
    ).expanduser()


def session_path(path=None):
    return Path(
        path or os.environ.get("NOUR_SENTINEL_SESSION") or DEFAULT_SESSION_FILE
    ).expanduser()


def _ensure_directory(directory):
    existed = directory.exists()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Ne jamais changer les permissions d'un répertoire personnel existant
    # (par exemple $HOME) : seule la arborescence dédiée est durcie.
    if not existed or directory.name == "nour-sentinel":
        os.chmod(directory, 0o700)


def _write_private(path, content):
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


def _read_private(path):
    path = Path(path)

    try:
        info = path.lstat()
    except OSError as error:
        raise AuthError(
            f"aucun secret configuré ({path}); exécutez --setup-auth"
        ) from error

    if stat.S_ISLNK(info.st_mode):
        raise AuthError(f"fichier de secret symbolique refusé: {path}")

    if not stat.S_ISREG(info.st_mode):
        raise AuthError(f"fichier de secret non ordinaire refusé: {path}")

    if info.st_uid != os.getuid():
        raise AuthError("le fichier de secret n'appartient pas à l'utilisateur courant")

    if info.st_mode & 0o077:
        raise AuthError(f"permissions trop larges sur le secret: {path} (0600 requis)")

    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise AuthError(f"lecture du secret impossible: {error}") from error


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


def setup(secret, path=None, force=False, minimum=MIN_SECRET_LENGTH):
    """Crée le hash Argon2id initial. Refuse d'écraser sans `force`."""

    validate_secret(secret, minimum)
    target = auth_path(path)

    if target.exists() and not force:
        raise AuthError(
            "un secret existe déjà; utilisez --change-auth pour le remplacer"
        )

    hasher, _, _, _ = _argon2()
    _write_private(target, hasher.hash(secret) + "\n")

    return target


def verify(secret, path=None):
    """Vérifie la phrase secrète. Retourne False sur simple désaccord."""

    stored = _read_private(auth_path(path))
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
    # clair est encore disponible uniquement dans cette fonction.
    if hasher.check_needs_rehash(stored):
        _write_private(auth_path(path), hasher.hash(secret) + "\n")

    return True


def change(old_secret, new_secret, path=None, minimum=MIN_SECRET_LENGTH):
    """Vérifie l'ancien secret avant de remplacer le hash."""

    if not verify(old_secret, path):
        raise AuthError("ancienne phrase secrète incorrecte")

    validate_secret(new_secret, minimum)

    if old_secret == new_secret:
        raise AuthError("la nouvelle phrase secrète doit être différente")

    return setup(new_secret, path=path, force=True, minimum=minimum)


def login(
    attempts=MAX_ATTEMPTS,
    path=None,
    require_tty=True,
    getpass_fn=None,
    sleep_fn=time.sleep,
    input_stream=None,
):
    """Trois tentatives, temporisation progressive, terminal requis."""

    target = auth_path(path)
    _read_private(target)

    stream = input_stream or sys.stdin

    if require_tty:
        is_tty = getattr(stream, "isatty", lambda: False)()

        if not is_tty:
            raise AuthError(
                "terminal interactif requis; utilisez ./lancer-nour-sentinel.sh"
            )

    prompt = getpass_fn or getpass.getpass

    for attempt in range(1, attempts + 1):
        secret = prompt("Phrase secrète NOUR SENTINEL : ")

        if verify(secret, target):
            return True

        if attempt < attempts:
            delay = 0.5 * attempt
            print(
                f"Authentification refusée ({attempt}/{attempts}); "
                f"nouvel essai dans {delay:g}s.",
                file=sys.stderr,
            )
            sleep_fn(delay)

    raise AuthError(f"authentification refusée après {attempts} tentative(s)")


def create_session(path=None, ttl=SESSION_TTL_SECONDS):
    """Crée une session locale courte, lisible par le moteur Rust."""

    ttl = max(30, min(int(ttl), 3600))
    now = int(time.time())
    target = session_path(path)

    content = json.dumps(
        {
            "version": 1,
            "created_at": now,
            "expires_at": now + ttl,
            "nonce": secrets.token_hex(16),
        },
        sort_keys=True,
    )

    _write_private(target, content + "\n")

    return target


def session_valid(path=None, now=None):
    """Valide une session : fichier ordinaire 0600 et expiration future."""

    target = session_path(path)

    try:
        info = target.lstat()
    except OSError:
        return False

    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return False

    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        return False

    try:
        session = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False

    if not isinstance(session, dict):
        return False

    expires_at = session.get("expires_at")

    if isinstance(expires_at, bool) or not isinstance(expires_at, int):
        return False

    current = int(time.time()) if now is None else int(now)

    return current < expires_at <= current + 3600


def clear_session(path=None):
    try:
        session_path(path).unlink()
    except OSError:
        pass


def ensure_authenticated(
    auth_file=None,
    session_file=None,
    ttl=SESSION_TTL_SECONDS,
    require_tty=True,
):
    """Réutilise une session valide ou demande la phrase secrète."""

    if session_valid(session_file):
        return session_path(session_file)

    login(path=auth_file, require_tty=require_tty)

    return create_session(session_file, ttl=ttl)


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
    parser.add_argument("--version", action="version", version="0.6.0-beta.1")

    commands = parser.add_subparsers(dest="command", required=True)

    setup_parser = commands.add_parser("setup", help="créer le secret initial")
    setup_parser.add_argument("--auth-file")

    change_parser = commands.add_parser("change", help="changer le secret")
    change_parser.add_argument("--auth-file")

    login_parser = commands.add_parser("login", help="s'authentifier")
    login_parser.add_argument("--auth-file")
    login_parser.add_argument("--session-file")
    login_parser.add_argument("--ttl", type=int, default=SESSION_TTL_SECONDS)

    status_parser = commands.add_parser("status", help="état de la session")
    status_parser.add_argument("--session-file")

    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "setup":
            if not sys.stdin.isatty():
                raise AuthError("terminal interactif requis pour créer le secret")
            target = setup(_prompt_new_secret(), path=arguments.auth_file)
            print(f"Secret Argon2id créé: {target}")
            return 0

        if arguments.command == "change":
            if not sys.stdin.isatty():
                raise AuthError("terminal interactif requis pour changer le secret")
            old = getpass.getpass("Ancienne phrase secrète : ")
            new = _prompt_new_secret()
            target = change(old, new, path=arguments.auth_file)
            print(f"Secret Argon2id remplacé: {target}")
            return 0

        if arguments.command == "login":
            login(path=arguments.auth_file)
            target = create_session(arguments.session_file, ttl=arguments.ttl)
            print(f"Session créée: {target}")
            return 0

        if arguments.command == "status":
            if session_valid(arguments.session_file):
                print("session valide")
                return 0

            print("session absente ou expirée")
            return 1

    except AuthError as error:
        print(f"[AUTH ERROR] {error}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
