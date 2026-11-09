"""Point d'entrée du cerveau Python.

L'authentification Argon2id est exécutée avant la lecture de stdin. Le mode
``--handshake`` permet à Rust d'attendre le succès de l'Auth Gate avant toute
collecte ; la ligne ``AUTH_OK`` n'est jamais émise en mode direct.
"""

import argparse
import json
import sys

from analyzer import analyze_events
from security_intelligence import auth_gate


def authenticate():
    """Ouvre le terminal contrôlant et vérifie le secret avant toute lecture."""

    try:
        with open("/dev/tty", "r", encoding="utf-8") as terminal:
            auth_gate.authenticate(input_stream=terminal)
    except OSError as error:
        raise auth_gate.AuthError(
            "terminal interactif requis pour l'authentification"
        ) from error


def main():
    parser = argparse.ArgumentParser(prog="nour-sentinel-python")
    parser.add_argument(
        "--handshake",
        action="store_true",
        help="émettre AUTH_OK après l'Auth Gate, pour le moteur Rust",
    )
    arguments = parser.parse_args()

    try:
        authenticate()

        if arguments.handshake:
            print("AUTH_OK", flush=True)

        data = json.load(sys.stdin)
        result = analyze_events(data)

        # stdout is reserved exclusively for JSON.
        json.dump(result, sys.stdout, indent=4)
        sys.stdout.write("\n")
        sys.stdout.flush()

    except auth_gate.AuthError as error:
        print(f"[AUTH ERROR] {error}", file=sys.stderr)
        sys.exit(2)

    except Exception as error:
        print(f"[PYTHON ERROR] {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
