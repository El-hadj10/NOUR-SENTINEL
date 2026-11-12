#!/usr/bin/env bash
# NOUR SENTINEL LAB 0.6.0-beta.3 — lanceur authentifié, sans session.
# Aucun secret n'est stocké dans ce fichier ni dans settings.json.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERSION="0.6.0-beta.3"
CORE_VERSION="0.5.0"
PROTOCOL_VERSION="3.0"
VENV="$ROOT/.venv"
PYTHON="$VENV/bin/python"
REQUIREMENTS="$ROOT/python-brain/requirements.txt"
AUTH_GATE="$ROOT/python-brain/security_intelligence/auth_gate.py"
BINARY="$ROOT/rust-engine/target/debug/nour-sentinel"
MANIFEST="$ROOT/rust-engine/Cargo.toml"

export PYTHONPATH="$ROOT/python-brain${PYTHONPATH:+:$PYTHONPATH}"

usage() {
    cat <<'EOF'
NOUR SENTINEL LAB 0.6.0-beta.3

Utilisation :
  ./lancer-nour-sentinel.sh                  Authentification puis moteur Rust
  ./lancer-nour-sentinel.sh --setup-deps     Créer le venv et installer argon2-cffi
  ./lancer-nour-sentinel.sh --setup-auth     Créer le secret propriétaire initial
  ./lancer-nour-sentinel.sh --change-auth    Changer le secret (ancien vérifié)
  ./lancer-nour-sentinel.sh --intel inventory
  ./lancer-nour-sentinel.sh --intel full-local
  ./lancer-nour-sentinel.sh --intel discover
  ./lancer-nour-sentinel.sh --intel scan --target 192.168.1.1 --protocol both --confirm-authorized
  ./lancer-nour-sentinel.sh --intel tls --target 127.0.0.1 --port 8443
  ./lancer-nour-sentinel.sh --intel fingerprint --target 127.0.0.1 --port 22 --protocol ssh
  ./lancer-nour-sentinel.sh --intel cve --online
  ./lancer-nour-sentinel.sh --intel dashboard [--port 8765]
  ./lancer-nour-sentinel.sh --help
  ./lancer-nour-sentinel.sh --version

Chaque lancement opérationnel vérifie la phrase secrète Argon2id. Aucune
session n'est créée ni réutilisée. La liste blanche par défaut est limitée à
127.0.0.1 et localhost dans config/security_intelligence.json.
EOF
}

die() {
    echo "[LAB ERROR] $*" >&2
    exit 2
}

ensure_python() {
    if [[ ! -x "$PYTHON" ]]; then
        die "environnement Python absent ; exécutez ./lancer-nour-sentinel.sh --setup-deps"
    fi

    if ! "$PYTHON" -c 'import argon2' >/dev/null 2>&1; then
        die "argon2-cffi absent ; exécutez ./lancer-nour-sentinel.sh --setup-deps"
    fi
}

setup_deps() {
    command -v python3 >/dev/null 2>&1 || die "python3 est requis"

    if [[ ! -x "$PYTHON" ]]; then
        python3 -m venv "$VENV" || die "création du venv impossible (python3-venv ?)"
    fi

    "$PYTHON" -m pip install --disable-pip-version-check -r "$REQUIREMENTS"
    echo "[LAB] Dépendances installées dans $VENV"
}

case "${1:-}" in
    --help|-h)
        usage
        ;;
    --version|-V)
        echo "NOUR SENTINEL LAB $VERSION (moteur $CORE_VERSION, protocole $PROTOCOL_VERSION)"
        ;;
    --setup-deps)
        setup_deps
        ;;
    --setup-auth)
        ensure_python
        "$PYTHON" "$AUTH_GATE" setup
        ;;
    --change-auth)
        ensure_python
        "$PYTHON" "$AUTH_GATE" change
        ;;
    --intel)
        shift
        [[ $# -ge 1 ]] || die "commande --intel manquante"
        ensure_python
        "$PYTHON" -m security_intelligence.cli "$@"
        ;;
    "")
        ensure_python

        if [[ -x "$BINARY" ]]; then
            "$BINARY"
        else
            command -v cargo >/dev/null 2>&1 || die "binaire Rust absent et cargo introuvable"
            cargo run --manifest-path "$MANIFEST"
        fi
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
