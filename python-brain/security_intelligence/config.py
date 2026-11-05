"""Configuration du laboratoire et liste blanche réseau.

Toute valeur est validée avant usage. Les chemins d'écriture sont confinés
sous `data/` : une configuration ne peut pas faire écrire un rapport ou une
base ailleurs dans le système.
"""

import ipaddress
import json
import os
from pathlib import Path

from security_intelligence import VERSION

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_CONFIG = PROJECT_ROOT / "config" / "security_intelligence.json"

DATA_ROOT = (PROJECT_ROOT / "data").resolve()


class ConfigError(ValueError):
    """Configuration absente, illisible ou hors des bornes autorisées."""


def _bounded_int(value, default, minimum, maximum, name):
    if value is None:
        return default

    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} doit être un entier")

    if value < minimum or value > maximum:
        raise ConfigError(f"{name} doit être compris entre {minimum} et {maximum}")

    return value


def _bounded_float(value, default, minimum, maximum, name):
    if value is None:
        return default

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} doit être un nombre")

    number = float(value)

    if number < minimum or number > maximum:
        raise ConfigError(f"{name} doit être compris entre {minimum} et {maximum}")

    return number


def _bool(value, default, name):
    if value is None:
        return default

    if not isinstance(value, bool):
        raise ConfigError(f"{name} doit être un booléen")

    return value


def _data_path(value, default, name):
    """Résout un chemin d'écriture et le confine sous `data/`."""

    raw = str(value or default).strip()
    candidate = Path(raw).expanduser()

    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate

    resolved = candidate.resolve()

    if resolved != DATA_ROOT and DATA_ROOT not in resolved.parents:
        raise ConfigError(f"{name} doit rester sous {DATA_ROOT}")

    return resolved


def normalize_targets(values):
    """Valide une liste blanche : IP littérales et `localhost` uniquement."""

    if not isinstance(values, list) or not values:
        raise ConfigError("authorized_targets doit être une liste non vide")

    targets = []

    for value in values:
        text = str(value).strip()

        if not text:
            continue

        if text == "localhost":
            if text not in targets:
                targets.append(text)
            continue

        try:
            ipaddress.ip_address(text)
        except ValueError as error:
            raise ConfigError(
                f"cible autorisée invalide (IP littérale ou localhost requise): {text}"
            ) from error

        if text not in targets:
            targets.append(text)

    if not targets:
        raise ConfigError("authorized_targets ne contient aucune cible exploitable")

    return targets


def resolve_target(target, allowed):
    """Retourne l'adresse à contacter, après contrôle strict de la liste blanche."""

    text = str(target or "").strip()
    permitted = {str(item).strip() for item in (allowed or ())}

    if not text:
        raise PermissionError("cible vide refusée")

    if text not in permitted:
        raise PermissionError(
            f"cible non autorisée: {text!r} (ajoutez-la explicitement à "
            "config/security_intelligence.json)"
        )

    if text == "localhost":
        return ["127.0.0.1"]

    try:
        return [str(ipaddress.ip_address(text))]
    except ValueError as error:
        raise PermissionError(f"cible invalide: {text!r}") from error


def validate_config(data):
    """Valide un document déjà chargé et retourne la configuration effective."""

    if not isinstance(data, dict):
        raise ConfigError("la configuration doit être un objet JSON")

    application = data.get("application") or {}

    if not isinstance(application, dict):
        raise ConfigError("application doit être un objet")

    if application.get("version") != VERSION:
        raise ConfigError(
            f"version de laboratoire attendue: {VERSION} "
            f"(reçu: {application.get('version')!r})"
        )

    targets = normalize_targets(data.get("authorized_targets"))

    inventory = data.get("inventory") or {}
    probes = data.get("probes") or {}
    journal = data.get("journal") or {}
    docker = data.get("docker") or {}
    online = data.get("online") or {}
    auth = data.get("auth") or {}
    reports = data.get("reports") or {}

    for section, name in (
        (inventory, "inventory"),
        (probes, "probes"),
        (journal, "journal"),
        (docker, "docker"),
        (online, "online"),
        (auth, "auth"),
        (reports, "reports"),
    ):
        if not isinstance(section, dict):
            raise ConfigError(f"{name} doit être un objet")

    config = {
        "version": VERSION,
        "environment": str(application.get("environment") or "lab"),
        "authorized_targets": tuple(targets),
        "timeout": _bounded_float(data.get("timeout"), 2.0, 0.5, 30.0, "timeout"),
        "max_response_bytes": _bounded_int(
            data.get("max_response_bytes"), 65536, 1024, 1_048_576, "max_response_bytes"
        ),
        "auth": {
            "min_secret_length": _bounded_int(
                auth.get("min_secret_length"), 16, 16, 128, "auth.min_secret_length"
            ),
            "max_attempts": _bounded_int(
                auth.get("max_attempts"), 3, 1, 5, "auth.max_attempts"
            ),
            "session_ttl_seconds": _bounded_int(
                auth.get("session_ttl_seconds"), 300, 30, 3600, "auth.session_ttl_seconds"
            ),
        },
        "inventory": {
            "packages": _bool(inventory.get("packages"), True, "inventory.packages"),
            "services": _bool(inventory.get("services"), True, "inventory.services"),
            "sockets": _bool(inventory.get("sockets"), True, "inventory.sockets"),
            "max_packages": _bounded_int(
                inventory.get("max_packages"), 5000, 1, 20000, "inventory.max_packages"
            ),
        },
        "probes": {
            "ssh_banner": _bool(probes.get("ssh_banner"), True, "probes.ssh_banner"),
            "http_head": _bool(probes.get("http_head"), True, "probes.http_head"),
            "tls": _bool(probes.get("tls"), True, "probes.tls"),
        },
        "journal": {
            "enabled": _bool(journal.get("enabled"), False, "journal.enabled"),
            "lines": _bounded_int(journal.get("lines"), 200, 1, 5000, "journal.lines"),
        },
        "docker": {
            "enabled": _bool(docker.get("enabled"), True, "docker.enabled"),
        },
        "online": {
            "enabled": _bool(online.get("enabled"), False, "online.enabled"),
            "max_requests": _bounded_int(
                online.get("max_requests"), 20, 1, 100, "online.max_requests"
            ),
            "cache_ttl_seconds": _bounded_int(
                online.get("cache_ttl_seconds"),
                86400,
                0,
                604800,
                "online.cache_ttl_seconds",
            ),
            "timeout_seconds": _bounded_float(
                online.get("timeout_seconds"), 10.0, 1.0, 60.0, "online.timeout_seconds"
            ),
            "nvd_api_key_env": str(online.get("nvd_api_key_env") or "NVD_API_KEY"),
        },
        "reports_dir": _data_path(
            reports.get("directory"), "data/reports", "reports.directory"
        ),
        "database": _data_path(
            reports.get("history_database"),
            "data/history/nour_sentinel_intel.db",
            "reports.history_database",
        ),
    }

    return config


def load_config(path=None):
    """Charge et valide `config/security_intelligence.json`."""

    config_path = Path(
        path or os.environ.get("NOUR_SENTINEL_INTEL_CONFIG") or DEFAULT_CONFIG
    ).expanduser()

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"configuration illisible: {error}") from error

    try:
        data = json.loads(text)
    except ValueError as error:
        raise ConfigError(f"configuration JSON invalide: {error}") from error

    config = validate_config(data)
    config["path"] = config_path

    return config
