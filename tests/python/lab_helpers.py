"""Fixtures partagées des tests du laboratoire (hors découverte unittest)."""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT / "python-brain") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "python-brain"))

from security_intelligence import VERSION  # noqa: E402


def make_config(directory):
    directory = Path(directory)

    return {
        "version": VERSION,
        "environment": "test",
        "authorized_targets": ("127.0.0.1", "localhost"),
        "timeout": 2.0,
        "max_response_bytes": 65536,
        "inventory": {
            "packages": True,
            "services": True,
            "sockets": True,
            "max_packages": 100,
        },
        "probes": {"ssh_banner": True, "http_head": True, "tls": True},
        "journal": {"enabled": False, "lines": 50},
        "docker": {"enabled": False},
        "online": {
            "enabled": True,
            "max_requests": 10,
            "cache_ttl_seconds": 3600,
            "timeout_seconds": 2.0,
            "nvd_api_key_env": "NVD_API_KEY",
        },
        "reports_dir": directory / "reports",
        "database": directory / "history" / "nour_sentinel_intel.db",
    }


def write_private(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)

    return path
