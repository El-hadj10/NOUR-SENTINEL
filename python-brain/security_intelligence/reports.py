"""Rapports JSON privés.

Chaque rapport est écrit atomiquement, en mode 0600, dans un dossier 0700.
Aucun rapport n'est écrit hors de `data/reports/`.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def ensure_private_directory(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)

    return directory


def write_report(report, directory):
    """Écrit un rapport horodaté et retourne son chemin."""

    directory = ensure_private_directory(directory)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    mode = str(report.get("mode") or "report").replace("/", "-")
    candidate = directory / f"{timestamp}-{mode}.json"
    counter = 1

    while candidate.exists():
        candidate = directory / f"{timestamp}-{mode}-{counter}.json"
        counter += 1

    descriptor, temporary = tempfile.mkstemp(
        prefix=".report.", suffix=".json", dir=str(directory)
    )

    try:
        os.fchmod(descriptor, 0o600)

        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, candidate)
        os.chmod(candidate, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise

    return candidate
