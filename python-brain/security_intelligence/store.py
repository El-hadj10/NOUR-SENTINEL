"""Mémoire d'intelligence du laboratoire (SQLite local).

La base ne conserve ni secret, ni hash de mot de passe, ni journal brut :
uniquement les exécutions et les constats normalisés.
"""

import json
import os
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    version TEXT NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    report_path TEXT,
    risk_summary TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    finding_id TEXT,
    asset_id TEXT,
    check_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    priority TEXT,
    status TEXT NOT NULL,
    cve TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_check ON findings(check_name);
"""


class StoreError(RuntimeError):
    """La mémoire locale n'a pas pu être ouverte ou écrite."""


class IntelStore:
    """Connexion SQLite explicite, fermée par l'appelant."""

    def __init__(self, path):
        self.path = Path(path)
        self.connection = None

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.path.parent, 0o700)

            self.connection = sqlite3.connect(str(self.path))
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.executescript(SCHEMA)
            self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.connection.commit()
            os.chmod(self.path, 0o600)
        except (OSError, sqlite3.Error) as error:
            raise StoreError(f"base d'intelligence indisponible: {error}") from error

    def save_run(self, report):
        """Enregistre une exécution et ses constats dans une transaction."""

        if self.connection is None:
            raise StoreError("base d'intelligence fermée")

        findings = [
            finding for finding in report.get("findings") or [] if isinstance(finding, dict)
        ]

        try:
            with self.connection:
                cursor = self.connection.execute(
                    """
                    INSERT INTO runs
                        (started_at, mode, version, findings_count, report_path, risk_summary)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(report.get("generated_at") or ""),
                        str(report.get("mode") or "unknown"),
                        str(report.get("version") or ""),
                        len(findings),
                        str(report.get("report_path") or ""),
                        json.dumps(report.get("risk_summary") or {}, ensure_ascii=False),
                    ),
                )
                run_id = cursor.lastrowid

                self.connection.executemany(
                    """
                    INSERT INTO findings
                        (run_id, finding_id, asset_id, check_name, severity,
                         confidence, priority, status, cve)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            run_id,
                            finding.get("finding_id"),
                            finding.get("asset_id"),
                            str(finding.get("check") or "unknown"),
                            str(finding.get("severity") or "info"),
                            str(finding.get("confidence") or "unknown"),
                            finding.get("priority"),
                            str(finding.get("status") or "open"),
                            finding.get("cve"),
                        )
                        for finding in findings
                    ],
                )
        except sqlite3.Error as error:
            raise StoreError(f"enregistrement impossible: {error}") from error

        return run_id

    def attach_report(self, run_id, report_path):
        """Relie une exécution au rapport privé effectivement écrit."""

        if self.connection is None:
            raise StoreError("base d'intelligence fermée")

        try:
            with self.connection:
                self.connection.execute(
                    "UPDATE runs SET report_path = ? WHERE id = ?",
                    (str(report_path), int(run_id)),
                )
        except sqlite3.Error as error:
            raise StoreError(f"lien rapport/base impossible: {error}") from error

    def count_runs(self):
        if self.connection is None:
            raise StoreError("base d'intelligence fermée")

        return int(self.connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0])

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
