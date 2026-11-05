"""Lecture journald en JSON, agrégée par le détecteur v0.5.0.

Les lignes brutes ne quittent jamais cette fonction : seuls des compteurs,
des adresses source et des indicateurs normalisés sont conservés.
"""

from intelligence.intrusion import detector
from security_intelligence.fingerprinting.inventory import run_command


def collect(config, host, runner=None, exposure="local"):
    """Retourne `(findings, metadata, errors)` sans conserver de log brut."""

    runner = runner or run_command
    lines = int((config or {}).get("journal", {}).get("lines") or 200)

    result = runner(
        ["journalctl", "-o", "json", "-n", str(lines), "--no-pager"],
        20,
    )

    if result.get("returncode") != 0:
        message = str(result.get("stderr") or "").strip()[:160] or "échec"
        return [], {"entries": 0}, [f"journalctl: {message}"]

    entries = detector.parse_journal_lines(
        str(result.get("stdout") or "").splitlines()
    )
    findings = detector.detect(entries, host=host)

    # Les constats v0.5.0 peuvent citer une ligne de journal dans `evidence`.
    # Le laboratoire ne l'exporte pas : il conserve le contrôle et le compte.
    for finding in findings:
        check = str(finding.get("check") or "intrusion.unknown")
        finding["evidence"] = f"journald:{check}"
        finding["metadata"] = {
            **(finding.get("metadata") or {}),
            "raw_logs": "not_exported",
        }

    return (
        findings,
        {"entries": len(entries), "indicators": len(findings)},
        [],
    )
