"""Moteur de risque : dédoublonnage, score et priorisation.

Le score combine gravité, confiance, exposition et signaux d'exploitation
(KEV/EPSS) quand ils sont connus. Il ne remplace pas l'analyse : il ordonne.
"""

from intelligence.models import (
    CONFIDENCE_WEIGHT,
    SEVERITIES,
    SEVERITY_RANK,
    normalize_confidence,
    normalize_severity,
)

SEVERITY_BASE = {
    "info": 1.0,
    "low": 2.0,
    "medium": 4.5,
    "high": 7.5,
    "critical": 10.0,
}

EXPOSURE_FACTOR = {
    "local": 0.5,
    "lan": 1.0,
    "vpn": 0.9,
    "external": 1.4,
    "unknown": 0.7,
}


def score(finding):
    severity = normalize_severity(finding.get("severity"))
    confidence = normalize_confidence(finding.get("confidence"))
    exposure = str(finding.get("exposure") or "unknown")

    value = (
        SEVERITY_BASE[severity]
        * CONFIDENCE_WEIGHT[confidence]
        * EXPOSURE_FACTOR.get(exposure, EXPOSURE_FACTOR["unknown"])
    )

    if finding.get("kev") is True:
        value = min(10.0, value + 2.0)

    epss = finding.get("epss")

    if isinstance(epss, (int, float)) and not isinstance(epss, bool):
        value = min(10.0, value + 2.0 * float(epss))

    return round(min(10.0, value), 2)


def _rank(finding):
    return (
        SEVERITY_RANK.get(normalize_severity(finding.get("severity")), 0),
        CONFIDENCE_WEIGHT.get(normalize_confidence(finding.get("confidence")), 0.0),
    )


def deduplicate(findings):
    """Un seul constat par (actif, port, contrôle, composant)."""

    merged = {}

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        key = (
            finding.get("asset_id"),
            finding.get("port"),
            finding.get("check"),
            finding.get("component"),
        )
        current = merged.get(key)

        if current is None:
            merged[key] = finding
            continue

        # Un même constat présent deux fois (objet ou contenu identique) ne
        # doit jamais être enregistré comme son propre doublon.
        if finding is current or finding == current:
            continue

        if _rank(finding) > _rank(current):
            merged[key] = finding
            merged[key].setdefault("metadata", {})["superseded"] = current.get(
                "finding_id"
            )
        else:
            duplicates = current.setdefault("metadata", {}).setdefault(
                "duplicates", []
            )
            identifier = finding.get("finding_id")
            current_identifier = current.get("finding_id")

            if (
                identifier
                and identifier != current_identifier
                and identifier not in duplicates
            ):
                duplicates.append(identifier)

    return list(merged.values())


def priority_for(value):
    if value >= 7.0:
        return "P1"

    if value >= 4.5:
        return "P2"

    if value >= 2.0:
        return "P3"

    return "P4"


def prioritize(findings):
    """Ajoute `priority_score` et `priority`, puis trie."""

    for finding in findings or []:
        finding["priority_score"] = score(finding)

    ordered = sorted(
        findings or [],
        key=lambda finding: (-finding["priority_score"], str(finding.get("finding_id"))),
    )

    for finding in ordered:
        finding["priority"] = priority_for(finding["priority_score"])

    return ordered


def summarize(findings):
    by_severity = {name: 0 for name in SEVERITIES}
    by_priority = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    by_status = {}
    with_evidence = 0

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(finding.get("severity"))
        by_severity[severity] += 1

        priority = finding.get("priority")

        if not priority:
            value = finding.get("priority_score")

            if not isinstance(value, (int, float)):
                value = score(finding)

            priority = priority_for(value)

        by_priority[priority] = by_priority.get(priority, 0) + 1

        status = str(finding.get("status") or "open")
        by_status[status] = by_status.get(status, 0) + 1

        if str(finding.get("evidence") or "").strip():
            with_evidence += 1

    return {
        "total": len([finding for finding in findings or [] if isinstance(finding, dict)]),
        "by_severity": by_severity,
        "by_priority": by_priority,
        "by_status": by_status,
        "with_evidence": with_evidence,
        "without_evidence": len(findings or []) - with_evidence,
    }
