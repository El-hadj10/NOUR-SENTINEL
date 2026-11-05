"""Modèle de constat normalisé.

Chaque module produit le même objet. Une alerte ne peut être haute ou critique
que si elle possède une preuve et une confiance suffisante : c'est la règle
centrale du plan (« aucune alerte critique sans preuve »).
"""

import hashlib
from datetime import datetime, timezone

SEVERITIES = ("info", "low", "medium", "high", "critical")

CONFIDENCES = ("confirmed", "corroborated", "probable", "low", "unknown")

EXPOSURES = ("local", "lan", "vpn", "external", "unknown")

STATUSES = ("open", "to_verify", "fixed", "not_applicable", "accepted")

SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

CONFIDENCE_WEIGHT = {
    "confirmed": 1.0,
    "corroborated": 0.9,
    "probable": 0.65,
    "low": 0.4,
    "unknown": 0.2,
}

# Synonymes acceptés depuis les scanners externes (nmap, trivy, testssl).
_SEVERITY_ALIASES = {
    "informational": "info",
    "moderate": "medium",
    "important": "high",
    "severe": "critical",
    "warning": "medium",
}

_CONFIDENCE_ALIASES = {
    "high": "corroborated",
    "medium": "probable",
    "moderate": "probable",
}

_TRUSTED_CONFIDENCES = ("confirmed", "corroborated")


def normalize_severity(value):
    text = str(value or "").strip().lower()
    text = _SEVERITY_ALIASES.get(text, text)

    return text if text in SEVERITY_RANK else "info"


def normalize_confidence(value):
    text = str(value or "").strip().lower()
    text = _CONFIDENCE_ALIASES.get(text, text)

    return text if text in CONFIDENCE_WEIGHT else "unknown"


def cap_severity(severity, confidence, evidence):
    """Ramène une sévérité haute à `medium` sans preuve ou confiance.

    Retourne `(severity, capped)`. Le drapeau est conservé dans le constat :
    une réduction n'est jamais silencieuse.
    """

    severity = normalize_severity(severity)
    confidence = normalize_confidence(confidence)

    if SEVERITY_RANK[severity] >= SEVERITY_RANK["high"]:
        has_evidence = bool(str(evidence or "").strip())

        if confidence not in _TRUSTED_CONFIDENCES or not has_evidence:
            return "medium", True

    return severity, False


def build_finding_id(asset, check, component):
    material = f"{asset}|{check}|{component}".lower()
    digest = hashlib.sha1(material.encode("utf-8")).hexdigest()[:12]

    return f"f-{digest}"


def make_finding(
    *,
    asset,
    check,
    component=None,
    observation="",
    evidence="",
    confidence="unknown",
    severity="info",
    exposure="unknown",
    recommendation="",
    references=None,
    status="open",
    ip=None,
    port=None,
    service=None,
    cve=None,
    kev=False,
    epss=None,
    confidence_reason="",
    metadata=None,
):
    """Construit un constat normalisé, identifiant stable inclus."""

    confidence = normalize_confidence(confidence)
    severity, capped = cap_severity(severity, confidence, evidence)

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    finding = {
        "finding_id": build_finding_id(asset, check, component or service or ""),
        "asset_id": asset,
        "ip": ip,
        "port": port,
        "service": service,
        "component": component,
        "check": check,
        "observation": observation,
        "evidence": evidence,
        "confidence": confidence,
        "confidence_reason": confidence_reason,
        "severity": severity,
        "severity_capped": capped,
        "exposure": exposure if exposure in EXPOSURES else "unknown",
        "references": list(references or []),
        "recommendation": recommendation,
        "status": status if status in STATUSES else "open",
        "first_seen": now,
        "last_seen": now,
        "cve": cve,
        "kev": bool(kev),
        "epss": epss,
    }

    if metadata:
        finding["metadata"] = metadata

    return finding
