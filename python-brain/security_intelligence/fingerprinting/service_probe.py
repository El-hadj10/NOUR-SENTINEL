"""Sondes protocolaires uniques, exclusivement sur cible autorisée.

Une bannière est auto-déclarée : confiance `probable`, jamais `confirmed`.
Aucun corps HTTP n'est téléchargé, aucune redirection n'est suivie.
"""

import ssl

from intelligence.applications import http_analyzer
from intelligence.fingerprinting import services
from intelligence.models import make_finding
from security_intelligence.config import resolve_target


def _identity_findings(identities, target, ip, port):
    findings = []

    for identity in identities:
        findings.append(
            make_finding(
                asset=target,
                ip=ip,
                port=port,
                service=identity.get("service"),
                component=identity.get("product"),
                check="service.banner",
                observation=(
                    f"{identity.get('product')} "
                    f"{identity.get('version') or '(version non déclarée)'} "
                    f"identifié par bannière"
                ),
                evidence=identity.get("evidence", ""),
                confidence="probable",
                confidence_reason=(
                    "Une bannière est auto-déclarée : elle ne prouve ni le "
                    "binaire exact ni l'absence de correctif rétroporté."
                ),
                severity="info",
                exposure="local",
                recommendation=(
                    "Vérifier la version du paquet installé et les correctifs "
                    "de la distribution."
                ),
            )
        )

    return findings


def probe_ssh(target, port=22, timeout=2.0, allowed=()):
    """Lit une bannière SSH, sans tentative d'authentification."""

    try:
        ip = resolve_target(target, allowed)[0]
    except PermissionError as error:
        return [], [str(error)]

    try:
        banner = services.probe_banner(ip, port, timeout=timeout)
    except OSError as error:
        return [], [f"bannière SSH {target}:{port}: {error}"]

    if not banner.strip():
        return [], [f"bannière SSH {target}:{port}: aucune réponse"]

    return _identity_findings(
        services.identify_banner(banner), target, ip, port
    ), []


def probe_http(target, port, path="/", timeout=2.0, allowed=(), use_tls=None):
    """Requête HEAD unique ; aucune redirection suivie, aucun corps lu."""

    try:
        ip = resolve_target(target, allowed)[0]
    except PermissionError as error:
        return [], [str(error)]

    try:
        response = http_analyzer.probe_http(
            ip, port, timeout=timeout, path=path, use_tls=use_tls
        )
    except (OSError, ssl.SSLError) as error:
        return [], [f"HTTP HEAD {target}:{port}: {error}"]

    findings = http_analyzer.analyze_response(
        response,
        asset=target,
        ip=ip,
        port=port,
        exposure="local",
    )

    headers = response.get("headers") or {}
    banner_material = " ".join(
        str(headers.get(name) or "")
        for name in ("server", "x-powered-by")
        if headers.get(name)
    )

    findings.extend(
        _identity_findings(
            services.identify_banner(banner_material), target, ip, port
        )
    )

    return findings, []
