"""Analyse applicative HTTP non destructive (pilier 6).

Analyse des en-têtes, cookies et méthodes déjà observés. Aucune injection,
aucune tentative de contournement, aucune requête répétée.
"""

import http.client
import re
import ssl

from intelligence.models import make_finding

SECURITY_HEADERS = (
    (
        "strict-transport-security",
        "medium",
        "HSTS absent",
        "Ajouter Strict-Transport-Security avec une durée suffisante.",
    ),
    (
        "content-security-policy",
        "medium",
        "CSP absente",
        "Définir une Content-Security-Policy adaptée aux contenus servis.",
    ),
    (
        "x-content-type-options",
        "low",
        "X-Content-Type-Options absent",
        "Ajouter X-Content-Type-Options: nosniff.",
    ),
    (
        "x-frame-options",
        "low",
        "X-Frame-Options absent",
        "Ajouter X-Frame-Options ou la directive frame-ancestors.",
    ),
    (
        "referrer-policy",
        "info",
        "Referrer-Policy absente",
        "Définir une politique de référent restrictive.",
    ),
)

SERVER_VERSION = re.compile(r"(?P<product>[A-Za-z][\w-]*)/(?P<version>[0-9][\w.]*)")


def _normalize_headers(headers):
    return {
        str(key).strip().lower(): str(value)
        for key, value in (headers or {}).items()
    }


def _finding(asset, ip, port, check, observation, evidence, severity, recommendation, confidence="confirmed", exposure="lan"):
    return make_finding(
        asset=asset,
        ip=ip,
        port=port,
        check=f"http.{check}",
        component="HTTP",
        service="HTTP",
        observation=observation,
        evidence=evidence,
        confidence=confidence,
        severity=severity,
        exposure=exposure,
        recommendation=recommendation,
    )


def analyze_headers(headers, asset="localhost", ip=None, port=None, exposure="lan"):
    """En-têtes de sécurité manquants ou révélateurs."""

    normalized = _normalize_headers(headers)
    findings = []

    for name, severity, observation, recommendation in SECURITY_HEADERS:
        if name in normalized:
            continue

        findings.append(
            _finding(
                asset,
                ip,
                port,
                f"header.{name}",
                observation,
                f"header:{name}=absent",
                severity,
                recommendation,
                exposure=exposure,
            )
        )

    server = normalized.get("server", "")
    match = SERVER_VERSION.search(server)

    if match:
        findings.append(
            _finding(
                asset,
                ip,
                port,
                "server_version_disclosure",
                f"Version du serveur divulguée : {match.group(0)}",
                f"header:Server={server[:120]}",
                "info",
                "Masquer la version exacte du serveur dans les en-têtes de réponse.",
                exposure=exposure,
            )
        )

    if normalized.get("access-control-allow-origin", "").strip() == "*":
        if normalized.get("access-control-allow-credentials", "").lower() == "true":
            findings.append(
                _finding(
                    asset,
                    ip,
                    port,
                    "cors_wildcard_credentials",
                    "CORS autorise toutes les origines avec identifiants",
                    "header:Access-Control-Allow-Origin=*; Access-Control-Allow-Credentials=true",
                    "high",
                    "Restreindre l'origine autorisée et ne jamais combiner * avec les identifiants.",
                    exposure=exposure,
                )
            )

    return findings


def analyze_cookies(set_cookie_values, asset="localhost", ip=None, port=None, exposure="lan"):
    """Contrôle des attributs de sécurité des cookies observés."""

    if isinstance(set_cookie_values, str):
        values = [set_cookie_values]
    else:
        values = list(set_cookie_values or [])

    findings = []

    for value in values:
        text = str(value)
        attributes = {
            part.strip().split("=", 1)[0].lower()
            for part in text.split(";")
            if part.strip()
        }

        name = text.split("=", 1)[0].strip() or "cookie"
        missing = [
            attribute
            for attribute in ("httponly", "secure", "samesite")
            if attribute not in attributes
        ]

        if not missing:
            continue

        findings.append(
            _finding(
                asset,
                ip,
                port,
                f"cookie.{name}",
                f"Cookie {name} sans attribut(s) {', '.join(missing)}",
                f"set-cookie:{name}",
                "low" if "httponly" not in missing else "medium",
                "Ajouter HttpOnly, Secure et SameSite selon l'usage du cookie.",
                exposure=exposure,
            )
        )

    return findings


def analyze_methods(methods, asset="localhost", ip=None, port=None, exposure="lan"):
    """Méthodes HTTP autorisées (résultat d'un OPTIONS ou d'un scan externe)."""

    allowed = {str(method).strip().upper() for method in (methods or [])}
    findings = []

    if allowed & {"TRACE", "TRACK"}:
        findings.append(
            _finding(
                asset,
                ip,
                port,
                "method.trace",
                "Méthode TRACE/TRACK autorisée",
                f"methods:{', '.join(sorted(allowed))}",
                "medium",
                "Désactiver TRACE et TRACK sur le serveur.",
                exposure=exposure,
            )
        )

    if allowed & {"PUT", "DELETE"}:
        findings.append(
            _finding(
                asset,
                ip,
                port,
                "method.write",
                "Méthodes d'écriture autorisées sans contrôle observé",
                f"methods:{', '.join(sorted(allowed))}",
                "low",
                "Vérifier l'authentification et les autorisations de ces méthodes.",
                confidence="probable",
                exposure=exposure,
            )
        )

    return findings


def analyze_response(response, asset="localhost", ip=None, port=None, exposure="lan"):
    """Analyse un dictionnaire de réponse déjà collecté."""

    if not isinstance(response, dict):
        return []

    findings = []
    findings.extend(
        analyze_headers(
            response.get("headers") or {},
            asset=asset,
            ip=ip,
            port=port,
            exposure=exposure,
        )
    )
    findings.extend(
        analyze_cookies(
            response.get("set_cookie") or response.get("cookies"),
            asset=asset,
            ip=ip,
            port=port,
            exposure=exposure,
        )
    )
    findings.extend(
        analyze_methods(
            response.get("methods"),
            asset=asset,
            ip=ip,
            port=port,
            exposure=exposure,
        )
    )

    return findings


def probe_http(ip, port, timeout=1.0, path="/", use_tls=None):
    """Requête HEAD unique. À n'appeler que sur une cible autorisée."""

    secure = use_tls if use_tls is not None else port in (443, 8443, 9443)

    if secure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            ip, port, timeout=timeout, context=context
        )
    else:
        connection = http.client.HTTPConnection(ip, port, timeout=timeout)

    try:
        connection.request(
            "HEAD", path, headers={"User-Agent": "NOUR-SENTINEL/0.5"}
        )
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}

        return {
            "status": response.status,
            "headers": headers,
            "set_cookie": response.getheader("Set-Cookie"),
            "methods": None,
            "url": f"{'https' if secure else 'http'}://{ip}:{port}{path}",
        }
    finally:
        connection.close()
