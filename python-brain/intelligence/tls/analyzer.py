"""Audit TLS.

Les contrôles sont purs : ils prennent une négociation ou un certificat déjà
observé. La collecte réseau (`inspect`) reste séparée et n'est appelée que si
le mode actif et le périmètre autorisé le permettent.

L'analyse fine du certificat (chaîne, SAN, signature) est déléguée à
`testssl.sh` via l'adaptateur d'outils : stdlib seul ne parse pas X.509.
"""

import socket
import ssl
from datetime import datetime, timezone

from intelligence.models import make_finding

WEAK_PROTOCOLS = {
    "SSLv2": "critical",
    "SSLv3": "critical",
    "TLSv1": "high",
    "TLSv1.1": "high",
    "TLS 1.0": "high",
    "TLS 1.1": "high",
}

WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon")


def _parse_date(value):
    if not value:
        return None

    text = str(value).strip().replace("Z", "+00:00")

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def analyze_protocol(version, cipher=None, bits=0, asset=None, port=None, exposure="lan"):
    """Analyse une négociation TLS observée."""

    asset = asset or "unknown"
    findings = []

    severity = WEAK_PROTOCOLS.get(str(version or "").strip())

    if severity:
        findings.append(
            make_finding(
                asset=asset,
                ip=asset,
                port=port,
                check="tls.protocol",
                component="TLS",
                service="HTTPS",
                observation=f"Protocole obsolète accepté : {version}",
                evidence=f"handshake:{version}",
                confidence="confirmed",
                severity=severity,
                exposure=exposure,
                recommendation=(
                    "Désactiver les protocoles antérieurs à TLS 1.2 et "
                    "privilégier TLS 1.3."
                ),
                references=["https://testssl.sh/"],
            )
        )

    cipher_text = str(cipher or "")

    if cipher_text and any(marker.lower() in cipher_text.lower() for marker in WEAK_CIPHER_MARKERS):
        findings.append(
            make_finding(
                asset=asset,
                ip=asset,
                port=port,
                check="tls.cipher",
                component="TLS",
                service="HTTPS",
                observation=f"Suite cryptographique faible négociée : {cipher_text}",
                evidence=f"cipher:{cipher_text}",
                confidence="confirmed",
                severity="high",
                exposure=exposure,
                recommendation="Retirer les suites RC4/3DES/NULL et imposer des suites AEAD.",
                references=["https://testssl.sh/"],
            )
        )

    if isinstance(bits, int) and 0 < bits < 112:
        findings.append(
            make_finding(
                asset=asset,
                ip=asset,
                port=port,
                check="tls.key_exchange",
                component="TLS",
                service="HTTPS",
                observation=f"Force de chiffrement insuffisante ({bits} bits)",
                evidence=f"cipher_bits:{bits}",
                confidence="confirmed",
                severity="high",
                exposure=exposure,
                recommendation="Imposer une force de chiffrement d'au moins 128 bits.",
            )
        )

    return findings


def analyze_certificate(certificate, asset=None, port=None, exposure="lan"):
    """Analyse un certificat déjà décodé (testssl, magasin local, fixture)."""

    if not isinstance(certificate, dict):
        return []

    asset = asset or "unknown"
    findings = []
    not_after = _parse_date(certificate.get("not_after"))
    now = datetime.now(timezone.utc)

    if not_after:
        if not_after < now:
            days = (now - not_after).days

            findings.append(
                make_finding(
                    asset=asset,
                    ip=asset,
                    port=port,
                    check="tls.certificate_expired",
                    component="TLS",
                    service="HTTPS",
                    observation=f"Certificat expiré depuis {days} jour(s)",
                    evidence=f"not_after:{certificate.get('not_after')}",
                    confidence="confirmed",
                    severity="high",
                    exposure=exposure,
                    recommendation="Renouveler le certificat et automatiser son renouvellement.",
                )
            )
        elif (not_after - now).days <= 30:
            findings.append(
                make_finding(
                    asset=asset,
                    ip=asset,
                    port=port,
                    check="tls.certificate_expiring",
                    component="TLS",
                    service="HTTPS",
                    observation=f"Certificat expirant dans {(not_after - now).days} jour(s)",
                    evidence=f"not_after:{certificate.get('not_after')}",
                    confidence="confirmed",
                    severity="medium",
                    exposure=exposure,
                    recommendation="Planifier le renouvellement du certificat.",
                )
            )

    if certificate.get("self_signed") is True:
        findings.append(
            make_finding(
                asset=asset,
                ip=asset,
                port=port,
                check="tls.self_signed",
                component="TLS",
                service="HTTPS",
                observation="Certificat auto-signé",
                evidence="certificate:self_signed=true",
                confidence="confirmed",
                severity="medium",
                exposure=exposure,
                recommendation="Utiliser un certificat émis par une autorité de confiance.",
            )
        )

    key_size = certificate.get("key_size")

    if isinstance(key_size, int) and 0 < key_size < 2048:
        findings.append(
            make_finding(
                asset=asset,
                ip=asset,
                port=port,
                check="tls.weak_key",
                component="TLS",
                service="HTTPS",
                observation=f"Clé de {key_size} bits",
                evidence=f"key_size:{key_size}",
                confidence="confirmed",
                severity="high",
                exposure=exposure,
                recommendation="Utiliser une clé RSA d'au moins 2048 bits ou ECDSA P-256.",
            )
        )

    signature = str(certificate.get("signature_algorithm") or "").lower()

    if "sha1" in signature or "md5" in signature:
        findings.append(
            make_finding(
                asset=asset,
                ip=asset,
                port=port,
                check="tls.weak_signature",
                component="TLS",
                service="HTTPS",
                observation=f"Signature faible : {certificate.get('signature_algorithm')}",
                evidence=f"signature_algorithm:{certificate.get('signature_algorithm')}",
                confidence="confirmed",
                severity="high",
                exposure=exposure,
                recommendation="Réémettre le certificat avec SHA-256 ou mieux.",
            )
        )

    return findings


def inspect(ip, port, timeout=2.0):
    """Négocie TLS pour observer version et suite. Réseau : à autoriser."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with context.wrap_socket(raw) as connection:
            version = connection.version()
            cipher = connection.cipher()

    return {
        "version": version,
        "cipher": cipher[0] if cipher else None,
        "bits": cipher[2] if cipher else 0,
        "certificate": None,
    }
