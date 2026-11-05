"""Audit TLS du laboratoire.

Deux négociations indépendantes (TLS 1.2 et TLS 1.3) et une lecture de
certificat. Un échec de négociation n'est jamais présenté comme une absence
de TLS : le constat reste `to_verify`.

Le certificat DER est écrit dans un dossier temporaire 0700 et analysé par
`openssl x509` en arguments de liste, sans shell.
"""

import os
import socket
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from intelligence.models import make_finding
from intelligence.tls import analyzer as stable_analyzer
from security_intelligence.config import resolve_target

PROTOCOLS = (
    ("tls1.2", ssl.TLSVersion.TLSv1_2),
    ("tls1.3", ssl.TLSVersion.TLSv1_3),
)


def _context(version=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    if version is not None:
        context.minimum_version = version
        context.maximum_version = version

    return context


def _connect(ip, port, timeout, version=None):
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with _context(version).wrap_socket(raw) as connection:
            cipher = connection.cipher()

            return {
                "supported": True,
                "version": connection.version(),
                "cipher": cipher[0] if cipher else None,
                "bits": cipher[2] if cipher else 0,
                "certificate_der": connection.getpeercert(binary_form=True),
            }


def negotiate(ip, port, version, timeout=3.0):
    try:
        return _connect(ip, port, timeout, version=version)
    except (OSError, ValueError) as error:
        return {
            "supported": False,
            "error": f"{type(error).__name__}: {str(error)[:160]}",
        }


def _parse_openssl_date(value):
    text = str(value or "").strip()

    for pattern in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            parsed = datetime.strptime(text, pattern)
            return parsed.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue

    return None


def parse_openssl_output(text):
    """Analyse la sortie texte de `openssl x509 -noout ...`."""

    certificate = {
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "san": [],
        "self_signed": False,
    }

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if line.startswith("subject="):
            certificate["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            certificate["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            certificate["not_before"] = _parse_openssl_date(
                line.split("=", 1)[1]
            )
        elif line.startswith("notAfter="):
            certificate["not_after"] = _parse_openssl_date(line.split("=", 1)[1])
        elif line.startswith(("DNS:", "IP Address:")):
            certificate["san"].extend(
                item.strip() for item in line.split(",") if item.strip()
            )

    if certificate["subject"] and certificate["subject"] == certificate["issuer"]:
        certificate["self_signed"] = True

    return certificate


def read_certificate(ip, port, timeout=3.0):
    """Négocie, écrit le DER en 0600 et délègue le décodage à OpenSSL."""

    connection = _connect(ip, port, timeout)
    der = connection.get("certificate_der")

    if not der:
        return None, "certificat absent de la négociation"

    directory = tempfile.mkdtemp(prefix="nour-tls-")
    os.chmod(directory, 0o700)
    path = Path(directory) / "certificate.der"

    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

        with os.fdopen(descriptor, "wb") as handle:
            handle.write(der)

        try:
            process = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    "DER",
                    "-in",
                    str(path),
                    "-noout",
                    "-subject",
                    "-issuer",
                    "-dates",
                    "-ext",
                    "subjectAltName",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return None, f"openssl indisponible: {error}"

        if process.returncode != 0:
            return None, f"openssl: {process.stderr.strip()[:160]}"

        return parse_openssl_output(process.stdout), None
    finally:
        try:
            path.unlink()
        except OSError:
            pass

        try:
            os.rmdir(directory)
        except OSError:
            pass


def audit(target, port, timeout=3.0, allowed=()):
    """Audit TLS complet ; retourne `(findings, metadata, errors)`."""

    try:
        ip = resolve_target(target, allowed)[0]
    except PermissionError as error:
        return [], {}, [str(error)]

    results = {}
    errors = []

    for label, version in PROTOCOLS:
        results[label] = negotiate(ip, port, version, timeout=timeout)

    supported = [label for label, result in results.items() if result.get("supported")]

    findings = []
    certificate = None

    if not supported:
        details = "; ".join(
            f"{label}={result.get('error', 'échec')}"
            for label, result in results.items()
        )

        findings.append(
            make_finding(
                asset=target,
                ip=ip,
                port=port,
                service="TLS",
                component="TLS",
                check="tls.negotiation_failed",
                observation=(
                    "Aucune négociation TLS 1.2/1.3 n'a abouti ; le service "
                    "peut être absent, filtré ou restreint"
                ),
                evidence=f"tls_attempts:{details[:300]}",
                confidence="low",
                confidence_reason=(
                    "Un échec de négociation n'établit pas l'absence de TLS."
                ),
                severity="info",
                exposure="local",
                recommendation=(
                    "Vérifier que le service écoute et accepte TLS 1.2 ou 1.3."
                ),
                status="to_verify",
            )
        )
    else:
        certificate, error = read_certificate(ip, port, timeout=timeout)

        if error:
            errors.append(f"certificat {target}:{port}: {error}")
        elif certificate:
            findings.extend(
                stable_analyzer.analyze_certificate(
                    certificate,
                    asset=target,
                    port=port,
                    exposure="local",
                )
            )

    metadata = {
        "target": target,
        "ip": ip,
        "port": port,
        "protocols": {
            label: {
                "supported": result.get("supported"),
                "negotiated": result.get("version"),
                "cipher": result.get("cipher"),
                "bits": result.get("bits"),
                "error": result.get("error"),
            }
            for label, result in results.items()
        },
        "certificate": certificate,
        "note": (
            "TLS 1.0/1.1 et STARTTLS ne sont pas testés par cette bêta ; "
            "une négociation échouée ne prouve pas l'absence de TLS."
        ),
    }

    return findings, metadata, errors
