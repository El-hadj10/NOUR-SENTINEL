"""Adaptateurs pour outils externes puissants.

Trois outils, tous optionnels et désactivés par défaut :

- `nmap` : détection de version (`-sV --version-light`) sur une cible autorisée ;
- `testssl.sh` : audit TLS approfondi et certificats ;
- `trivy` : vulnérabilités d'images et de systèmes de fichiers.

Règles : jamais de shell, arguments en liste, cible issue d'un périmètre
autorisé, sortie JSON/XML parsée hors ligne dans les tests.
"""

import json
import shutil
import subprocess
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from intelligence.models import make_finding
from security_intelligence import collection_trace

EXECUTABLES = {"nmap": "nmap", "testssl": "testssl.sh", "trivy": "trivy"}

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
    "WARN": "medium",
    "WARNING": "medium",
    "INFO": "info",
    "OK": None,
}


def available(tool):
    executable = EXECUTABLES.get(tool, tool)

    return shutil.which(executable) is not None


def build_nmap_command(target, ports):
    port_list = ",".join(str(int(port)) for port in ports)

    return [
        "nmap",
        "-sV",
        "--version-light",
        "-Pn",
        "-p",
        port_list,
        str(target),
    ]


def build_testssl_command(target, port, output_path):
    return [
        "testssl.sh",
        "--quiet",
        "--jsonfile-pretty",
        str(output_path),
        f"{target}:{int(port)}",
    ]


def build_trivy_image_command(image):
    return ["trivy", "image", "--quiet", "--format", "json", str(image)]


def build_trivy_fs_command(path):
    return [
        "trivy",
        "fs",
        "--quiet",
        "--format",
        "json",
        "--scanners",
        "vuln,config",
        str(path),
    ]


@collection_trace.instrument("tool", "adapters.run_tool")
def run_tool(argv, timeout=120):
    """Exécute un outil sans shell. Ne lève jamais pour un code non nul."""

    try:
        process = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return {"returncode": -1, "stdout": "", "stderr": str(error)}

    return {
        "returncode": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }


def parse_nmap_xml(text):
    """Retourne les services découverts, sans interprétation de vulnérabilité."""

    services = []

    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return services

    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr") if address is not None else None

        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")

            if state is None or state.get("state") != "open":
                continue

            services.append(
                {
                    "ip": ip,
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "extrainfo": service.get("extrainfo") if service is not None else None,
                }
            )

    return services


def findings_from_nmap(services, asset="localhost", ip=None, exposure="lan"):
    findings = []

    for service in services or []:
        product = service.get("product") or service.get("service")

        if not product:
            continue

        version = service.get("version")
        label = " ".join(
            part for part in (product, version, service.get("extrainfo")) if part
        )

        findings.append(
            make_finding(
                asset=asset,
                ip=service.get("ip") or ip,
                port=service.get("port"),
                service=service.get("service"),
                component=product,
                check="tool.nmap_service",
                observation=f"Service identifié par nmap : {label}",
                evidence=f"nmap:-sV:{label}",
                confidence="corroborated",
                severity="info",
                exposure=exposure,
                recommendation=(
                    "Corréler ce produit et cette version avec les avis de sécurité."
                ),
                references=["https://nmap.org/book/man-version-detection.html"],
            )
        )

    return findings


def _load_json(document):
    if isinstance(document, (dict, list)):
        return document

    try:
        return json.loads(document)
    except (TypeError, ValueError):
        return None


def parse_testssl_json(document):
    data = _load_json(document)

    if isinstance(data, dict):
        data = data.get("scanResult", [data])

    return data if isinstance(data, list) else []


def findings_from_testssl(document, asset="localhost", ip=None, port=None, exposure="lan"):
    findings = []

    for entry in parse_testssl_json(document):
        if not isinstance(entry, dict):
            continue

        severity = SEVERITY_MAP.get(str(entry.get("severity", "")).upper())

        if not severity:
            continue

        identifier = str(entry.get("id") or "finding")
        detail = str(entry.get("finding") or "").strip()

        findings.append(
            make_finding(
                asset=asset,
                ip=ip,
                port=port,
                service="HTTPS",
                component="TLS",
                check=f"tls.testssl.{identifier}",
                observation=detail[:300] or f"testssl: {identifier}",
                evidence=f"testssl.sh:{identifier}",
                confidence="confirmed",
                severity=severity,
                exposure=exposure,
                recommendation="Corriger la configuration TLS signalée par testssl.sh.",
                references=["https://testssl.sh/"],
                metadata={"testssl_severity": entry.get("severity")},
            )
        )

    return findings


def findings_from_trivy(document, asset="localhost", target=None, exposure="lan"):
    data = _load_json(document) or {}
    findings = []

    for result in data.get("Results", []) if isinstance(data, dict) else []:
        for vulnerability in result.get("Vulnerabilities") or []:
            identifier = vulnerability.get("VulnerabilityID")
            severity = SEVERITY_MAP.get(
                str(vulnerability.get("Severity", "")).upper(), "medium"
            )

            if not identifier:
                continue

            package = vulnerability.get("PkgName")
            installed = vulnerability.get("InstalledVersion")
            fixed = vulnerability.get("FixedVersion")

            findings.append(
                make_finding(
                    asset=asset,
                    component=package,
                    check=f"cve.{identifier}",
                    observation=(
                        vulnerability.get("Title")
                        or f"{package} {installed} présente {identifier}"
                    )[:300],
                    evidence=(
                        f"trivy:{target or result.get('Target')}; "
                        f"installed={installed}; fixed={fixed or 'unknown'}"
                    ),
                    confidence="confirmed",
                    severity=severity,
                    exposure=exposure,
                    recommendation=(
                        f"Mettre à jour {package} vers {fixed} ou appliquer le correctif fournisseur."
                        if fixed
                        else f"Mettre à jour {package} ou appliquer le correctif fournisseur."
                    ),
                    references=[vulnerability.get("PrimaryURL")]
                    if vulnerability.get("PrimaryURL")
                    else [],
                    status="open",
                    cve=identifier,
                    metadata={
                        "installed_version": installed,
                        "fixed_version": fixed,
                        "target": target,
                    },
                )
            )

    return findings


def tool_available_for_tests():
    """Petit utilitaire de diagnostic, sans exécution."""

    return {name: available(name) for name in EXECUTABLES}


def image_reference(path):
    """Distingue une image d'un chemin local, sans deviner davantage."""

    return not Path(str(path)).exists()
