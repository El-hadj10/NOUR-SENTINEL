"""Orchestration des six capacités de sécurité (v0.5.0).

Ordre : constats réseau existants, inventaire local, corrélation CVE,
vérifications actives autorisées, politiques d'authentification, journaux,
puis outils externes optionnels. Le tout est dédoublonné et priorisé.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from detector import detect_threats
from intelligence import VERSION, risk_engine
from intelligence.applications import http_analyzer
from intelligence.fingerprinting import services
from intelligence.intrusion import detector as intrusion
from intelligence.models import make_finding
from intelligence.passwords import policy_audit
from intelligence.tls import analyzer as tls_analyzer
from intelligence.tools import adapters
from intelligence.vulnerabilities import correlator

CAPABILITIES = (
    "service_fingerprinting",
    "vulnerability_intelligence",
    "tls_audit",
    "password_policy_audit",
    "host_intrusion_detection",
    "application_security_analysis",
)

WILDCARD_ADDRESSES = ("0.0.0.0", "::", "[::]")

SENSITIVE_WILDCARD_PORTS = {
    22,
    23,
    445,
    2375,
    2376,
    3306,
    3389,
    5432,
    5900,
    6379,
    9200,
    11211,
}

CRITICAL_IF_WILDCARD = {23, 2375, 3306, 3389, 5900}

HTTP_PORTS = (80, 443, 3000, 8000, 8008, 8080, 8443, 8888, 9443)

TLS_PORTS = (443, 465, 636, 993, 995, 8443, 9443)


def _private_ipv4(text):
    parts = text.split(".")

    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return None

    first, second = int(parts[0]), int(parts[1])

    if first == 127:
        return "local"

    if first == 100 and 64 <= second <= 127:
        return "vpn"

    if first == 10:
        return "lan"

    if first == 172 and 16 <= second <= 31:
        return "lan"

    if first == 192 and second == 168:
        return "lan"

    if first == 169 and second == 254:
        return "lan"

    return None


def classify_exposure(address):
    """Exposition *présumée* d'une adresse d'écoute.

    Une écoute sur `0.0.0.0` ne prouve pas un accès depuis Internet : le
    pare-feu, le NAT et le routage peuvent limiter la portée.
    """

    text = str(address or "").strip()

    if not text:
        return "unknown"

    if text in ("::1", "0:0:0:0:0:0:0:1"):
        return "local"

    if text in WILDCARD_ADDRESSES:
        return "lan"

    lowered = text.lower()

    if lowered.startswith(("fe80:", "fc", "fd")):
        return "lan"

    private = _private_ipv4(text)

    if private:
        return private

    return "external"


def _read_text(path):
    try:
        return Path(str(path)).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def analyze_inventory(inventory, host):
    """Constats et produits identifiés à partir des sockets en écoute."""

    findings = []
    products = []

    if not isinstance(inventory, dict):
        return findings, products

    for listener in inventory.get("listeners") or []:
        if not isinstance(listener, dict):
            continue

        address = str(listener.get("address") or "")
        port = listener.get("port")

        if not isinstance(port, int) or isinstance(port, bool):
            continue

        exposure = classify_exposure(address)
        identity = services.identify_listener(listener)

        if identity:
            products.append(
                {
                    **identity,
                    "asset": host,
                    "ip": address,
                    "port": port,
                    "exposure": exposure,
                }
            )
            findings.append(
                make_finding(
                    asset=host,
                    ip=address,
                    port=port,
                    service=identity["service"],
                    component=identity["product"],
                    check="service.identified",
                    observation=(
                        f"{identity['product']} est à l'écoute sur {address}:{port}"
                    ),
                    evidence=identity["evidence"],
                    confidence="confirmed",
                    severity="info",
                    exposure=exposure,
                    recommendation=(
                        "Vérifier la version, la configuration effective et la "
                        "nécessité de cette exposition."
                    ),
                    metadata={
                        "unit": listener.get("unit"),
                        "container": listener.get("container"),
                    },
                )
            )

        if address in WILDCARD_ADDRESSES and port in SENSITIVE_WILDCARD_PORTS:
            severity = "high" if port in CRITICAL_IF_WILDCARD else "medium"

            findings.append(
                make_finding(
                    asset=host,
                    ip=address,
                    port=port,
                    service=(identity or {}).get("service"),
                    component=(identity or {}).get("product") or "service",
                    check=f"exposure.wildcard.{port}",
                    observation=(
                        f"Écoute sur l'interface générique (port {port}), "
                        "potentiellement joignable depuis plusieurs réseaux"
                    ),
                    evidence=(
                        f"socket:{address}:{port}; pid={listener.get('pid')}; "
                        f"process={listener.get('process')}; "
                        f"unit={listener.get('unit')}"
                    ),
                    confidence="confirmed",
                    confidence_reason=(
                        "L'exposition réelle dépend du pare-feu, du NAT, du "
                        "routage et des règles IPv6."
                    ),
                    severity=severity,
                    exposure="lan",
                    recommendation=(
                        "Restreindre l'écoute à l'interface nécessaire et "
                        "vérifier les règles de filtrage IPv4 et IPv6."
                    ),
                )
            )

        if port == 2375:
            findings.append(
                make_finding(
                    asset=host,
                    ip=address,
                    port=port,
                    service="docker",
                    component="Docker Engine",
                    check="docker.api_plaintext",
                    observation="API Docker exposée sans TLS",
                    evidence=f"socket:{address}:{port}",
                    confidence="confirmed",
                    severity="high",
                    exposure=classify_exposure(address),
                    recommendation=(
                        "Ne jamais exposer l'API Docker en clair ; utiliser le "
                        "socket Unix local ou TLS mutuel."
                    ),
                )
            )
        elif port == 2376:
            findings.append(
                make_finding(
                    asset=host,
                    ip=address,
                    port=port,
                    service="docker",
                    component="Docker Engine",
                    check="docker.api_tls",
                    observation="API Docker exposée en TLS",
                    evidence=f"socket:{address}:{port}",
                    confidence="confirmed",
                    severity="medium",
                    exposure=classify_exposure(address),
                    recommendation=(
                        "Vérifier l'authentification mutuelle et la gestion des "
                        "certificats clients."
                    ),
                )
            )

        if not listener.get("process") and not listener.get("container"):
            findings.append(
                make_finding(
                    asset=host,
                    ip=address,
                    port=port,
                    component="unknown",
                    check=f"inventory.attribution.{port}",
                    observation=(
                        f"Socket en écoute non attribué (port {port})"
                    ),
                    evidence=(
                        f"socket:{address}:{port}; pid=inconnu "
                        "(permissions ou socket sans processus visible)"
                    ),
                    confidence="low",
                    confidence_reason=(
                        "Les sockets d'autres utilisateurs ne sont pas visibles "
                        "sans privilèges suffisants."
                    ),
                    severity="info",
                    exposure=classify_exposure(address),
                    recommendation=(
                        "Relancer avec les privilèges nécessaires pour attribuer "
                        "le socket à son processus."
                    ),
                )
            )

    return findings, products


def active_checks(inventory, config, authorized, host):
    """Vérifications réseau actives, strictement limitées au périmètre."""

    findings = []

    if not isinstance(config, dict) or not config.get("active_probing"):
        return findings

    allowed = {str(item) for item in (authorized or [])}

    try:
        timeout = max(0.1, float(config.get("banner_timeout_ms") or 800) / 1000)
    except (TypeError, ValueError):
        timeout = 0.8

    for listener in inventory.get("listeners") or []:
        if not isinstance(listener, dict):
            continue

        ip = str(listener.get("address") or "")
        port = listener.get("port")

        if not isinstance(port, int) or ip not in allowed:
            continue

        exposure = classify_exposure(ip)

        if config.get("http_probe") and port in HTTP_PORTS:
            try:
                response = http_analyzer.probe_http(ip, port, timeout)
            except OSError:
                continue

            findings.extend(
                http_analyzer.analyze_response(
                    response, asset=host, ip=ip, port=port, exposure=exposure
                )
            )

        if config.get("tls_probe") and port in TLS_PORTS:
            try:
                negotiation = tls_analyzer.inspect(ip, port, timeout)
            except (OSError, ValueError):
                continue

            findings.extend(
                tls_analyzer.analyze_protocol(
                    negotiation.get("version"),
                    negotiation.get("cipher"),
                    negotiation.get("bits") or 0,
                    asset=host,
                    port=port,
                    exposure=exposure,
                )
            )

    return findings


def _ssh_policy_findings(config, host):
    if not isinstance(config, dict) or not config.get("ssh_policy_audit"):
        return [], []

    path = config.get("sshd_config_path") or "/etc/ssh/sshd_config"
    text = _read_text(path)

    if text is None:
        return [], [f"sshd_config illisible: {path}"]

    findings = policy_audit.audit_ssh_policy(
        policy_audit.parse_sshd_config(text), asset=host
    )

    login_defs_path = config.get("login_defs_path") or "/etc/login.defs"
    login_defs = _read_text(login_defs_path)

    if login_defs is not None:
        findings.extend(policy_audit.audit_login_defs(login_defs, asset=host))

    return findings, []


def _journal_findings(config, host):
    if not isinstance(config, dict) or not config.get("journal_audit"):
        return [], []

    try:
        lines = max(1, int(config.get("journal_lines") or 200))
    except (TypeError, ValueError):
        lines = 200

    command = ["journalctl", "-o", "json", "-n", str(lines), "--no-pager"]

    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as error:
        return [], [f"journalctl: {error}"]

    if process.returncode != 0:
        return [], [f"journalctl: {process.stderr.strip()[:200]}"]

    entries = intrusion.parse_journal_lines(process.stdout.splitlines())

    return intrusion.detect(entries, host=host), []


def _nmap_findings(ip, ports, host):
    if not adapters.available("nmap"):
        return [], ["nmap introuvable"]

    result = adapters.run_tool(adapters.build_nmap_command(ip, ports), timeout=120)

    if result["returncode"] != 0:
        return [], [f"nmap {ip}: {result['stderr'][:160]}"]

    services_found = adapters.parse_nmap_xml(result["stdout"])

    return (
        adapters.findings_from_nmap(
            services_found, asset=host, ip=ip, exposure=classify_exposure(ip)
        ),
        [],
    )


def _testssl_findings(ip, port, host):
    if not adapters.available("testssl"):
        return [], ["testssl.sh introuvable"]

    with tempfile.TemporaryDirectory() as directory:
        output_path = Path(directory) / "testssl.json"

        result = adapters.run_tool(
            adapters.build_testssl_command(ip, port, str(output_path)), timeout=120
        )

        if not output_path.exists():
            return [], [
                f"testssl {ip}:{port}: aucune sortie JSON "
                f"({result['stderr'][:120]})"
            ]

        try:
            document = json.loads(
                output_path.read_text(encoding="utf-8", errors="replace")
            )
        except ValueError as error:
            return [], [f"testssl {ip}:{port}: JSON invalide ({error})"]

    return (
        adapters.findings_from_testssl(
            document, asset=host, ip=ip, port=port, exposure=classify_exposure(ip)
        ),
        [],
    )


def _trivy_findings(targets, host):
    if not adapters.available("trivy"):
        return [], ["trivy introuvable"]

    findings = []
    errors = []

    for target in targets or []:
        text = str(target).strip()

        if not text:
            continue

        command = (
            adapters.build_trivy_fs_command(text)
            if Path(text).exists()
            else adapters.build_trivy_image_command(text)
        )
        result = adapters.run_tool(command, timeout=180)

        if result["returncode"] != 0:
            errors.append(f"trivy {text}: {result['stderr'][:160]}")
            continue

        try:
            document = json.loads(result["stdout"])
        except ValueError as error:
            errors.append(f"trivy {text}: JSON invalide ({error})")
            continue

        findings.extend(
            adapters.findings_from_trivy(
                document, asset=host, target=text, exposure="lan"
            )
        )

    return findings, errors


def collect_tool_findings(tools_config, inventory, authorized, host):
    """Exécute les outils activés, uniquement sur le périmètre autorisé."""

    findings = []
    errors = []
    used = []

    if not isinstance(tools_config, dict) or not tools_config.get("enabled"):
        return findings, used, errors

    allowed = {str(item) for item in (authorized or [])}
    listeners = [
        listener
        for listener in inventory.get("listeners") or []
        if isinstance(listener, dict) and str(listener.get("address")) in allowed
    ]

    if tools_config.get("nmap"):
        for listener in listeners:
            port = listener.get("port")
            ip = str(listener.get("address"))

            if not isinstance(port, int):
                continue

            found, failed = _nmap_findings(ip, [port], host)
            findings.extend(found)
            errors.extend(failed)

            if found and "nmap" not in used:
                used.append("nmap")

    if tools_config.get("testssl"):
        for listener in listeners:
            port = listener.get("port")
            ip = str(listener.get("address"))

            if not isinstance(port, int) or port not in TLS_PORTS:
                continue

            found, failed = _testssl_findings(ip, port, host)
            findings.extend(found)
            errors.extend(failed)

            if found and "testssl" not in used:
                used.append("testssl")

    targets = tools_config.get("trivy_targets") or []

    if tools_config.get("trivy") and targets:
        found, failed = _trivy_findings(targets, host)
        findings.extend(found)
        errors.extend(failed)

        if found and "trivy" not in used:
            used.append("trivy")

    return findings, used, errors


def _normalize_legacy(findings, host):
    """Convertit les constats v0.4.x au modèle normalisé v0.5.0."""

    normalized = []

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        if "finding_id" in finding:
            normalized.append(finding)
            continue

        ip = finding.get("ip") or host
        port = finding.get("port")

        normalized.append(
            make_finding(
                asset=ip,
                ip=ip,
                port=port,
                service=finding.get("service"),
                component=finding.get("service"),
                check=f"exposure.port.{port}",
                observation=finding.get("message", ""),
                evidence=finding.get("evidence", "port_open"),
                confidence=finding.get("confidence", "low"),
                severity=finding.get("severity", "info"),
                exposure=classify_exposure(ip),
                recommendation=finding.get("recommendation", ""),
                metadata={
                    "origin": "network_scan",
                    "legacy_risk_level": finding.get("risk_level"),
                },
            )
        )

    return normalized


def _dedupe_products(products):
    seen = set()
    result = []

    for product in products:
        key = (product.get("product"), product.get("port"), product.get("ip"))

        if key in seen:
            continue

        seen.add(key)
        result.append(product)

    return result


def analyze(payload):
    """Point d'entrée unique : payload JSON Rust -> rapport de sécurité."""

    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object")

    events = payload.get("events") if isinstance(payload.get("events"), list) else []
    devices = payload.get("devices") if isinstance(payload.get("devices"), list) else []
    inventory = (
        payload.get("inventory") if isinstance(payload.get("inventory"), dict) else {}
    )
    analysis_config = (
        payload.get("analysis_config")
        if isinstance(payload.get("analysis_config"), dict)
        else {}
    )
    intelligence_config = (
        payload.get("intelligence_config")
        if isinstance(payload.get("intelligence_config"), dict)
        else {}
    )
    tools_config = (
        payload.get("tools_config")
        if isinstance(payload.get("tools_config"), dict)
        else {}
    )
    authorized = (
        payload.get("authorized_targets")
        if isinstance(payload.get("authorized_targets"), list)
        else []
    )

    host = str(inventory.get("hostname") or "localhost")

    findings = _normalize_legacy(detect_threats(events, analysis_config), host)

    inventory_findings, products = analyze_inventory(inventory, host)
    findings.extend(inventory_findings)
    findings.extend(correlator.correlate(products))

    findings.extend(active_checks(inventory, intelligence_config, authorized, host))

    errors = []

    ssh_findings, ssh_errors = _ssh_policy_findings(intelligence_config, host)
    findings.extend(ssh_findings)
    errors.extend(ssh_errors)

    journal_findings, journal_errors = _journal_findings(intelligence_config, host)
    findings.extend(journal_findings)
    errors.extend(journal_errors)

    tool_findings, tools_used, tool_errors = collect_tool_findings(
        tools_config, inventory, authorized, host
    )
    findings.extend(tool_findings)
    errors.extend(tool_errors)

    findings = risk_engine.prioritize(risk_engine.deduplicate(findings))

    open_ports = [
        event
        for event in events
        if isinstance(event, dict) and event.get("state") == "open"
    ]

    return {
        "engine": "NOUR SENTINEL",
        "version": VERSION,
        "source": payload.get("source", "unknown"),
        "capabilities": list(CAPABILITIES),
        "network": {
            "neighbors_discovered": len(devices),
            "ports_observed": len(events),
            "open_ports": len(open_ports),
        },
        "inventory": {
            "hostname": inventory.get("hostname"),
            "kernel": inventory.get("kernel"),
            "distribution": inventory.get("distribution"),
            "interfaces": inventory.get("interfaces") or [],
            "listeners_count": len(inventory.get("listeners") or []),
            "listeners": inventory.get("listeners") or [],
        },
        "services": _dedupe_products(products),
        "devices": devices,
        "findings_count": len(findings),
        "findings": findings,
        "risk_summary": risk_engine.summarize(findings),
        "tools_used": tools_used,
        "errors": errors,
        "status": "analysis_completed",
    }
