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
import authz
from intelligence import VERSION, risk_engine
from version import CORE_VERSION, LAB_VERSION, PROTOCOL_VERSION
from intelligence.applications import http_analyzer
from intelligence.fingerprinting import services
from intelligence.intrusion import detector as intrusion
from intelligence.models import make_finding
from intelligence.passwords import policy_audit
from intelligence.tls import analyzer as tls_analyzer
from intelligence.tools import adapters
from intelligence.vulnerabilities import correlator
from security_intelligence import collection_trace

CAPABILITIES = (
    "service_fingerprinting",
    "vulnerability_intelligence",
    "tls_audit",
    "password_policy_audit",
    "host_intrusion_detection",
    "application_security_analysis",
)

WILDCARD_ADDRESSES = frozenset({"0.0.0.0", "::"})

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


def normalize_address(address):
    """Normalise les formes IPv4/IPv6 d'une adresse d'écoute.

    `::`, `[::]`, `0:0:0:0:0:0:0:0`, `::0` et `0.0.0.0` désignent tous une
    écoute générique. Les adresses IPv4 mappées sont ramenées à leur forme
    IPv4 pour que la classification reste identique quelle que soit la
    famille de socket rapportée par le noyau.
    """

    text = str(address or "").strip().lower()

    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]

    if text.startswith("::ffff:") and "." in text:
        text = text[len("::ffff:") :]

    if text in ("0:0:0:0:0:0:0:0", "::0"):
        text = "::"
    elif text == "0:0:0:0:0:0:0:1":
        text = "::1"

    return text


def is_wildcard_address(address):
    return normalize_address(address) in WILDCARD_ADDRESSES


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

    text = normalize_address(address)

    if not text:
        return "unknown"

    if text == "::1":
        return "local"

    if text in WILDCARD_ADDRESSES:
        return "lan"

    if text.startswith(("fe80:", "fc", "fd")):
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

        if is_wildcard_address(address) and port in SENSITIVE_WILDCARD_PORTS:
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


@collection_trace.instrument("tcp", "engine.active_checks")
def active_checks(inventory, config, authorized, host):
    """Vérifications réseau actives, strictement limitées au périmètre."""

    authz.require()
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


@collection_trace.instrument("system", "engine._journal_findings")
def _journal_findings(config, host):
    """Constats journald, erreurs et nombre d'entrées réellement analysées.

    Le troisième élément permet de distinguer un ``journalctl`` muet (zéro
    entrée) d'une lecture qui a produit des événements exploitables : sans
    lui, une lecture vide serait présentée comme terminée.
    """

    if not isinstance(config, dict) or not config.get("journal_audit"):
        return [], [], 0

    try:
        lines = max(1, int(config.get("journal_lines") or 200))
    except (TypeError, ValueError):
        lines = 200

    command = ["journalctl", "-o", "json", "-n", str(lines), "--no-pager"]

    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as error:
        return [], [f"journalctl: {error}"], 0

    if process.returncode != 0:
        return [], [f"journalctl: {process.stderr.strip()[:200]}"], 0

    entries = intrusion.parse_journal_lines(process.stdout.splitlines())

    return intrusion.detect(entries, host=host), [], len(entries)


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


@collection_trace.instrument("tool", "engine.collect_tool_findings")
def collect_tool_findings(tools_config, inventory, authorized, host):
    """Exécute les outils activés, uniquement sur le périmètre autorisé."""

    authz.require()
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


def capability_status(
    intelligence_config,
    inventory,
    authorized,
    products,
    tools_used,
    findings=None,
    errors=None,
    journal_entries=None,
):
    """Statut réel des six capacités pour cette exécution.

    Les six états sont : ``started`` (lancement sans preuve de fin),
    ``completed`` (collecte terminée avec résultat exploitable), ``failed``
    (erreur d'exécution), ``disabled`` (configuration), ``no_data`` (aucune
    cible/produit) et ``blocked_missing_permission`` (privilège manquant).

    Un démarrage n'est jamais présenté comme un succès : ``completed`` exige
    une donnée produite (socket, produit, constat) ou une lecture terminée
    avec des événements exploitables. ``journal_entries`` porte le nombre
    d'entrées journald réellement analysées ; ``None`` signifie « non
    transmis » et interdit de conclure à un succès.
    """

    config = intelligence_config if isinstance(intelligence_config, dict) else {}
    listeners = [
        listener
        for listener in (inventory or {}).get("listeners") or []
        if isinstance(listener, dict)
    ]
    allowed = {str(item) for item in (authorized or [])}
    in_scope = [
        listener
        for listener in listeners
        if str(listener.get("address") or "") in allowed
    ]
    http_targets = [
        listener for listener in in_scope if listener.get("port") in HTTP_PORTS
    ]
    tls_targets = [
        listener for listener in in_scope if listener.get("port") in TLS_PORTS
    ]
    active = bool(config.get("active_probing"))
    used = {str(item) for item in tools_used or []}
    findings = [item for item in findings or [] if isinstance(item, dict)]
    errors = [str(item) for item in errors or []]

    permission_markers = (
        "permission denied",
        "operation not permitted",
        "not permitted",
        "accès refusé",
        "acces refuse",
        "eacces",
        "privilège",
        "privilege",
        "requires root",
        "root privileges",
    )

    def entry(status, reason):
        return {"status": status, "reason": reason}

    def error_status(tokens):
        matched = [
            error
            for error in errors
            if any(token in error.lower() for token in tokens)
        ]

        if not matched:
            return None

        if any(
            marker in error.lower()
            for error in matched
            for marker in permission_markers
        ):
            return "blocked_missing_permission"

        return "failed"

    def has_finding(prefixes):
        return any(
            str(item.get("check") or "").startswith(prefixes)
            for item in findings
        )

    statuses = {}

    nmap_status = error_status(("nmap",))

    if listeners:
        statuses["service_fingerprinting"] = entry(
            "completed",
            f"{len(listeners)} socket(s) analysé(s) ; attribution locale",
        )
    elif nmap_status:
        statuses["service_fingerprinting"] = entry(
            nmap_status, "nmap n'a pas produit de résultat exploitable"
        )
    else:
        statuses["service_fingerprinting"] = entry(
            "no_data", "aucun socket en écoute fourni"
        )

    vulnerability_status = error_status(("osv", "nvd", "kev", "epss", "trivy", "cve"))

    if products:
        statuses["vulnerability_intelligence"] = entry(
            "completed", "corrélation hors ligne des produits terminée"
        )
    elif "trivy" in used and not vulnerability_status:
        statuses["vulnerability_intelligence"] = entry(
            "completed", "trivy a produit un rapport"
        )
    elif vulnerability_status:
        statuses["vulnerability_intelligence"] = entry(
            vulnerability_status, "recherche de vulnérabilités en erreur"
        )
    else:
        statuses["vulnerability_intelligence"] = entry(
            "no_data", "aucun produit identifié"
        )

    tls_status = error_status(("tls", "certificate", "openssl", "handshake"))

    if "testssl" in used and not tls_status:
        statuses["tls_audit"] = entry("completed", "testssl.sh a produit un rapport")
    elif not active:
        statuses["tls_audit"] = entry("disabled", "active_probing désactivé")
    elif not config.get("tls_probe"):
        statuses["tls_audit"] = entry("disabled", "tls_probe désactivé")
    elif not tls_targets:
        statuses["tls_audit"] = entry(
            "no_data", "aucun port TLS dans le périmètre autorisé"
        )
    elif tls_status:
        statuses["tls_audit"] = entry(tls_status, "négociation TLS en erreur")
    elif has_finding(("tls.",)):
        statuses["tls_audit"] = entry(
            "completed", "négociation TLS terminée avec un résultat"
        )
    else:
        statuses["tls_audit"] = entry(
            "started", "négociation tentée ; aucun résultat de handshake exploitable"
        )

    if not config.get("ssh_policy_audit"):
        statuses["password_policy_audit"] = entry(
            "disabled", "ssh_policy_audit désactivé"
        )
    else:
        policy_status = error_status(("sshd", "ssh", "login.defs", "pam", "sudoers"))
        statuses["password_policy_audit"] = entry(
            policy_status or "completed",
            "lecture des politiques terminée"
            if not policy_status
            else "lecture des politiques en erreur",
        )

    if isinstance(journal_entries, bool) or not isinstance(journal_entries, int):
        journal_entries = None

    if not config.get("journal_audit"):
        statuses["host_intrusion_detection"] = entry(
            "disabled", "journal_audit désactivé"
        )
    else:
        journal_status = error_status(("journal", "journalctl", "systemd"))

        if journal_status:
            statuses["host_intrusion_detection"] = entry(
                journal_status, "lecture journald en erreur"
            )
        elif journal_entries is None:
            statuses["host_intrusion_detection"] = entry(
                "started",
                "lecture journald tentée ; nombre d'entrées non transmis",
            )
        elif journal_entries > 0:
            statuses["host_intrusion_detection"] = entry(
                "completed",
                f"{journal_entries} entrée(s) journald analysée(s)",
            )
        else:
            statuses["host_intrusion_detection"] = entry(
                "no_data", "journald lu ; aucune entrée exploitable"
            )

    http_status = error_status(("http", "head"))

    if not active:
        statuses["application_security_analysis"] = entry(
            "disabled", "active_probing désactivé"
        )
    elif not config.get("http_probe"):
        statuses["application_security_analysis"] = entry(
            "disabled", "http_probe désactivé"
        )
    elif not http_targets:
        statuses["application_security_analysis"] = entry(
            "no_data", "aucun port HTTP dans le périmètre autorisé"
        )
    elif http_status:
        statuses["application_security_analysis"] = entry(
            http_status, "requête HTTP en erreur"
        )
    elif has_finding(("http.",)):
        statuses["application_security_analysis"] = entry(
            "completed", "réponse HTTP analysée"
        )
    else:
        statuses["application_security_analysis"] = entry(
            "started", "requête HEAD tentée ; aucun résultat exploitable"
        )

    return {capability: statuses[capability] for capability in CAPABILITIES}


@collection_trace.instrument("analysis", "engine.analyze")
def analyze(payload):
    """Point d'entrée unique : payload JSON Rust -> rapport de sécurité.

    L'autorisation est vérifiée avant toute lecture ou analyse. Le processus
    qui appelle ``main.py`` l'obtient uniquement après l'Auth Gate Argon2id.
    """

    authz.require()

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

    journal_findings, journal_errors, journal_entries = _journal_findings(
        intelligence_config, host
    )
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
        "core_version": CORE_VERSION,
        "lab_version": LAB_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "source": payload.get("source", "unknown"),
        "capabilities": list(CAPABILITIES),
        "capability_status": capability_status(
            intelligence_config,
            inventory,
            authorized,
            products,
            tools_used,
            findings,
            errors,
            journal_entries=journal_entries,
        ),
        "network": {
            "neighbors_discovered": len(devices),
            "ports_observed": len(events),
            "open_ports": len(open_ports),
        },
        "inventory": {
            "hostname": inventory.get("hostname"),
            "kernel": inventory.get("kernel"),
            "architecture": inventory.get("architecture"),
            "distribution": inventory.get("distribution"),
            "os_id": inventory.get("os_id"),
            "os_version": inventory.get("os_version"),
            "interfaces": inventory.get("interfaces") or [],
            "listeners_count": len(inventory.get("listeners") or []),
            "listeners": [
                services.describe_listener(item)
                for item in inventory.get("listeners") or []
                if services.describe_listener(item) is not None
            ],
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
