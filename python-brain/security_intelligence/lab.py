"""Orchestration du laboratoire 0.6.0-beta.3.

Chaque exécution produit un rapport normalisé, l'écrit en 0600 sous
`data/reports/` et l'enregistre dans la base d'intelligence.
"""

import socket
from datetime import datetime, timezone

import authz

from security_intelligence import BASE_VERSION, LAB_NAME, VERSION
from security_intelligence import (
    CORE_VERSION,
    LAB_VERSION,
    PROTOCOL_VERSION,
    collection_trace,
    profiles,
    reports,
    risk_engine,
)
from intelligence.fingerprinting import services as fingerprinting_services
from security_intelligence.config import resolve_target
from security_intelligence.applications import docker as docker_inventory
from security_intelligence.fingerprinting import inventory, service_probe
from security_intelligence.intrusion import journal as journal_intel
from security_intelligence.passwords import policy
from security_intelligence.store import IntelStore, StoreError
from security_intelligence.tls import analyzer as tls_analyzer
from security_intelligence.vulnerabilities.online import OnlineIntel

LIMITS = (
    "Une bannière n'est pas une preuve du binaire exact ; les correctifs "
    "rétroportés ne sont pas vérifiés.",
    "Une recherche NVD par mots-clés peut produire des faux positifs.",
    "TLS 1.0/1.1, STARTTLS et toutes les suites ne sont pas testés ; un échec "
    "de négociation ne prouve pas l'absence de TLS.",
    "Les alertes journald sont des pistes d'investigation, pas des preuves.",
    "Aucune exploitation, aucun brute force, aucune remédiation automatique.",
    "Aucun mot de passe, hash ou journal brut n'est collecté ni exporté.",
)


def public_inventory(data):
    """Inventaire sérialisable, sans doublon de la liste d'erreurs."""

    return {
        "host": data.get("host") or {},
        "os_release": data.get("os_release") or {},
        "package_manager": data.get("package_manager"),
        "package_count": data.get("package_count", 0),
        "packages": data.get("packages") or [],
        "products": data.get("products") or [],
        "services": data.get("services") or [],
        "listeners": [
            fingerprinting_services.describe_listener(item)
            for item in data.get("listeners") or []
            if fingerprinting_services.describe_listener(item) is not None
        ],
    }


def _persist(report, config, errors):
    run_id = None

    try:
        store = IntelStore(config["database"])

        try:
            run_id = store.save_run(report)
        finally:
            store.close()
    except StoreError as error:
        errors.append(str(error))

    try:
        path = reports.write_report(report, config["reports_dir"])
        report["report_path"] = str(path)
    except OSError as error:
        errors.append(f"rapport non écrit: {error}")
        return report

    if run_id is not None:
        try:
            store = IntelStore(config["database"])

            try:
                store.attach_report(run_id, str(path))
            finally:
                store.close()
        except StoreError as error:
            errors.append(f"lien rapport/base impossible: {error}")

    return report


@collection_trace.instrument("operation", "lab.finalize")
def finalize(mode, config, findings, errors, inventory_data=None, metadata=None):
    """Dédoublonne, priorise, écrit le rapport et mémorise l'exécution."""

    authz.require()
    unique = risk_engine.deduplicate(findings)
    ordered = risk_engine.prioritize(unique)

    report = {
        "engine": LAB_NAME,
        "version": VERSION,
        "base_version": BASE_VERSION,
        "core_version": CORE_VERSION,
        "lab_version": LAB_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "mode": mode,
        "environment": config.get("environment", "lab"),
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "host": socket.gethostname(),
        "authorized_targets": list(config.get("authorized_targets") or []),
        "findings_count": len(ordered),
        "findings": ordered,
        "risk_summary": risk_engine.summarize(ordered),
        "errors": [str(error)[:300] for error in errors],
        "limits": list(LIMITS),
    }

    if inventory_data is not None:
        report["inventory"] = public_inventory(inventory_data)

    if metadata is not None:
        report["details"] = metadata

    report = _persist(report, config, errors)
    report["errors"] = [str(error)[:300] for error in errors]

    return report


@collection_trace.instrument("operation", "lab.run_inventory")
def run_inventory(config):
    authz.require()
    data = inventory.collect(config)
    errors = list(data.get("errors") or [])

    return finalize(
        "inventory",
        config,
        [],
        errors,
        inventory_data=data,
        metadata={"note": "Inventaire local uniquement ; aucun scan réseau."},
    )


@collection_trace.instrument("operation", "lab.run_full_local")
def run_full_local(config):
    authz.require()
    data = inventory.collect(config)
    errors = list(data.get("errors") or [])

    policy_findings, policy_meta, policy_errors = policy.collect(config, data["host"]["hostname"])
    errors.extend(policy_errors)
    findings = list(policy_findings)

    journal_meta = {"enabled": False}
    journal_errors = []

    if config.get("journal", {}).get("enabled"):
        journal_findings, journal_meta, journal_errors = journal_intel.collect(
            config, data["host"]["hostname"]
        )
        findings.extend(journal_findings)
        errors.extend(journal_errors)

    docker_findings, docker_meta, docker_errors = docker_inventory.collect(
        config, data["host"]["hostname"]
    )
    findings.extend(docker_findings)
    errors.extend(docker_errors)

    return finalize(
        "full-local",
        config,
        findings,
        errors,
        inventory_data=data,
        metadata={
            "policies": policy_meta,
            "journal": journal_meta,
            "docker": docker_meta,
            "note": "Audit local ; aucune sonde réseau lancée.",
        },
    )


@collection_trace.instrument("operation", "lab.run_fingerprint")
def run_fingerprint(config, target, port, protocol="http", profile=profiles.DEFAULT_PROFILE):
    authz.require()
    selection = profiles.resolve_profile(profile)
    timeout = profiles.probe_timeout(config.get("timeout", 2.0), selection)
    # Refus immédiat hors liste blanche : aucune sonde n'est tentée.
    resolve_target(target, config.get("authorized_targets") or ())

    if protocol == "ssh":
        findings, errors = service_probe.probe_ssh(
            target,
            port,
            timeout=timeout,
            allowed=config.get("authorized_targets") or (),
        )
    elif protocol == "http":
        findings, errors = service_probe.probe_http(
            target,
            port,
            timeout=timeout,
            allowed=config.get("authorized_targets") or (),
        )
    else:
        raise ValueError("protocole attendu: ssh ou http")

    return finalize(
        "fingerprint",
        config,
        findings,
        errors,
        metadata={
            "target": target,
            "port": port,
            "protocol": protocol,
            "profile": selection["name"],
        },
    )


@collection_trace.instrument("operation", "lab.run_tls")
def run_tls(config, target, port, profile=profiles.DEFAULT_PROFILE):
    authz.require()
    if not config.get("probes", {}).get("tls", True):
        raise PermissionError("sonde TLS désactivée dans la configuration")

    selection = profiles.resolve_profile(profile)
    timeout = profiles.probe_timeout(config.get("timeout", 3.0), selection)
    resolve_target(target, config.get("authorized_targets") or ())

    findings, metadata, errors = tls_analyzer.audit(
        target,
        port,
        timeout=timeout,
        allowed=config.get("authorized_targets") or (),
    )

    return finalize(
        "tls",
        config,
        findings,
        errors,
        metadata={"tls": metadata, "profile": selection["name"]},
    )


@collection_trace.instrument("operation", "lab.run_cve_online")
def run_cve_online(config, package=None, version=None):
    authz.require()
    if not config.get("online", {}).get("enabled"):
        raise PermissionError(
            "intelligence externe désactivée dans config/security_intelligence.json"
        )

    if package and not version:
        raise ValueError("--version est requis avec --package")

    host = socket.gethostname()

    if package:
        packages = [{"package": package, "version": version}]
    else:
        data = inventory.collect(config)
        packages = data.get("packages") or []

        if not packages:
            raise RuntimeError("aucun paquet local à interroger")

    limit = min(
        10,
        int(config.get("online", {}).get("max_requests") or 20),
    )
    client = OnlineIntel(config)
    findings, metadata, errors = client.assess_packages(
        host, packages, limit=limit
    )

    return finalize(
        "cve-online",
        config,
        findings,
        errors,
        metadata={"online": metadata},
    )
