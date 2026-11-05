"""Détection d'intrusion à partir des journaux système (pilier 5).

Une anomalie est un signal à investiguer, jamais une compromission prouvée.
Chaque constat conserve la ligne de journal qui le justifie.
"""

import json
import re
from datetime import datetime, timezone

from intelligence.models import make_finding

FAILED_SSH = re.compile(
    r"Failed (?:password|publickey|none) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"
)
ACCEPTED_SSH = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"
)
NEW_USER = re.compile(r"new user|useradd|useradd\[", re.I)
FIREWALL = re.compile(r"\b(ufw|nftables|iptables)\b", re.I)
SERVICE_STARTED = re.compile(r"Started (?P<unit>[^.\s]+\.service)")
SUDO_COMMAND = re.compile(r"COMMAND=(?P<command>.+)$")


def parse_journal_lines(lines):
    """Ignore silencieusement les lignes non JSON (journald partiel)."""

    entries = []

    for line in lines or []:
        text = line.strip() if isinstance(line, str) else ""
        if not text:
            continue

        try:
            entry = json.loads(text)
        except ValueError:
            continue

        if isinstance(entry, dict):
            entries.append(entry)

    return entries


def _timestamp(entry):
    raw = entry.get("__REALTIME_TIMESTAMP") or entry.get("_SOURCE_REALTIME_TIMESTAMP")

    try:
        return datetime.fromtimestamp(int(raw) / 1_000_000, tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def _message(entry):
    return str(entry.get("MESSAGE") or "")


def _finding(host, check, observation, evidence, severity, recommendation, confidence="corroborated"):
    return make_finding(
        asset=host,
        check=f"intrusion.{check}",
        component="journald",
        observation=observation,
        evidence=evidence,
        confidence=confidence,
        severity=severity,
        exposure="local",
        recommendation=recommendation,
        status="to_verify",
    )


def detect(entries, host="localhost", window_seconds=600, failure_threshold=5):
    """Analyse des entrées journald déjà parsées."""

    findings = []
    failures_by_ip = {}

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue

        message = _message(entry)
        match = FAILED_SSH.search(message)

        if match:
            failures_by_ip.setdefault(match.group("ip"), []).append(
                (_timestamp(entry), match.group("user"), message)
            )

    # Rafales d'échecs : fenêtre glissante par adresse source.
    for ip, failures in failures_by_ip.items():
        moments = sorted(moment for moment, _, _ in failures if moment is not None)

        for index, start in enumerate(moments):
            window = [
                moment
                for moment in moments[index:]
                if (moment - start).total_seconds() <= window_seconds
            ]

            if len(window) < failure_threshold:
                continue

            findings.append(
                _finding(
                    host,
                    "ssh_failure_burst",
                    f"{len(window)} échecs SSH en moins de {window_seconds // 60} minutes depuis {ip}",
                    (
                        f"journald: {len(window)} échecs depuis {ip}; "
                        f"utilisateur visé={failures[-1][1]}"
                    ),
                    "medium",
                    "Vérifier l'origine, bloquer si nécessaire et imposer des clés.",
                )
            )
            break

    # Succès après échecs : événement prioritaire, pas une preuve.
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue

        match = ACCEPTED_SSH.search(_message(entry))

        if not match:
            continue

        ip = match.group("ip")
        moment = _timestamp(entry)
        previous = [
            failure
            for failure in failures_by_ip.get(ip, [])
            if failure[0] is not None and (moment is None or failure[0] <= moment)
        ]

        if previous:
            findings.append(
                _finding(
                    host,
                    "ssh_success_after_failures",
                    f"Connexion SSH réussie depuis {ip} après {len(previous)} échec(s)",
                    f"journald: Accepted pour {match.group('user')} depuis {ip}",
                    "high",
                    "Corréler avec l'activité de l'utilisateur et vérifier les journaux de session.",
                )
            )

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue

        message = _message(entry)
        identifier = str(entry.get("SYSLOG_IDENTIFIER") or "")

        if NEW_USER.search(message) or identifier in ("useradd", "adduser"):
            findings.append(
                _finding(
                    host,
                    "account_change",
                    "Création ou modification de compte système",
                    f"journald:{identifier}:{message[:200]}",
                    "medium",
                    "Vérifier que ce compte est attendu et documenté.",
                )
            )

        if identifier == "sudo":
            match = SUDO_COMMAND.search(message)

            if match:
                findings.append(
                    _finding(
                        host,
                        "sudo_command",
                        "Commande sudo exécutée",
                        f"journald:{message[:200]}",
                        "info",
                        "Vérifier la légitimité de la commande et du compte.",
                    )
                )

        if FIREWALL.search(message) or identifier in ("ufw", "nftables"):
            findings.append(
                _finding(
                    host,
                    "firewall_change",
                    "Changement de pare-feu observé",
                    f"journald:{identifier}:{message[:200]}",
                    "medium",
                    "Confirmer le changement et réévaluer la surface d'exposition.",
                )
            )

        match = SERVICE_STARTED.search(message)

        if match:
            findings.append(
                _finding(
                    host,
                    "service_started",
                    f"Démarrage du service {match.group('unit')}",
                    f"journald:{message[:200]}",
                    "info",
                    "Vérifier que le service est attendu et à jour.",
                )
            )

    unique = {}

    for finding in findings:
        unique.setdefault((finding["check"], finding["evidence"]), finding)

    return list(unique.values())
