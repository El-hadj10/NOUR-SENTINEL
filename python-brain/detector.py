
def get_recommendation(port, service, severity):
    recommendations = {
        22: "Utiliser l'authentification par clés SSH, désactiver l'authentification par mot de passe et restreindre l'accès par IP/ACL.",
        23: "Telnet est non chiffré. Remplacer par SSH ou désactiver complètement ce service.",
        53: "Vérifier la configuration DNS. Restreindre les requêtes récursives aux clients autorisés uniquement.",
        80: "Forcer HTTPS (redirection 301/302). Vérifier les en-têtes de sécurité (HSTS, CSP).",
        443: "Vérifier la validité du certificat TLS, utiliser TLS 1.2+ uniquement et configurer des suites de chiffrement fortes.",
        3306: "MySQL ne doit JAMAIS être exposé directement à Internet. Utiliser un tunnel SSH ou restreindre à l'accès local/réseau privé.",
        3389: "RDP exposé est une cible privilégiée. Utiliser un VPN, activer NLA, limiter par IP et envisager un bastion.",
        5432: "PostgreSQL doit être restreint au réseau privé. Vérifier pg_hba.conf et ne pas exposer directement.",
        5900: "VNC non chiffré par défaut. Utiliser un tunnel SSH ou un serveur VNC avec chiffrement fort.",
        8080: "Vérifier qu'il ne s'agit pas d'une interface d'administration exposée. Appliquer les mêmes règles de sécurité qu'en production.",
    }
    
    base_rec = recommendations.get(port, f"Vérifier la nécessité d'exposer {service} sur ce port. Restreindre l'accès au strict nécessaire.")
    
    if severity == "warning":
        return f"[CRITIQUE] {base_rec}"
    return base_rec


def detect_threats(events, analysis_config):

    sensitive_ports = set(
        analysis_config.get("sensitive_ports", [])
    )

    known_services = analysis_config.get(
        "known_services", {}
    )

    findings = []

    for event in events:

        if event.get("type") != "port_observed":
            continue

        port = event.get("port")
        state = event.get("state")
        ip = event.get("ip", "unknown")

        if not isinstance(port, int):
            continue

        if isinstance(port, bool) or not 1 <= port <= 65535:
            continue

        if state != "open":
            continue

        service = known_services.get(
            str(port), "Unknown"
        )

        severity = (
            "warning"
            if port in sensitive_ports
            else "info"
        )

        recommendation = get_recommendation(port, service, severity)

        findings.append({
            "ip": ip,
            "port": port,
            "service": service,
            "severity": severity,
            "message": (
                f"{service} accessible on {ip}:{port}"
            ),
            "recommendation": recommendation,
            "risk_level": severity
        })

    return findings
