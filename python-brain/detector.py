
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

        findings.append({
            "ip": ip,
            "port": port,
            "service": service,
            "severity": severity,
            "message": (
                f"{service} accessible on {ip}:{port}"
            )
        })

    return findings
