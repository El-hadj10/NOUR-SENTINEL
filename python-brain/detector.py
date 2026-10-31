
SENSITIVE_PORTS = {
    23: "Telnet",
    3389: "Remote Desktop Protocol",
    5900: "VNC"
}

KNOWN_SERVICES = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP Alternative"
}


def detect_threats(events):
    findings = []

    for event in events:
        if event.get("type") != "port_observed":
            continue

        port = event.get("port")
        state = event.get("state")
        ip = event.get("ip", "unknown")

        if not isinstance(port, int) or not 1 <= port <= 65535:
            continue

        if state != "open":
            continue

        service = KNOWN_SERVICES.get(
            port, SENSITIVE_PORTS.get(port, "Unknown")
        )

        severity = (
            "warning" if port in SENSITIVE_PORTS else "info"
        )

        findings.append({
            "ip": ip,
            "port": port,
            "service": service,
            "severity": severity,
            "message": f"{service} accessible on {ip}:{port}"
        })

    return findings
