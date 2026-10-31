
SENSITIVE_PORTS = {
    23: "Telnet",
    3389: "Remote Desktop Protocol",
    5900: "VNC"
}


def detect_threats(events):

    findings = []

    for event in events:

        if event.get("type") != "port_observed":
            continue

        port = event.get("port")
        state = event.get("state")

        if not isinstance(port, int):
            continue

        if state != "open":
            continue

        if port in SENSITIVE_PORTS:

            findings.append({
                "port": port,
                "service": SENSITIVE_PORTS[port],
                "severity": "warning",
                "message": (
                    f"Sensitive service detected: "
                    f"{SENSITIVE_PORTS[port]}"
                )
            })

    return findings
