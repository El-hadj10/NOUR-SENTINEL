
from detector import detect_threats


def analyze_events(data):

    events = data.get("events", [])
    devices = data.get("devices", [])

    findings = detect_threats(events)

    open_ports = [
        event for event in events
        if event.get("state") == "open"
    ]

    return {
        "engine": "NOUR SENTINEL",
        "version": "0.2.0",
        "source": data.get("source", "unknown"),
        "network": {
            "neighbors_discovered": len(devices),
            "ports_observed": len(events),
            "open_ports": len(open_ports)
        },
        "devices": devices,
        "findings_count": len(findings),
        "findings": findings,
        "status": "analysis_completed"
    }
