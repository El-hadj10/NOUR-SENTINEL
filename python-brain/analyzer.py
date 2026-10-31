
from detector import detect_threats


def analyze_events(data):

    events = data.get("events", [])

    findings = detect_threats(events)

    return {
        "engine": "NOUR SENTINEL",
        "version": "0.1.0",
        "source": data.get("source", "unknown"),
        "events_analyzed": len(events),
        "findings_count": len(findings),
        "findings": findings,
        "status": "analysis_completed"
    }
