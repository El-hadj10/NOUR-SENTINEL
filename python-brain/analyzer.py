"""Compatibilité : l'analyse est désormais orchestrée par intelligence.engine."""

from intelligence.engine import analyze


def analyze_events(data):
    return analyze(data)
