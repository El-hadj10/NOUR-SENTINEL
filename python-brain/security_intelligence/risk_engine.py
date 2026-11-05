"""Moteur de risque partagé avec la ligne stable v0.5.0.

Une seule implémentation : le laboratoire ne réinvente ni le score, ni le
plafonnement des sévérités, ni la priorisation.
"""

from intelligence.risk_engine import (  # noqa: F401
    deduplicate,
    prioritize,
    priority_for,
    score,
    summarize,
)

__all__ = ["deduplicate", "prioritize", "priority_for", "score", "summarize"]
