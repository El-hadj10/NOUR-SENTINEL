"""Instrumentation en mémoire de tous les points de collecte du laboratoire.

Chaque fonction décorée enregistre une tentative *avant* la vérification
d'autorisation, puis un démarrage *après* succès. Un refus laisse donc une
trace ``attempt`` sans ``start`` : la preuve que le corps de la fonction — et
donc la commande, la sonde, l'écriture du rapport ou l'accès SQLite — n'a
jamais été exécuté.

Le journal reste strictement en mémoire : il ne contient aucun secret, n'est
jamais écrit sur disque et disparaît avec le processus. Il sert aux tests de
non-contournement et au diagnostic local, pas de piste d'audit persistante.
"""

import functools
import os
import threading
from collections import deque

import authz

MAX_EVENTS = 512

CATEGORIES = (
    "system",       # OS, paquets, services, sockets, politiques locales
    "application",  # Docker et applications locales
    "tcp",          # négociations et sondes réseau
    "external",     # OSV, NVD, KEV, EPSS
    "tool",         # outils externes optionnels
    "report",       # rapports privés
    "sqlite",       # mémoire d'intelligence
    "analysis",     # analyse du payload
    "operation",    # opérations publiques du laboratoire
)

_lock = threading.Lock()
_events = deque(maxlen=MAX_EVENTS)
_sites = {}


def _record(phase, category, site):
    event = {
        "phase": phase,
        "category": category,
        "site": site,
        "pid": os.getpid(),
    }

    with _lock:
        _events.append(event)


def instrument(category, site):
    """Décorateur : trace la tentative, exige l'autorisation, trace le départ."""

    if category not in CATEGORIES:
        raise ValueError(f"catégorie de collecte inconnue: {category}")

    def decorate(function):
        _sites[site] = category

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            _record("attempt", category, site)
            authz.require()
            _record("start", category, site)
            return function(*args, **kwargs)

        wrapper.collection_site = site
        wrapper.collection_category = category

        return wrapper

    return decorate


def events(phase=None):
    """Copie des événements, éventuellement filtrés sur ``phase``."""

    with _lock:
        snapshot = tuple(dict(event) for event in _events)

    if phase is None:
        return snapshot

    return tuple(event for event in snapshot if event["phase"] == phase)


def sites():
    """Registre des points instrumentés : ``{site: catégorie}``."""

    with _lock:
        return dict(_sites)


def started(site):
    return any(
        event["phase"] == "start" and event["site"] == site
        for event in events()
    )


def reset():
    with _lock:
        _events.clear()


__all__ = [
    "CATEGORIES",
    "events",
    "instrument",
    "reset",
    "sites",
    "started",
]
