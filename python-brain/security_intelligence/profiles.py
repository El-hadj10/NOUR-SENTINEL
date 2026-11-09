"""Profils d'agressivité des sondes actives, en dictionnaire explicite.

Un profil ne lève aucun garde-fou : la cible reste une IPv4 choisie dans la
table ARP, `--confirm-authorized` reste obligatoire, la liste blanche
s'applique et le plafond de 32 ports par protocole n'est jamais dépassé.
Le profil règle uniquement les ports par défaut, le timeout et le nombre de
sondes simultanées.
"""

DEFAULT_PROFILE = "standard"

MIN_PROBE_TIMEOUT = 0.5
MAX_PROBE_TIMEOUT = 30.0
MAX_CONCURRENCY = 8

PROFILES = {
    "passif": {
        "name": "passif",
        "description": "Peu de ports, une sonde à la fois, timeouts doublés.",
        "timeout_factor": 2.0,
        "concurrency": 1,
        "tcp_ports": (22, 80, 443, 8443),
        "udp_ports": (53, 123),
    },
    "standard": {
        "name": "standard",
        "description": "Ports usuels, une sonde à la fois, timeout de configuration.",
        "timeout_factor": 1.0,
        "concurrency": 1,
        "tcp_ports": (
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        ),
        "udp_ports": (53, 67, 68, 69, 123, 137, 138, 161, 500, 1900, 5353),
    },
    "agressif": {
        "name": "agressif",
        "description": "Liste étendue (32 TCP max), quatre sondes simultanées, timeout réduit.",
        "timeout_factor": 0.5,
        "concurrency": 4,
        "tcp_ports": (
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1433, 1521, 1723, 2049, 2375,
            2376, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
            9090, 27017,
        ),
        "udp_ports": (
            53, 67, 68, 69, 123, 137, 138, 161, 500, 1900,
            5353, 5355, 11211, 2055,
        ),
    },
}


def resolve_profile(name=None):
    """Retourne le profil nommé, ou refuse un nom inconnu."""

    key = (
        DEFAULT_PROFILE if name is None else str(name).strip().lower()
    )

    try:
        return PROFILES[key]
    except KeyError as error:
        raise ValueError(
            f"profil inconnu: {name!r} (attendu: {', '.join(PROFILES)})"
        ) from error


def probe_timeout(base_timeout, profile):
    """Applique le facteur du profil, borné pour rester utilisable."""

    value = float(base_timeout) * float(profile["timeout_factor"])
    return max(MIN_PROBE_TIMEOUT, min(MAX_PROBE_TIMEOUT, value))


def scan_timeout(base_timeout, profile):
    """Timeout par port : plus court en agressif, plus long en passif."""

    value = float(base_timeout) * float(profile["timeout_factor"])
    return max(0.1, min(MAX_PROBE_TIMEOUT, value))
