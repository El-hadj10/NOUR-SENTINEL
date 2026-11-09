"""Identification des services.

Deux sources, jamais confondues :

- locale (`/proc`) : processus vérifié -> confiance `confirmed` ;
- distante (bannière) : auto-déclarée -> confiance `probable`.

Une bannière n'est pas une preuve de version : les correctifs rétroportés
d'une distribution peuvent rendre une version ancienne non vulnérable.
"""

import re
import socket
from pathlib import Path

from security_intelligence import collection_trace

# (service, produit, motif). L'ordre détermine la priorité.
SIGNATURES = (
    ("ssh", "OpenSSH", re.compile(r"SSH-2\.0-OpenSSH[_-](?P<version>[\w.\-]+)")),
    ("http", "Apache httpd", re.compile(r"\bApache/(?P<version>[0-9][0-9.]*)", re.I)),
    ("http", "nginx", re.compile(r"\bnginx/(?P<version>[0-9][0-9.]*)", re.I)),
    ("http", "Microsoft-IIS", re.compile(r"Microsoft-IIS/(?P<version>[0-9.]+)", re.I)),
    ("ftp", "vsftpd", re.compile(r"220[ -].*vsftpd (?P<version>[0-9][0-9.]*)", re.I)),
    ("ftp", "ProFTPD", re.compile(r"220[ -].*ProFTPD (?P<version>[0-9][0-9.]*)", re.I)),
    ("smtp", "Postfix", re.compile(r"220[ -].*Postfix", re.I)),
    ("smtp", "Exim", re.compile(r"220[ -].*Exim (?P<version>[0-9][0-9.]*)", re.I)),
    ("redis", "Redis", re.compile(r"redis_version:(?P<version>[0-9][0-9.]*)")),
    ("docker", "Docker API", re.compile(r'"ApiVersion"\s*:\s*"(?P<version>[0-9.]+)"')),
)

# (motif sur le nom de processus, service, produit).
PROCESS_SIGNATURES = (
    (re.compile(r"^sshd$"), "ssh", "OpenSSH"),
    (re.compile(r"^apache2$|^httpd$"), "http", "Apache httpd"),
    (re.compile(r"^nginx$"), "http", "nginx"),
    (re.compile(r"^dockerd$|^docker-proxy$"), "docker", "Docker Engine"),
    (re.compile(r"^mysqld$|^mariadbd$"), "mysql", "MySQL"),
    (re.compile(r"^postgres$"), "postgresql", "PostgreSQL"),
    (re.compile(r"^named$|^unbound$"), "dns", "DNS server"),
    (re.compile(r"^systemd-resolve$"), "dns", "systemd-resolved"),
    (re.compile(r"^tor$"), "proxy", "Tor"),
    (re.compile(r"^privoxy$"), "proxy", "Privoxy"),
    (re.compile(r"^glances$"), "monitoring", "Glances"),
    (re.compile(r"^tailscaled$"), "vpn", "Tailscale"),
    (re.compile(r"^cupsd$"), "printing", "CUPS"),
    (re.compile(r"^smbd$|^nmbd$"), "smb", "Samba"),
    (re.compile(r"^rpcbind$"), "rpc", "rpcbind"),
)


def _first_line(text):
    line = text.strip().splitlines()[0] if text.strip() else ""

    return line[:160]


def identify_banner(banner):
    """Identifie un produit à partir d'une bannière, sans la surinterpréter."""

    if not isinstance(banner, str) or not banner.strip():
        return []

    text = banner[:4096]
    results = []
    seen = set()

    for service, product, pattern in SIGNATURES:
        match = pattern.search(text)

        if not match or product in seen:
            continue

        seen.add(product)
        groups = match.groupdict()

        results.append(
            {
                "service": service,
                "product": product,
                "version": groups.get("version"),
                "confidence": "probable",
                "evidence": f"banner:{_first_line(text)}",
                "source": "banner",
            }
        )

    return results


def describe_listener(listener):
    """Décrit ce qui est réellement prouvé pour un socket.

    Un socket lié n'est pas un service disponible : l'application n'est
    identifiée que par son processus local, et aucune réponse applicative
    n'est vérifiée par l'inventaire. ``application_verified`` reste donc
    toujours ``false`` ici.
    """

    if not isinstance(listener, dict):
        return None

    identity = identify_listener(listener)
    protocol = str(listener.get("protocol") or "tcp").lower()
    state = str(listener.get("state") or ("listen" if protocol == "tcp" else "bound"))

    if protocol == "udp" and state in ("listen", "closed"):
        state = "bound"

    return {
        **listener,
        "protocol": protocol,
        "state": state,
        "socket_bound": bool(listener.get("port")),
        "process_identified": bool(listener.get("pid") or listener.get("process")),
        "application_identified": bool(identity),
        "application_service": (identity or {}).get("product"),
        "application_verified": False,
    }


def identify_listener(listener):
    """Identifie un service à partir de son processus local (preuve forte)."""

    if not isinstance(listener, dict):
        return None

    process = str(listener.get("process") or "").strip()
    exe = str(listener.get("exe") or "").strip()
    unit = str(listener.get("unit") or "").strip()

    candidates = [process, Path(exe).name if exe else "", unit.split(".")[0]]

    for candidate in candidates:
        if not candidate:
            continue

        for pattern, service, product in PROCESS_SIGNATURES:
            if pattern.search(candidate):
                return {
                    "service": service,
                    "product": product,
                    "version": None,
                    "confidence": "confirmed",
                    "evidence": f"local_process:{exe or process or candidate}",
                    "source": "local",
                }

    return None


@collection_trace.instrument("tcp", "services.probe_banner")
def probe_banner(ip, port, timeout=0.8, request=None):
    """Lit une bannière. À n'appeler que sur une cible autorisée."""

    with socket.create_connection((ip, port), timeout=timeout) as connection:
        connection.settimeout(timeout)

        if request:
            payload = request.encode("ascii") if isinstance(request, str) else request
            connection.sendall(payload)

        try:
            data = connection.recv(1024)
        except socket.timeout:
            return ""

    return data.decode("latin-1", "replace")
