"""Découverte ARP passive et sondes bornées sur une seule IP sélectionnée."""

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from security_intelligence import collection_trace, profiles

ARP_TABLE_PATH = Path("/proc/net/arp")
MAX_PORTS_PER_PROTOCOL = 32
CONNECT_TIMEOUT_SECONDS = 0.5
DEFAULT_TCP_PORTS = profiles.PROFILES["standard"]["tcp_ports"]
DEFAULT_UDP_PORTS = profiles.PROFILES["standard"]["udp_ports"]
_MAC_ADDRESS = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def parse_arp_table(text):
    """Retourne les voisins IPv4 avec une entrée ARP complète, sans leur MAC."""

    lines = text.splitlines()

    if not lines:
        return []

    neighbors = []

    for line in lines[1:]:
        fields = line.split()

        if (
            len(fields) != 6
            or not _MAC_ADDRESS.fullmatch(fields[3])
            or fields[3] == "00:00:00:00:00:00"
        ):
            continue

        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError:
            continue

        if (
            not isinstance(address, ipaddress.IPv4Address)
            or address.is_unspecified
            or address.is_loopback
            or address.is_multicast
            or address.is_link_local
            or not any(address in network for network in _PRIVATE_NETWORKS)
            or fields[2] == "0x0"
        ):
            continue

        neighbors.append({"ip": str(address), "interface": fields[5]})

    return neighbors


def parse_ports(value, defaults, protocol):
    """Valide une liste explicite de ports, sans plages ni expansion implicite."""

    if value is None:
        return tuple(defaults)

    if isinstance(value, str):
        parts = value.split(",")

        if not parts or any(not part.strip().isdigit() for part in parts):
            raise ValueError(f"liste de ports {protocol} invalide")

        ports = tuple(int(part.strip()) for part in parts)
    else:
        try:
            ports = tuple(value)
        except TypeError as error:
            raise ValueError(f"liste de ports {protocol} invalide") from error

    if any(
        isinstance(port, bool)
        or not isinstance(port, int)
        or port < 1
        or port > 65535
        for port in ports
    ):
        raise ValueError(f"port {protocol} invalide (1-65535)")

    ports = tuple(dict.fromkeys(ports))

    if not ports:
        raise ValueError(f"liste de ports {protocol} invalide")

    if len(ports) > MAX_PORTS_PER_PROTOCOL:
        raise ValueError(
            f"maximum {MAX_PORTS_PER_PROTOCOL} ports {protocol} par commande"
        )

    return ports


def _read_neighbors():
    try:
        table = ARP_TABLE_PATH.read_text(encoding="ascii")
    except OSError as error:
        raise OSError(f"lecture de la table ARP impossible: {error}") from error

    return parse_arp_table(table)


@collection_trace.instrument("operation", "network_scan.discover_neighbors")
def discover_neighbors():
    """Lit la table ARP locale uniquement ; n'envoie aucune sonde réseau."""

    neighbors = _read_neighbors()

    return {
        "mode": "network_discovery",
        "neighbor_count": len(neighbors),
        "neighbors": neighbors,
        "active_probes": False,
    }


def _validate_target(target, neighbors):
    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError as error:
        raise ValueError("la cible doit être une adresse IPv4 littérale") from error

    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("seules les adresses IPv4 sont acceptées")

    normalized = str(address)

    if normalized not in {neighbor["ip"] for neighbor in neighbors}:
        raise PermissionError(
            "cible refusée : choisissez une IPv4 présente dans la découverte ARP "
            "actuelle"
        )

    return normalized


def _probe_tcp(target, port, timeout):
    try:
        connection = socket.create_connection((target, port), timeout=timeout)
    except ConnectionRefusedError:
        state = "closed"
    except socket.timeout:
        state = "filtered_or_timeout"
    except OSError:
        state = "unreachable"
    else:
        connection.close()
        state = "open"

    return {"port": port, "state": state}


def _probe_udp(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            connection.connect((target, port))
            connection.send(b"")
            response = connection.recv(512)
    except ConnectionRefusedError:
        state = "closed"
    except socket.timeout:
        state = "open_or_filtered"
    except OSError:
        state = "unreachable"
    else:
        state = "open" if response else "open_or_filtered"

    return {"port": port, "state": state}


def _run_probes(probe, target, ports, timeout, concurrency):
    """Exécute les sondes dans l'ordre des ports, avec une concurrence bornée."""

    if concurrency <= 1 or len(ports) <= 1:
        return [probe(target, port, timeout) for port in ports]

    with ThreadPoolExecutor(max_workers=min(concurrency, len(ports))) as executor:
        return list(executor.map(lambda port: probe(target, port, timeout), ports))


def _scan_tcp(target, ports, timeout=CONNECT_TIMEOUT_SECONDS, concurrency=1):
    return _run_probes(_probe_tcp, target, ports, timeout, concurrency)


def _scan_udp(target, ports, timeout=CONNECT_TIMEOUT_SECONDS, concurrency=1):
    return _run_probes(_probe_udp, target, ports, timeout, concurrency)


@collection_trace.instrument("operation", "network_scan.scan_target")
def scan_target(
    target,
    protocol="both",
    tcp_ports=None,
    udp_ports=None,
    authorized=False,
    profile=profiles.DEFAULT_PROFILE,
):
    """Sonde des ports communs sur une IP ARP choisie et confirmée explicitement."""

    if authorized is not True:
        raise PermissionError(
            "confirmez que vous êtes autorisé à tester cette cible avec "
            "--confirm-authorized"
        )

    if protocol not in ("tcp", "udp", "both"):
        raise ValueError("protocole invalide (tcp, udp ou both)")

    selection = profiles.resolve_profile(profile)
    timeout = profiles.scan_timeout(CONNECT_TIMEOUT_SECONDS, selection)
    neighbors = _read_neighbors()
    address = _validate_target(target, neighbors)
    tcp_ports = parse_ports(tcp_ports, selection["tcp_ports"], "TCP")
    udp_ports = parse_ports(udp_ports, selection["udp_ports"], "UDP")
    results = {}

    if protocol in ("tcp", "both"):
        results["tcp"] = _scan_tcp(
            address, tcp_ports, timeout, selection["concurrency"]
        )

    if protocol in ("udp", "both"):
        results["udp"] = _scan_udp(
            address, udp_ports, timeout, selection["concurrency"]
        )

    return {
        "mode": "network_scan",
        "target": address,
        "protocols": results,
        "limits": {
            "profile": selection["name"],
            "max_ports_per_protocol": MAX_PORTS_PER_PROTOCOL,
            "timeout_seconds": timeout,
            "concurrency": selection["concurrency"],
        },
        "udp_note": (
            "open_or_filtered est ambigu : UDP ne répond souvent pas aux "
            "datagrammes génériques."
        ),
    }
