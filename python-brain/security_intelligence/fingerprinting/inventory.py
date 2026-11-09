"""Inventaire local : OS, paquets, services systemd et sockets en écoute.

Aucune commande réseau, aucune modification : uniquement des lectures
(`dpkg-query`, `rpm`, `systemctl list-units`, `ss -ltn`).
"""

import platform
import re
import socket
import subprocess

import authz
from security_intelligence import collection_trace

DEFAULT_TIMEOUT = 15

PACKAGE_SIGNATURES = (
    (re.compile(r"^openssh-server$"), "ssh", "OpenSSH"),
    (re.compile(r"^apache2$|^httpd$"), "http", "Apache httpd"),
    (re.compile(r"^nginx(?:-core)?$"), "http", "nginx"),
    (re.compile(r"^tor$"), "proxy", "Tor"),
    (re.compile(r"^privoxy$"), "proxy", "Privoxy"),
    (re.compile(r"^docker\.io$|^docker-ce$|^moby-engine$"), "docker", "Docker Engine"),
    (re.compile(r"^mysql-server$|^mariadb-server$"), "mysql", "MySQL"),
    (re.compile(r"^postgresql(?:-\d+)?$"), "postgresql", "PostgreSQL"),
    (re.compile(r"^openssl$|^libssl[0-9a-z.]*$"), "crypto", "OpenSSL"),
)


@collection_trace.instrument("system", "inventory.run_command")
def run_command(argv, timeout=DEFAULT_TIMEOUT):
    """Exécute une commande sans shell ; ne lève jamais pour un code non nul."""

    try:
        process = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return {"returncode": -1, "stdout": "", "stderr": str(error)}

    return {
        "returncode": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }


def parse_os_release(text):
    values = {}

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")

    return values


@collection_trace.instrument("system", "inventory.read_os_release")
def read_os_release(path="/etc/os-release"):
    try:
        from pathlib import Path

        return parse_os_release(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}


def parse_package_output(text, manager):
    packages = []

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if not line or "\t" not in line:
            continue

        name, version = line.split("\t", 1)
        name = name.strip()
        version = version.strip()

        if not name or not version:
            continue

        packages.append(
            {
                "package": name,
                "version": version,
                "manager": manager,
            }
        )

    return packages


@collection_trace.instrument("system", "inventory.list_packages")
def list_packages(runner=None):
    """dpkg prioritaire, rpm en repli. Retourne `(gestionnaire, paquets)`."""

    authz.require()
    runner = runner or run_command

    dpkg = runner(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
        DEFAULT_TIMEOUT,
    )

    if dpkg.get("returncode") == 0:
        return "dpkg", parse_package_output(dpkg.get("stdout"), "dpkg")

    rpm = runner(
        ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
        DEFAULT_TIMEOUT,
    )

    if rpm.get("returncode") == 0:
        return "rpm", parse_package_output(rpm.get("stdout"), "rpm")

    return None, []


def parse_systemd_units(text):
    units = []

    for raw_line in (text or "").splitlines():
        fields = raw_line.split()

        if not fields:
            continue

        unit = fields[0].lstrip("●").strip()

        if not unit.endswith(".service"):
            continue

        if unit not in units:
            units.append(unit)

    return units


@collection_trace.instrument("system", "inventory.list_services")
def list_services(runner=None):
    authz.require()
    runner = runner or run_command

    result = runner(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend",
            "--plain",
        ],
        DEFAULT_TIMEOUT,
    )

    if result.get("returncode") != 0:
        return [], (
            f"systemctl: {str(result.get('stderr') or '').strip()[:160] or 'échec'}"
        )

    return parse_systemd_units(result.get("stdout")), None


def parse_ss_output(text, protocol="tcp"):
    """Parse `ss` sans confondre socket lié et service disponible."""

    protocol = "udp" if str(protocol).lower() == "udp" else "tcp"
    listeners = []

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if not line or line.lower().startswith("state"):
            continue

        fields = line.split()

        if len(fields) < 4:
            continue

        local = fields[3]

        if ":" not in local:
            continue

        address, port_text = local.rsplit(":", 1)

        try:
            port = int(port_text)
        except ValueError:
            continue

        if port <= 0:
            continue

        address = address.strip("[]")

        if address in ("*", ""):
            address = "0.0.0.0"

        if address == "::":
            address = "::"

        family = "ipv6" if ":" in address else "ipv4"

        listener = {
            "address": address,
            "port": port,
            "family": family,
            "protocol": protocol,
            "state": "bound" if protocol == "udp" else "listen",
        }

        if listener not in listeners:
            listeners.append(listener)

    return sorted(listeners, key=lambda item: (item["address"], item["port"]))


@collection_trace.instrument("system", "inventory.list_listeners")
def list_listeners(runner=None):
    authz.require()
    runner = runner or run_command

    listeners = []
    errors = []

    for protocol, flag in (("tcp", "-ltnH"), ("udp", "-lunH")):
        result = runner(["ss", flag], DEFAULT_TIMEOUT)

        if result.get("returncode") != 0:
            errors.append(
                f"ss {protocol}: "
                f"{str(result.get('stderr') or '').strip()[:120] or 'échec'}"
            )
            continue

        listeners.extend(parse_ss_output(result.get("stdout") or "", protocol))

    deduplicated = []

    for listener in sorted(
        listeners,
        key=lambda item: (item["protocol"], item["address"], item["port"]),
    ):
        if listener not in deduplicated:
            deduplicated.append(listener)

    return deduplicated, "; ".join(errors) or None


def fingerprint_packages(packages):
    """Identifie les familles locales connues à partir des paquets installés."""

    products = []
    seen = set()

    for package in packages or []:
        name = str(package.get("package") or "")

        for pattern, service, product in PACKAGE_SIGNATURES:
            if not pattern.search(name) or product in seen:
                continue

            seen.add(product)
            products.append(
                {
                    "service": service,
                    "product": product,
                    "version": package.get("version"),
                    "package": name,
                    "confidence": "confirmed",
                    "source": f"package:{package.get('manager') or 'unknown'}",
                    "evidence": (
                        f"package:{name} {package.get('version')} "
                        f"({package.get('manager') or 'unknown'})"
                    ),
                }
            )

    return products


@collection_trace.instrument("system", "inventory.collect")
def collect(config):
    """Retourne un inventaire local sans jamais lancer de scan réseau."""

    authz.require()
    options = (config or {}).get("inventory") or {}
    errors = []

    os_release = read_os_release()
    host = {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "distribution": os_release.get("PRETTY_NAME") or platform.platform(),
        "os_id": os_release.get("ID"),
        "os_version": os_release.get("VERSION_ID"),
    }

    packages = []
    manager = None

    if options.get("packages", True):
        manager, packages = list_packages()

        if manager is None:
            errors.append("inventaire des paquets indisponible (dpkg/rpm absents)")

        limit = int(options.get("max_packages") or 5000)
        packages = packages[:limit]

    services = []

    if options.get("services", True):
        services, error = list_services()

        if error:
            errors.append(error)

    listeners = []

    if options.get("sockets", True):
        listeners, error = list_listeners()

        if error:
            errors.append(error)

    return {
        "host": host,
        "os_release": os_release,
        "package_manager": manager,
        "package_count": len(packages),
        "packages": packages,
        "products": fingerprint_packages(packages),
        "services": services,
        "listeners": listeners,
        "errors": errors,
    }
