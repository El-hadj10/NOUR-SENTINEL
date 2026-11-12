"""CLI du laboratoire Security Intelligence.

L'authentification Argon2id est vérifiée avant chaque commande
opérationnelle, sans session réutilisable. La sortie standard ne contient que
le rapport JSON ; les messages humains vont sur la sortie d'erreur.
"""

import argparse
import json
import sys

from security_intelligence import (
    VERSION,
    auth_gate,
    config as config_module,
    dashboard,
    lab,
    network_scan,
    profiles,
)


def _add_profile(parser):
    parser.add_argument(
        "--profile",
        choices=tuple(profiles.PROFILES),
        default=profiles.DEFAULT_PROFILE,
        help="agressivité des sondes : passif, standard ou agressif",
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="security_intelligence",
        description="NOUR SENTINEL LAB — diagnostic défensif authentifié.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"NOUR SENTINEL LAB {VERSION}",
    )

    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser(
        "inventory",
        help="inventaire local OS/paquets/services/sockets (aucun réseau)",
    )
    commands.add_parser(
        "full-local",
        help="inventaire, SSH/PAM, journald et Docker (aucun réseau)",
    )
    commands.add_parser(
        "discover",
        help="affiche les voisins IPv4 de la table ARP sans les sonder",
    )

    scan = commands.add_parser(
        "scan",
        help="sondes TCP/UDP bornées sur une IPv4 ARP choisie explicitement",
    )
    scan.add_argument("--target", required=True, help="IPv4 affichée par discover")
    scan.add_argument("--protocol", choices=("tcp", "udp", "both"), default="both")
    scan.add_argument("--tcp-ports", help="liste de ports TCP séparés par des virgules")
    scan.add_argument("--udp-ports", help="liste de ports UDP séparés par des virgules")
    scan.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="confirmez votre autorisation à sonder cette cible",
    )
    _add_profile(scan)

    fingerprint = commands.add_parser(
        "fingerprint", help="une bannière SSH ou un HEAD HTTP autorisé"
    )
    fingerprint.add_argument("--target", required=True)
    fingerprint.add_argument("--port", required=True, type=int)
    fingerprint.add_argument(
        "--protocol", choices=("ssh", "http"), default="http"
    )
    _add_profile(fingerprint)

    tls = commands.add_parser("tls", help="négociation TLS 1.2/1.3 et certificat")
    tls.add_argument("--target", required=True)
    tls.add_argument("--port", required=True, type=int)
    _add_profile(tls)

    cve = commands.add_parser("cve", help="recherche OSV/KEV/EPSS explicite")
    cve.add_argument("--online", action="store_true")
    cve.add_argument("--package")
    cve.add_argument("--version")

    board = commands.add_parser(
        "dashboard",
        help="tableau de bord local 127.0.0.1 (options, rapport, ondes réseau)",
    )
    board.add_argument(
        "--port",
        type=int,
        default=dashboard.DEFAULT_PORT,
        help=f"port d'écoute sur 127.0.0.1 (défaut: {dashboard.DEFAULT_PORT})",
    )

    return parser


def _validate_port(port):
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port TCP invalide (1-65535)")

    return port


def _validate_dashboard_port(port):
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port de tableau de bord invalide (1-65535)")

    return port


def run(args, config):
    if args.command == "inventory":
        return lab.run_inventory(config)

    if args.command == "full-local":
        return lab.run_full_local(config)

    if args.command == "discover":
        return network_scan.discover_neighbors()

    if args.command == "scan":
        tcp_ports = None
        udp_ports = None

        if args.protocol == "tcp" and args.udp_ports is not None:
            raise ValueError("--udp-ports nécessite --protocol udp ou both")

        if args.protocol == "udp" and args.tcp_ports is not None:
            raise ValueError("--tcp-ports nécessite --protocol tcp ou both")

        # Sans liste explicite, le profil choisit les ports ; la validation
        # (32 ports maximum, 1-65535) reste faite par scan_target.
        if args.protocol in ("tcp", "both") and args.tcp_ports is not None:
            tcp_ports = network_scan.parse_ports(args.tcp_ports, (), "TCP")

        if args.protocol in ("udp", "both") and args.udp_ports is not None:
            udp_ports = network_scan.parse_ports(args.udp_ports, (), "UDP")

        return network_scan.scan_target(
            args.target,
            protocol=args.protocol,
            tcp_ports=tcp_ports,
            udp_ports=udp_ports,
            authorized=args.confirm_authorized,
            profile=args.profile,
        )

    if args.command == "fingerprint":
        return lab.run_fingerprint(
            config,
            args.target,
            _validate_port(args.port),
            protocol=args.protocol,
            profile=args.profile,
        )

    if args.command == "tls":
        return lab.run_tls(
            config, args.target, _validate_port(args.port), profile=args.profile
        )

    if args.command == "cve":
        if not args.online:
            raise PermissionError(
                "aucun appel externe implicite : ajoutez --online"
            )

        return lab.run_cve_online(
            config,
            package=args.package,
            version=args.version,
        )

    raise ValueError(f"commande inconnue: {args.command}")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        # Auth directe avant toute commande et avant la configuration.
        auth_gate.authenticate()
        config = config_module.load_config()

        # Le tableau de bord bloque jusqu'à Ctrl+C : il prend la main avant la
        # sortie JSON du CLI et reste dans ce thread, seul autorisé par authz.
        if args.command == "dashboard":
            return dashboard.serve(config, port=_validate_dashboard_port(args.port))

        report = run(args, config)
    except auth_gate.AuthError as error:
        print(f"[AUTH ERROR] {error}", file=sys.stderr)
        return 2
    except config_module.ConfigError as error:
        print(f"[CONFIG ERROR] {error}", file=sys.stderr)
        return 2
    except PermissionError as error:
        print(f"[REFUS] {error}", file=sys.stderr)
        return 3
    except (OSError, RuntimeError, ValueError) as error:
        print(f"[LAB ERROR] {error}", file=sys.stderr)
        return 1

    if report.get("mode") == "network_discovery":
        print(
            f"[LAB] mode=network_discovery voisins={report['neighbor_count']} "
            "sondes_actives=non",
            file=sys.stderr,
        )
    elif report.get("mode") == "network_scan":
        counts = {
            protocol: len(results)
            for protocol, results in report["protocols"].items()
        }
        print(
            f"[LAB] mode=network_scan cible={report['target']} ports={counts}",
            file=sys.stderr,
        )
    else:
        summary = report.get("risk_summary") or {}
        print(
            f"[LAB] mode={report.get('mode')} "
            f"constats={report.get('findings_count', 0)} "
            f"preuves={summary.get('with_evidence', 0)}/{summary.get('total', 0)}",
            file=sys.stderr,
        )

    if report.get("report_path"):
        print(f"[LAB] rapport: {report['report_path']}", file=sys.stderr)

    for error in report.get("errors") or []:
        print(f"[LAB ERROR] {error}", file=sys.stderr)

    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    sys.stdout.flush()

    return 0


if __name__ == "__main__":
    sys.exit(main())
