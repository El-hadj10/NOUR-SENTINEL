"""CLI du laboratoire Security Intelligence.

L'authentification Argon2id est vérifiée avant chaque commande
opérationnelle, sans session réutilisable. La sortie standard ne contient que
le rapport JSON ; les messages humains vont sur la sortie d'erreur.
"""

import argparse
import json
import sys

from security_intelligence import VERSION, auth_gate, config as config_module, lab


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

    fingerprint = commands.add_parser(
        "fingerprint", help="une bannière SSH ou un HEAD HTTP autorisé"
    )
    fingerprint.add_argument("--target", required=True)
    fingerprint.add_argument("--port", required=True, type=int)
    fingerprint.add_argument(
        "--protocol", choices=("ssh", "http"), default="http"
    )

    tls = commands.add_parser("tls", help="négociation TLS 1.2/1.3 et certificat")
    tls.add_argument("--target", required=True)
    tls.add_argument("--port", required=True, type=int)

    cve = commands.add_parser("cve", help="recherche OSV/KEV/EPSS explicite")
    cve.add_argument("--online", action="store_true")
    cve.add_argument("--package")
    cve.add_argument("--version")

    return parser


def _validate_port(port):
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port TCP invalide (1-65535)")

    return port


def run(args, config):
    if args.command == "inventory":
        return lab.run_inventory(config)

    if args.command == "full-local":
        return lab.run_full_local(config)

    if args.command == "fingerprint":
        return lab.run_fingerprint(
            config,
            args.target,
            _validate_port(args.port),
            protocol=args.protocol,
        )

    if args.command == "tls":
        return lab.run_tls(config, args.target, _validate_port(args.port))

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
