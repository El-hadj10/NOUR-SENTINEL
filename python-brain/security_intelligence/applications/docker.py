"""Inventaire Docker en lecture seule.

Seule commande exécutée : `docker ps --no-trunc --format {{json .}}`.
Aucun démarrage, arrêt, création ou modification de conteneur.
"""

import json

import authz
from intelligence.models import make_finding
from security_intelligence import collection_trace
from security_intelligence.fingerprinting.inventory import run_command


def parse_docker_ps(lines):
    containers = []

    for line in lines or []:
        text = str(line).strip()

        if not text:
            continue

        try:
            entry = json.loads(text)
        except ValueError:
            continue

        if not isinstance(entry, dict):
            continue

        containers.append(
            {
                "id": str(entry.get("ID") or "")[:12],
                "name": entry.get("Names"),
                "image": entry.get("Image"),
                "state": entry.get("State"),
                "status": entry.get("Status"),
                "ports": entry.get("Ports"),
            }
        )

    return containers


@collection_trace.instrument("application", "docker.collect")
def collect(config, host, runner=None):
    """Retourne `(findings, metadata, errors)` sans action sur les conteneurs."""

    authz.require()

    if not (config or {}).get("docker", {}).get("enabled", True):
        return [], {"containers": []}, []

    runner = runner or run_command

    result = runner(
        ["docker", "ps", "--no-trunc", "--format", "{{json .}}"],
        15,
    )

    if result.get("returncode") != 0:
        message = str(result.get("stderr") or "").strip()[:160] or "échec"
        return [], {"containers": []}, [f"docker ps: {message}"]

    containers = parse_docker_ps(
        str(result.get("stdout") or "").splitlines()
    )
    findings = []

    for container in containers:
        name = container.get("name") or container.get("id") or "conteneur"
        image = container.get("image") or "image inconnue"

        findings.append(
            make_finding(
                asset=host,
                check="docker.container",
                component="Docker",
                observation=f"Conteneur en cours d'exécution : {name} ({image})",
                evidence=f"docker:ps name={name}; image={image}",
                confidence="confirmed",
                severity="info",
                exposure="local",
                recommendation=(
                    "Vérifier l'image, sa provenance et les mises à jour."
                ),
            )
        )

        ports = str(container.get("ports") or "")

        if "0.0.0.0:" in ports or "[::]:" in ports:
            findings.append(
                make_finding(
                    asset=host,
                    check="docker.published_port",
                    component="Docker",
                    observation=(
                        f"Port de conteneur publié sur toutes les interfaces : {name}"
                    ),
                    evidence=f"docker:ports={ports[:200]}",
                    confidence="confirmed",
                    confidence_reason=(
                        "La portée réelle dépend du pare-feu et du routage."
                    ),
                    severity="medium",
                    exposure="lan",
                    recommendation=(
                        "Publier le port sur 127.0.0.1 ou restreindre l'accès "
                        "par le pare-feu."
                    ),
                )
            )

    return findings, {"containers": containers}, []
