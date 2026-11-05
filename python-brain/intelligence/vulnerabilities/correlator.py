"""Corrélation CVE hors ligne (pilier 2).

La base embarquée ne remplace pas NVD/OSV/KEV/EPSS : elle fournit des
*candidats* traçables. Un correctif rétroporté par la distribution peut rendre
une version ancienne non vulnérable, donc aucun constat n'est « applicable
confirmée » sans vérification du paquet.
"""

import json
from pathlib import Path

from intelligence.models import make_finding

DEFAULT_DB = Path(__file__).with_name("advisories.json")


def parse_version(text):
    """`9.7p1` -> (9, 7). S'arrête à la première partie non numérique."""

    parts = []
    cleaned = str(text or "").strip()

    for chunk in cleaned.split("."):
        digits = ""

        for character in chunk:
            if character.isdigit():
                digits += character
            else:
                break

        if not digits:
            break

        parts.append(int(digits))

        # Suffixe amont (9.7p1) ou révision de distribution
        # (2.4.58-1ubuntu4) : la version amont s'arrête ici.
        if len(digits) != len(chunk):
            break

    return tuple(parts)


def compare_versions(left, right):
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    length = max(len(left_parts), len(right_parts))

    for index in range(length):
        left_value = left_parts[index] if index < len(left_parts) else 0
        right_value = right_parts[index] if index < len(right_parts) else 0

        if left_value != right_value:
            return -1 if left_value < right_value else 1

    return 0


def version_in_range(version, minimum=None, maximum=None):
    parsed = parse_version(version)

    if not parsed:
        return False

    if minimum and compare_versions(version, minimum) < 0:
        return False

    if maximum and compare_versions(version, maximum) > 0:
        return False

    return True


def load_advisories(path=None):
    """Charge la base locale. Retourne `[]` si elle est absente ou invalide."""

    try:
        content = Path(path or DEFAULT_DB).read_text(encoding="utf-8")
        data = json.loads(content)
    except (OSError, ValueError):
        return []

    return data if isinstance(data, list) else []


def correlate(products, advisories=None, exposure=None):
    """Confronte des produits identifiés à la base locale."""

    database = advisories if advisories is not None else load_advisories()
    findings = []

    for product in products or []:
        if not isinstance(product, dict):
            continue

        name = str(product.get("product") or "").strip().lower()
        version = product.get("version")

        if not name or not version:
            continue

        for advisory in database:
            if str(advisory.get("product", "")).strip().lower() != name:
                continue

            if not version_in_range(
                version,
                advisory.get("affected_min"),
                advisory.get("affected_max"),
            ):
                continue

            cve = advisory.get("cve")
            fixed_in = advisory.get("fixed_in")
            asset = product.get("asset") or product.get("ip") or "unknown"

            findings.append(
                make_finding(
                    asset=asset,
                    ip=product.get("ip"),
                    port=product.get("port"),
                    service=product.get("service"),
                    component=product.get("product"),
                    check=f"cve.{cve}",
                    observation=(
                        f"{product.get('product')} {version} correspond à la plage "
                        f"affectée de {cve}"
                    ),
                    evidence=(
                        f"version={version}; source={product.get('evidence')}; "
                        f"base_locale={cve}"
                    ),
                    confidence=product.get("confidence", "probable"),
                    confidence_reason=(
                        "Correspondance de version uniquement : correctifs de "
                        "distribution et conditions réelles d'exploitation non vérifiés."
                    ),
                    severity=advisory.get("severity", "medium"),
                    exposure=exposure or product.get("exposure", "unknown"),
                    recommendation=(
                        f"Vérifier la version du paquet de la distribution et les "
                        f"correctifs rétroportés. Version corrigée amont : {fixed_in}."
                    ),
                    references=[advisory.get("reference"), advisory.get("summary")]
                    if advisory.get("reference")
                    else [advisory.get("summary")],
                    status="to_verify",
                    cve=cve,
                    kev=bool(advisory.get("kev")),
                    epss=advisory.get("epss"),
                    metadata={
                        "offline": True,
                        "fixed_in": fixed_in,
                        "summary": advisory.get("summary"),
                        "note": advisory.get("notes"),
                    },
                )
            )

    return findings
