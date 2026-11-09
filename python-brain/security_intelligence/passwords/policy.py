"""Audit des politiques d'authentification effectives.

`sshd -T` lit la configuration effective sans se connecter. Aucun accès à
`/etc/shadow`, aucun hash, aucune tentative d'authentification.
"""

from pathlib import Path

import authz
from intelligence.models import make_finding
from intelligence.passwords import policy_audit
from security_intelligence import collection_trace
from security_intelligence.fingerprinting.inventory import run_command

SSHD_CONFIG = "/etc/ssh/sshd_config"
LOGIN_DEFS = "/etc/login.defs"
PAM_COMMON_PASSWORD = "/etc/pam.d/common-password"


def parse_sshd_effective(text):
    directives = {}

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split(None, 1)

        if len(parts) != 2:
            continue

        directives[parts[0].strip().lower()] = parts[1].strip()

    return directives


@collection_trace.instrument("system", "policy.read_effective_sshd")
def read_effective_sshd(config_path=None, runner=None):
    """Retourne `(directives, erreur)` depuis `sshd -T`."""

    authz.require()
    runner = runner or run_command
    argv = ["sshd", "-T"]

    if config_path:
        argv.extend(["-f", str(config_path)])

    result = runner(argv, 10)

    if result.get("returncode") != 0:
        return {}, (
            f"sshd -T: {str(result.get('stderr') or '').strip()[:160] or 'échec'}"
        )

    return parse_sshd_effective(result.get("stdout")), None


def parse_pam_common_password(text):
    """Extrait les options explicites de pam_pwquality et pam_unix."""

    parsed = {"pwquality": {}, "unix": {}, "modules": []}

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 3:
            continue

        # Le champ de contrôle PAM peut contenir une espace, par exemple
        # `[success=1 default=ignore]`. On repère donc le module par son nom
        # au lieu de supposer qu'il est toujours en troisième position.
        module_index = next(
            (
                index
                for index, token in enumerate(parts)
                if token in ("pam_pwquality.so", "pam_unix.so")
            ),
            None,
        )

        if module_index is None:
            continue

        module = parts[module_index]
        options = {}

        for token in parts[module_index + 1 :]:
            if "=" in token:
                key, value = token.split("=", 1)
                options[key] = value
            else:
                options[token] = True

        if module == "pam_pwquality.so":
            parsed["pwquality"] = options
        else:
            parsed["unix"] = options

        parsed["modules"].append(module)

    return parsed


def audit_pam(text, asset="localhost", exposure="local"):
    """Constats sur la politique PAM effective, sans lire de secret."""

    parsed = parse_pam_common_password(text)
    findings = []

    def add(check, observation, evidence, severity, recommendation, confidence="confirmed", status="open"):
        findings.append(
            make_finding(
                asset=asset,
                check=f"password_policy.{check}",
                component="PAM",
                observation=observation,
                evidence=evidence,
                confidence=confidence,
                severity=severity,
                exposure=exposure,
                recommendation=recommendation,
                status=status,
            )
        )

    if not parsed["modules"]:
        add(
            "pam_policy_absent",
            "Aucune politique PAM de mot de passe lisible",
            "pam:common-password:absent",
            "info",
            "Vérifier /etc/pam.d/common-password et la politique de complexité.",
            confidence="low",
            status="to_verify",
        )
        return findings

    minlen = parsed["pwquality"].get("minlen")

    try:
        minlen_value = int(str(minlen)) if minlen is not None else None
    except ValueError:
        minlen_value = None

    if minlen_value is not None and minlen_value < 12:
        add(
            "pam_min_length",
            f"Longueur minimale PAM faible ({minlen_value})",
            f"pam:pwquality:minlen={minlen_value}",
            "medium",
            "Imposer minlen=12 ou davantage et une politique de phrases de passe.",
        )

    remember = parsed["unix"].get("remember")

    try:
        remember_value = int(str(remember)) if remember is not None else None
    except ValueError:
        remember_value = None

    if remember_value is not None and remember_value < 5:
        add(
            "pam_history",
            f"Historique de mots de passe trop court ({remember_value})",
            f"pam:pam_unix:remember={remember_value}",
            "low",
            "Conserver au moins 5 mots de passe précédents.",
        )

    hashing = str(parsed["unix"].get("yescrypt", "") or "").lower()
    # Les algorithmes sont des options sans valeur (`md5`, `yescrypt`),
    # pas des valeurs : on inspecte donc les clés.
    algorithms = " ".join(str(key) for key in parsed["unix"].keys()).lower()

    if "md5" in algorithms:
        add(
            "pam_hash_md5",
            "PAM accepte MD5 pour les mots de passe",
            "pam:pam_unix:md5",
            "medium",
            "Utiliser yescrypt ou SHA-512.",
        )
    elif "sha256" in algorithms:
        add(
            "pam_hash_sha256",
            "PAM utilise SHA-256 pour les mots de passe",
            "pam:pam_unix:sha256",
            "low",
            "Préférer yescrypt ou SHA-512.",
        )

    if not hashing and "yescrypt" not in algorithms and "sha512" not in algorithms:
        add(
            "pam_hash_unspecified",
            "Algorithme de hachage PAM non explicitement fort",
            "pam:pam_unix:hash=unspecified",
            "low",
            "Vérifier l'algorithme effectif (yescrypt ou SHA-512).",
            confidence="low",
            status="to_verify",
        )

    return findings


@collection_trace.instrument("system", "policy.collect")
def collect(config, host, exposure="local", runner=None):
    """Collecte SSH effectif, login.defs et PAM ; retourne findings/meta/errors."""

    authz.require()
    findings = []
    errors = []
    metadata = {
        "sshd_effective": False,
        "login_defs": False,
        "pam": False,
    }

    directives, error = read_effective_sshd(runner=runner)

    if error:
        errors.append(error)
    else:
        metadata["sshd_effective"] = True
        findings.extend(
            policy_audit.audit_ssh_policy(directives, asset=host, exposure=exposure)
        )

    try:
        login_defs = Path(LOGIN_DEFS).read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        errors.append(f"login.defs illisible: {error}")
    else:
        metadata["login_defs"] = True
        findings.extend(
            policy_audit.audit_login_defs(login_defs, asset=host, exposure=exposure)
        )

    try:
        pam = Path(PAM_COMMON_PASSWORD).read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        errors.append(f"PAM common-password illisible: {error}")
    else:
        metadata["pam"] = True
        findings.extend(audit_pam(pam, asset=host, exposure=exposure))

    return findings, metadata, errors
