"""Audit des politiques d'authentification, sans jamais lire de secret.

Aucun mot de passe, aucune empreinte et aucune tentative de connexion :
seules les directives de configuration sont examinées.
"""

from intelligence.models import make_finding

SSH_REFERENCE = "https://www.ssh.com/academy/ssh/sshd_config"


def _is_yes(value, default=False):
    if value is None:
        return default

    return str(value).strip().lower() in ("yes", "true", "on", "1")


def parse_sshd_config(text):
    """Extrait les directives effectives (dernière valeur gagnante).

    Les blocs `Match` conditionnels sont ignorés : leur portée dépend du
    client et ne peut pas être évaluée hors contexte.
    """

    directives = {}
    in_match = False

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""

        if key == "match":
            in_match = value.strip().lower() != "all"
            continue

        if in_match:
            continue

        directives[key] = value

    return directives


def audit_ssh_policy(directives, asset="localhost", exposure="lan"):
    """Constats sur les directives SSH effectives."""

    findings = []

    def add(check, observation, evidence, severity, recommendation):
        findings.append(
            make_finding(
                asset=asset,
                check=f"ssh_policy.{check}",
                component="OpenSSH",
                service="SSH",
                observation=observation,
                evidence=evidence,
                confidence="confirmed",
                severity=severity,
                exposure=exposure,
                recommendation=recommendation,
                references=[SSH_REFERENCE],
            )
        )

    root_login = str(directives.get("permitrootlogin", "")).strip().lower()

    if root_login == "yes":
        add(
            "root_login",
            "Connexion directe de root autorisée",
            "sshd_config:PermitRootLogin yes",
            "high",
            "Désactiver PermitRootLogin ou utiliser prohibit-password.",
        )

    if _is_yes(directives.get("passwordauthentication")):
        add(
            "password_auth",
            "Authentification par mot de passe autorisée",
            "sshd_config:PasswordAuthentication yes",
            "medium",
            "Privilégier les clés et désactiver PasswordAuthentication.",
        )

    if not _is_yes(directives.get("pubkeyauthentication"), default=True):
        add(
            "pubkey_disabled",
            "Authentification par clé publique désactivée",
            "sshd_config:PubkeyAuthentication no",
            "high",
            "Réactiver PubkeyAuthentication et auditer les clés autorisées.",
        )

    if _is_yes(directives.get("permitemptypasswords")):
        add(
            "empty_passwords",
            "Mots de passe vides autorisés",
            "sshd_config:PermitEmptyPasswords yes",
            "critical",
            "Désactiver immédiatement PermitEmptyPasswords.",
        )

    if _is_yes(directives.get("x11forwarding")):
        add(
            "x11_forwarding",
            "Redirection X11 activée",
            "sshd_config:X11Forwarding yes",
            "low",
            "Désactiver X11Forwarding si non nécessaire.",
        )

    try:
        max_tries = int(str(directives.get("maxauthtries", "")).strip())
    except (TypeError, ValueError):
        max_tries = None

    if max_tries is not None and max_tries > 6:
        add(
            "max_auth_tries",
            f"MaxAuthTries élevé ({max_tries})",
            f"sshd_config:MaxAuthTries {max_tries}",
            "low",
            "Réduire MaxAuthTries à 6 ou moins.",
        )

    methods = str(directives.get("authenticationmethods", ""))

    if methods and "password" in methods.lower() and "publickey" not in methods.lower():
        add(
            "auth_methods",
            "Seul le mot de passe figure dans AuthenticationMethods",
            f"sshd_config:AuthenticationMethods {methods}",
            "medium",
            "Ajouter publickey à AuthenticationMethods.",
        )

    return findings


def parse_login_defs(text):
    values = {}

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        # login.defs historique utilise des espaces ; les fichiers modernes
        # acceptent aussi KEY=value.
        if "=" in line:
            key, value = line.split("=", 1)
        else:
            parts = line.split(None, 1)

            if len(parts) != 2:
                continue

            key, value = parts

        values[key.strip().upper()] = value.strip()

    return values


def audit_login_defs(text, asset="localhost", exposure="lan"):
    """Constats sur `/etc/login.defs` (valeurs explicitement définies)."""

    values = parse_login_defs(text)
    findings = []

    def add(check, observation, evidence, severity, recommendation):
        findings.append(
            make_finding(
                asset=asset,
                check=f"password_policy.{check}",
                component="PAM/login.defs",
                observation=observation,
                evidence=evidence,
                confidence="confirmed",
                severity=severity,
                exposure=exposure,
                recommendation=recommendation,
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
                ],
            )
        )

    def integer(name):
        try:
            return int(values.get(name, ""))
        except (TypeError, ValueError):
            return None

    max_days = integer("PASS_MAX_DAYS")

    if max_days is not None and (max_days > 365 or max_days == 99999):
        add(
            "password_expiration",
            f"Expiration des mots de passe trop lointaine ({max_days} jours)",
            f"login.defs:PASS_MAX_DAYS {max_days}",
            "medium",
            "Réduire PASS_MAX_DAYS à 365 jours ou moins.",
        )

    min_length = integer("PASS_MIN_LEN")

    if min_length is not None and min_length < 12:
        add(
            "password_length",
            f"Longueur minimale faible ({min_length})",
            f"login.defs:PASS_MIN_LEN {min_length}",
            "medium",
            "Imposer au moins 12 caractères et une politique de phrases de passe.",
        )

    warn_age = integer("PASS_WARN_AGE")

    if warn_age is not None and warn_age < 7:
        add(
            "password_warning",
            f"Avertissement d'expiration trop court ({warn_age} jours)",
            f"login.defs:PASS_WARN_AGE {warn_age}",
            "low",
            "Prévenir au moins 7 jours avant expiration.",
        )

    method = values.get("ENCRYPT_METHOD", "").upper()

    if method and method not in ("SHA512", "YESCRYPT"):
        add(
            "password_hash",
            f"Algorithme de hachage faible ({method})",
            f"login.defs:ENCRYPT_METHOD {method}",
            "medium",
            "Utiliser SHA512 ou YESCRYPT.",
        )

    return findings


def audit_sudoers(text, asset="localhost", exposure="lan"):
    """Détecte les délégations sans mot de passe (NOPASSWD)."""

    findings = []

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "NOPASSWD" not in line.upper():
            continue

        findings.append(
            make_finding(
                asset=asset,
                check="sudo_policy.nopasswd",
                component="sudoers",
                observation="Règle sudo sans mot de passe",
                evidence=f"sudoers:{line[:200]}",
                confidence="confirmed",
                severity="medium",
                exposure=exposure,
                recommendation=(
                    "Vérifier que cette délégation est nécessaire et limitée "
                    "aux commandes strictement requises."
                ),
                references=["https://www.sudo.ws/docs/man/sudoers.man/"],
            )
        )

    return findings
