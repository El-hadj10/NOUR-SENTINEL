# NOUR SENTINEL — Security Intelligence (v0.5.0)

## 1. Objectif

Passer d'un scanner qui observe des ports à un moteur qui explique ce qu'il
voit : quel processus écoute, quel logiciel est présent, quelle configuration
est risquée, sur quelle preuve repose le constat, avec quel niveau de
confiance, et quelle vérification humaine reste nécessaire.

## 2. Répartition des responsabilités

| Couche | Responsabilité | Preuves produites |
|---|---|---|
| Rust (`inventory.rs`) | Sockets TCP/UDP, processus, unités systemd, conteneurs, interfaces | `/proc`, `/sys`, `ip -j addr` |
| JSON (`protocol.json` 3.0) | Contrat versionné collecte → analyse | Schéma des constats |
| Python (`intelligence/`) | Six capacités d'analyse | Constats normalisés |
| Risk engine | Déduplication, score, priorisation | `priority_score`, `P1..P4` |
| SQLite (`history.rs`) | Mémoire des scans | `scan_id`, changements |

Rust ne conclut pas ; Python ne modifie rien ; aucun module n'agit sur le
système audité.

## 3. Les six capacités

### Pilier 1 — Service & Software Fingerprinting

- `intelligence/fingerprinting/services.py`.
- Deux sources distinctes : processus local (`confirmed`) et bannière
  (`probable`).
- Signatures : OpenSSH, Apache, nginx, IIS, vsftpd, ProFTPD, Postfix, Exim,
  Redis, API Docker.
- Corrélation possible avec `unit` et conteneur fournis par Rust.

### Pilier 2 — Vulnerability Intelligence

- `intelligence/vulnerabilities/correlator.py` + `advisories.json`.
- Fonctionne **hors ligne** : la base embarquée fournit des candidats.
- Statut systématique `to_verify` : une correspondance de version n'est pas
  une vulnérabilité applicable, les correctifs rétroportés doivent être
  examinés.
- `clients.py` fournit NVD, OSV, KEV et EPSS, jamais appelés automatiquement.
- Règle : sévérité critique sans preuve ou confiance suffisante → plafonnée à
  `medium` (`severity_capped: true`).

### Pilier 3 — TLS & Cryptographic Audit

- `intelligence/tls/analyzer.py`.
- Protocoles obsolètes, suites faibles, force de chiffrement, certificat
  (expiration, auto-signature, clé courte, signature SHA-1/MD5).
- Le certificat est analysé à partir d'un dictionnaire déjà décodé : la
  collecte fine (chaîne, SAN) est déléguée à `testssl.sh`.
- `inspect()` ne s'exécute que si `intelligence.tls_probe` est actif et la
  cible autorisée.

### Pilier 4 — Password & Authentication Audit

- `intelligence/passwords/policy_audit.py`.
- `sshd_config` : `PermitRootLogin`, `PasswordAuthentication`,
  `PubkeyAuthentication`, `PermitEmptyPasswords`, `MaxAuthTries`,
  `AuthenticationMethods`, `X11Forwarding`. Les blocs `Match` sont ignorés.
- `login.defs` : expiration, longueur minimale, avertissement, algorithme.
- `PASS_MAX_DAYS` : `99999` (pas d'expiration forcée) n'est plus signalé ;
  une rotation inférieure à 90 jours est un signal `low`, pas un verdict.
  Le seuil est **contextuel** : NIST SP 800-63B §5.1.1.2 déconseille la
  rotation arbitraire, tandis que PCI DSS v4.0 (8.3.9) impose 90 jours aux
  comptes concernés. La recommandation renvoie à ces deux cadres.
- `sudoers` : règles `NOPASSWD`.
- Aucun mot de passe, aucune empreinte, aucune tentative de connexion.

### Pilier 5 — Host Intrusion Detection

- `intelligence/intrusion/detector.py`.
- Entrées `journalctl -o json` parsées hors ligne.
- Détections : rafale d'échecs SSH, succès après échecs, création de compte,
  commande sudo, démarrage de service, changement de pare-feu.
- Chaque constat conserve l'extrait de journal et reste `to_verify`.

### Pilier 6 — Application Security Analyzer

- `intelligence/applications/http_analyzer.py`.
- En-têtes de sécurité manquants, divulgation de version, CORS wildcard avec
  identifiants, cookies sans `HttpOnly`/`Secure`/`SameSite`, méthodes
  `TRACE`/`PUT`/`DELETE`.
- `probe_http()` envoie une seule requête `HEAD` et seulement si
  `intelligence.http_probe` est actif.

## 4. Outils externes optionnels

Désactivés par défaut (`tools.enabled: false`), jamais exécutés par les tests.

| Outil | Usage | Garde-fou |
|---|---|---|
| `nmap` | `-sV --version-light` sur une cible autorisée | argv en liste, pas de shell |
| `testssl.sh` | audit TLS et certificats, sortie JSON | fichiers temporaires, port TLS uniquement |
| `trivy` | images et systèmes de fichiers (`vuln,config`) | cibles explicites dans `trivy_targets` |

Un outil absent n'interrompt jamais l'analyse : il est signalé dans
`errors`, et `tools_used` reste vide.

## 5. Format des constats

Champs principaux : `finding_id` (stable), `asset_id`, `ip`, `port`,
`service`, `component`, `check`, `observation`, `evidence`, `confidence`,
`confidence_reason`, `severity`, `severity_capped`, `exposure`,
`recommendation`, `references`, `status`, `first_seen`, `last_seen`, `cve`,
`kev`, `epss`, `priority_score`, `priority`.

Statuts : `open`, `to_verify`, `fixed`, `not_applicable`, `accepted`.

Niveaux de confiance : `confirmed`, `corroborated`, `probable`, `low`,
`unknown`.

## 6. Score et priorisation

```text
score = base(gravité) × facteur(confiance) × facteur(exposition)
      + 2 si KEV + 2 × EPSS
```

- `P1 ≥ 7`, `P2 ≥ 4.5`, `P3 ≥ 2`, `P4` sinon.
- Le score ordonne, il ne décide pas : la recommandation reste dans le
  constat.

## 7. Garde-fous

- Le scanner Rust ne balaie pas automatiquement les appareils ARP. Dans le
  laboratoire Python, la découverte reste passive et un seul voisin choisi
  explicitement peut être sondé après confirmation d'autorisation, avec un
  plafond de 32 ports par protocole.
- Aucune exploitation, aucun brute force, aucune action automatique.
- Aucune collecte de secrets.
- `active_probing` désactivé par défaut ; vérifications actives uniquement
  vers `network.targets`.
- Une alerte haute ou critique sans preuve ni confiance est plafonnée.
- Toute exposition est qualifiée de *présumée* : pare-feu, NAT et routage ne
  sont pas déduits d'une simple écoute.

## 8. Limites assumées

- La base CVE embarquée est volontairement réduite et hors ligne.
- L'attribution du *processus* échoue sans privilèges suffisants ; le
  propriétaire du socket (`uid`, `user`) reste néanmoins identifié depuis
  `/proc/net/tcp`, et le constat reste `inventory.attribution.*` en confiance
  `low`.
- L'analyse de certificat dépend d'un certificat déjà décodé ou de
  `testssl.sh`.
- Les détections par journaux ne sont pas des preuves de compromission.
- Aucune analyse multi-scans au-delà de la comparaison de périmètre existante.
