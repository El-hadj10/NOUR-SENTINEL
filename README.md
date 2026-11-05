# NOUR SENTINEL

**Intelligent Network Security Engine**

NOUR SENTINEL est un outil modulaire de diagnostic réseau et de sécurité,
combinant Rust, Python et SQLite.

- **Rust** : collecte réseau (ARP passive, TCP concurrent), inventaire local
  des sockets et persistance de l'historique.
- **Python** : six capacités d'analyse — fingerprinting, CVE, TLS, politiques
  d'authentification, journaux, applicatif HTTP.
- **SQLite** : mémoire des scans et de leurs observations.
- **JSON** : contrat versionné entre les deux moteurs (`protocol.json` 3.0).

## Versions

**Version de référence : 0.5.0 — Security Intelligence**

Statut : les six capacités sont implémentées, testées hors ligne et
documentées dans [`docs/SECURITY_INTELLIGENCE.md`](docs/SECURITY_INTELLIGENCE.md).

Provenance :

- v0.4.1 : erreurs d'historique explicites, comparaison de périmètre, tests
  isolés.
- v0.4.0 : historique SQLite transactionnel et détection de changements.
- v0.5.0 : inventaire local, constats explicables et outils externes
  optionnels.

## Les six capacités

| Pilier | Module Python | Ce qu'il produit |
|---|---|---|
| Fingerprinting | `intelligence/fingerprinting/` | Produit, version, service, confiance |
| Intelligence CVE | `intelligence/vulnerabilities/` | Candidats `to_verify` + clients NVD/OSV/KEV/EPSS |
| Audit TLS | `intelligence/tls/` | Protocoles, suites, certificats |
| Mots de passe | `intelligence/passwords/` | `sshd_config`, `login.defs`, `sudoers` |
| Intrusion | `intelligence/intrusion/` | Journald : échecs SSH, comptes, pare-feu |
| Applicatif | `intelligence/applications/` | En-têtes, cookies, méthodes HTTP |

Chaque constat porte `finding_id`, `evidence`, `confidence`,
`confidence_reason`, `severity`, `exposure`, `status` et
`recommendation`. Une sévérité haute ou critique sans preuve est plafonnée à
`medium` et signalée (`severity_capped`).

## Outils externes optionnels

Désactivés par défaut (`tools.enabled: false`), exécutés sans shell,
uniquement sur le périmètre autorisé :

| Outil | Rôle | Configuration |
|---|---|---|
| `nmap` | détection de version (`-sV`) | `tools.nmap` |
| `testssl.sh` | audit TLS et certificats | `tools.testssl` |
| `trivy` | vulnérabilités d'images et de fichiers | `tools.trivy`, `tools.trivy_targets` |

Un outil absent est signalé dans `errors` : l'analyse se poursuit.

## Architecture

```text
NOUR-SENTINEL/
├── rust-engine/       # Scanner TCP, ARP passif, inventaire, historique SQLite
│   └── src/inventory.rs
├── python-brain/      # Analyse et détection Python
│   └── intelligence/  # Six piliers + risk engine + adaptateurs d'outils
├── communication/     # Contrat JSON versionné
├── config/            # Configuration
├── data/              # Historique et artefacts (non versionnés)
├── tests/
│   ├── python/
│   ├── rust/
│   └── integration/
└── docs/
```

## Prérequis

- Linux (`/proc`, `/sys`, table ARP)
- Rust et Cargo
- Python 3 (bibliothèque standard)
- SQLite (inclus via `rusqlite`, feature `bundled`)
- Optionnel : `nmap`, `testssl.sh`, `trivy`, `journalctl`, `iproute2`

## Installation

```bash
cargo build --manifest-path rust-engine/Cargo.toml
```

L'analyzer v0.5.0 n'a aucune dépendance Python.

## Configuration

`config/settings.json` :

| Section | Paramètre | Rôle |
|---|---|---|
| `application` | `version` | Version affichée et reportée |
| `engines.python` | `executable` | Interpréteur Python |
| `network` | `targets` | Adresses IP explicitement autorisées |
| `network` | `ports` | Ports TCP vérifiés (périmètre) |
| `network` | `timeout_ms` | Délai de connexion par port |
| `network` | `max_concurrency` | Workers (plafond 256) |
| `analysis` | `sensitive_ports` | Ports déclenchant une alerte |
| `intelligence` | `local_inventory` | Inventaire `/proc` (activé par défaut) |
| `intelligence` | `active_probing` | Vérifications réseau actives (désactivé) |
| `intelligence` | `http_probe`, `tls_probe` | Sondes HTTP/TLS (désactivées) |
| `intelligence` | `ssh_policy_audit` | Audit `sshd_config`/`login.defs` |
| `intelligence` | `journal_audit`, `journal_lines` | Détection par journald |
| `tools` | `enabled`, `nmap`, `testssl`, `trivy` | Outils externes |
| `security` | `authorized_scanning_only`, `automatic_actions` | Garde-fous |

Variables d'environnement :

- `NOUR_SENTINEL_CONFIG` : configuration alternative.
- `NOUR_SENTINEL_HISTORY_DIR` : répertoire d'historique (tests).

## Exécution

```bash
cargo run --manifest-path rust-engine/Cargo.toml
```

Le rapport JSON final contient :

- `capabilities` : les six piliers exécutés ;
- `inventory` : hôte, interfaces et sockets attribués (`pid`, `process`,
  `unit`, `container`, `confidence`) ;
- `services` : produits identifiés localement ;
- `findings` : constats normalisés triés par `priority_score` ;
- `risk_summary` : répartition par gravité, priorité et statut ;
- `tools_used` et `errors` : outils réellement exécutés et échecs explicites ;
- `history` : `recorded`, `not_recorded` ou `unavailable`.

Exemple de constat :

```json
{
  "finding_id": "f-0123456789ab",
  "check": "exposure.wildcard.22",
  "observation": "Écoute sur l'interface générique (port 22)",
  "evidence": "socket:0.0.0.0:22; pid=1234; process=sshd; unit=ssh.service",
  "confidence": "confirmed",
  "severity": "medium",
  "exposure": "lan",
  "status": "open",
  "priority_score": 4.5,
  "priority": "P2"
}
```

## Historique, sauvegarde et restauration

La base se trouve par défaut dans `data/history/nour_sentinel.db`.

- Sauvegarde : `cp data/history/nour_sentinel.db sauvegarde-nour.db`.
- Restauration : arrêter le moteur, remplacer le fichier, relancer.
- Compatibilité : une base v0.4.0 est migrée automatiquement au premier
  démarrage.

## Tests

```bash
cargo test --manifest-path rust-engine/Cargo.toml   # 41 tests unitaires Rust
python3 -m unittest discover -s tests/python        # 82 tests Python
python3 -m unittest discover -s tests/integration   # 8 tests d'intégration
```

Les tests n'ouvrent aucune connexion externe : fixtures pour `nmap`,
`testssl.sh`, `trivy` et journald ; historique et configuration temporaires.

## Sécurité

Utiliser cet outil uniquement sur des systèmes et réseaux pour lesquels vous
disposez d'une autorisation explicite.

- La découverte ARP est strictement passive (`/proc/net/arp`).
- La vérification TCP est active, uniquement vers les cibles déclarées.
- Les vérifications actives d'intelligence et les outils externes sont
  désactivés par défaut et limités au périmètre autorisé.
- Aucune exploitation, aucun brute force, aucune collecte de secrets.
- Aucun blocage automatique, aucune remédiation automatique.
- Un port ouvert est une exposition présumée, jamais une vulnérabilité
  confirmée.
- Une alerte haute ou critique sans preuve est plafonnée à `medium`.

## Limites connues

- La base CVE embarquée est réduite et hors ligne ; les statuts restent
  `to_verify` tant que les correctifs de distribution ne sont pas vérifiés.
- L'attribution d'un socket d'un autre utilisateur exige des privilèges
  suffisants ; à défaut, le propriétaire (`uid`/`user`) reste identifié depuis
  `/proc/net/tcp`, mais le processus et l'unité sont inconnus.
- L'analyse de certificat dépend d'un certificat décodé ou de `testssl.sh`.
- Les alertes issues des journaux sont des signaux à investiguer, pas des
  preuves de compromission.
- La découverte ARP n'est pas encore reliée au scan TCP.
