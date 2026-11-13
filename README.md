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

Les rapports exposent trois versions distinctes, additives aux champs
historiques `version`/`base_version` : `core_version` (moteur 0.5.0),
`lab_version` (0.6.0-beta.4) et `protocol_version` (3.0).

## Versions

**Ligne stable de référence : 0.5.0 — Security Intelligence**

Statut : les six capacités sont implémentées, testées hors ligne et
documentées dans [`docs/SECURITY_INTELLIGENCE.md`](docs/SECURITY_INTELLIGENCE.md).

**Laboratoire : 0.6.0-beta.4 — Security Intelligence Lab**

Couche additive au-dessus de la v0.5.0 : authentification propriétaire
Argon2id directe (sans session), CLI `--intel`, liste blanche locale,
connecteurs OSV/NVD/KEV/EPSS, rapports privés et base SQLite dédiée. Dossier
complet : [`docs/SECURITY_INTELLIGENCE_LAB.md`](docs/SECURITY_INTELLIGENCE_LAB.md).

Le laboratoire est volontairement séparé de la ligne stable ; aucun tag n'est
déplacé et la fusion exige un rebasage puis un audit complet.

Provenance :

- v0.4.1 : erreurs d'historique explicites, comparaison de périmètre, tests
  isolés.
- v0.4.0 : historique SQLite transactionnel et détection de changements.
- v0.5.0 : inventaire local, constats explicables et outils externes
  optionnels.
- 0.6.0-beta.1 : Auth Gate Argon2id, lanceur, CLI authentifié, liste blanche,
  collecteurs locaux et connecteurs externes explicites.
- 0.6.0-beta.2 : suppression de la session forgeable, Argon2id direct à
  chaque lancement, verrou `flock`, compteur persistant et E2E PTY.
- 0.6.0-beta.3 : entrées Python directes fermées, jeton mémoire non
  persistant et Auth Gate Python avant toute collecte Rust.
- 0.6.0-beta.4 : tableau de bord local (`--intel dashboard`) — options en
  boutons, ondes `/proc/net/dev` et rapport détaillé, garde-fous inchangés.

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

## Laboratoire 0.6.0-beta.4

```bash
./lancer-nour-sentinel.sh --setup-deps   # venv + argon2-cffi
./lancer-nour-sentinel.sh --setup-auth   # secret Argon2id initial
./lancer-nour-sentinel.sh                # moteur Rust après authentification

./lancer-nour-sentinel.sh --intel inventory
./lancer-nour-sentinel.sh --intel full-local
./lancer-nour-sentinel.sh --intel discover
./lancer-nour-sentinel.sh --intel scan --target 192.168.1.1 --protocol both --confirm-authorized
GATEWAY="$(ip -4 route show default | awk '$1 == "default" && $2 == "via" {print $3}')"
./lancer-nour-sentinel.sh --intel tls --target "$GATEWAY" --port 8443
./lancer-nour-sentinel.sh --intel cve --online
./lancer-nour-sentinel.sh --intel dashboard   # puis ouvrir l'URL affichée
```

- Rust démarre le cerveau Python avant toute configuration ; `main.py`
  exécute Argon2id sous terminal et n'émet `AUTH_OK` qu'après succès. Le CLI
  vérifie Argon2id avant chaque commande. Aucune session n'est créée.
- `intelligence.engine.analyze()` et les fonctions `lab.run_*` exigent une
  autorisation mémoire délivrée par l'Auth Gate ; un import direct ne collecte
  rien.
- La cible réseau par défaut est `default_gateway` : l'adresse IPv4 de la
  passerelle est résolue à l'exécution, sans être stockée dans les fichiers.
  Une route privée unique est exigée pour TLS/fingerprint. `discover` lit la
  table ARP locale sans envoyer de paquets ; `scan` sonde une seule IPv4
  RFC1918 choisie dans cette liste, après confirmation
  `--confirm-authorized`. Les listes TCP et UDP sont limitées à 32 ports
  chacune et les résultats ne sont pas enregistrés dans les rapports ou la
  base.
- Les sondes du laboratoire restent limitées à la cible exacte autorisée dans
  `config/security_intelligence.json`. Pour `--intel tls` ou `fingerprint`,
  indique l'IP de la box affichée par `ip -4 route show default`.
  `full-local` ne lance aucun réseau.
- Rapports JSON en 0600 sous `data/reports/`, base
  `data/history/nour_sentinel_intel.db`, dossiers en 0700.
- `--intel dashboard` sert une interface locale sur `127.0.0.1` : un jeton de
  session dans le fragment d'URL, un panneau de boutons qui sélectionnent une
  capacité du laboratoire (rien n'est collecté avant le clic sur « Exécuter »),
  les ondes du trafic réel lues dans `/proc/net/dev` avec le débit de chaque
  interface trié par activité, et le rapport détaillé de l'option lancée, sous
  les ondes. Aucun accès hors de la boucle locale, et aucun garde-fou levé :
  confirmation, liste blanche et plafond de 32 ports s'appliquent à l'identique.
- OSV/NVD/KEV/EPSS ne sont jamais appelés implicitement : `--online` est
  requis, avec cache et budget de requêtes.

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
- Python 3 (bibliothèque standard pour l'analyzer stable)
- `python3-venv` et `argon2-cffi` pour le laboratoire (installés par le lanceur)
- SQLite (inclus via `rusqlite`, feature `bundled`)
- Optionnel : `nmap`, `testssl.sh`, `trivy`, `journalctl`, `iproute2`

## Installation

```bash
cargo build --manifest-path rust-engine/Cargo.toml
```

L'analyzer v0.5.0 n'a aucune dépendance Python. Le laboratoire installe
`argon2-cffi` dans `.venv` via `./lancer-nour-sentinel.sh --setup-deps`.

## Configuration

`config/settings.json` :

L'interpréteur Python n'est plus configurable : le binaire utilise
systématiquement `.venv/bin/python`, validé avant le handshake. Le champ
obsolète `engines.python.executable` a été supprimé.

| Section | Paramètre | Rôle |
|---|---|---|
| `application` | `version` | Version affichée et reportée |
| `engines.python` | `enabled` | Active le cerveau Python |
| `network` | `targets` | `default_gateway` (passerelle IPv4 RFC1918 unique) ou IP explicitement autorisées |
| `network` | `discover_arp` | Découverte passive des voisins (désactivée par défaut) |
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

- `capabilities` : les six piliers déclarés ; `capability_status` : statut réel
  (`started`, `completed`, `failed`, `disabled`, `no_data`,
  `blocked_missing_permission`) avec sa raison. Un démarrage n'est jamais
  présenté comme un succès ;
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
cargo test --manifest-path rust-engine/Cargo.toml   # 52 tests unitaires Rust
.venv/bin/python -m unittest discover -s tests/python # 253 tests Python (lab complet)
.venv/bin/python -m unittest discover -s tests/integration # 11 tests d'intégration
```

Les tests n'ouvrent aucune connexion externe : fixtures pour `nmap`,
`testssl.sh`, `trivy`, journald, Docker, OSV/NVD/KEV/EPSS ; serveurs locaux
éphémères pour SSH, HTTP et TLS ; historique, rapports et configuration
temporaires. Le venv complet exécute les 253 tests ; sans `argon2-cffi`, les
30 tests d'authentification sont ignorés. Le tableau de bord est couvert par
22 tests dédiés (jeton, origine, confirmation, débits).

## Sécurité

Utiliser cet outil uniquement sur des systèmes et réseaux pour lesquels vous
disposez d'une autorisation explicite.

- La découverte ARP est strictement passive (`/proc/net/arp`).
- La vérification TCP est active, uniquement vers les cibles déclarées.
- Trois profils (`passif`, `standard`, `agressif`) règlent ports, timeout et
  concurrence des sondes ; ils ne lèvent ni la confirmation, ni la sélection
  ARP, ni la liste blanche, ni le plafond de 32 ports par protocole.
- Les vérifications actives d'intelligence et les outils externes sont
  désactivés par défaut et limités au périmètre autorisé.
- Aucune session locale réutilisable : chaque lancement vérifie Argon2id.
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
- Le scanner TCP Rust ne parcourt pas automatiquement les voisins ARP. Le
  laboratoire Python propose désormais `--intel discover`, puis `--intel scan`
  pour sonder une seule IP sélectionnée, avec confirmation explicite.
- Le laboratoire exige des privilèges pour le processus d'un socket d'un autre
  utilisateur et pour un `sshd -T` complet ; les erreurs sont conservées, pas
  masquées.
- Les connecteurs externes restent `to_verify` : aucun constat « applicable
  confirmée » sans vérification du correctif de distribution.
