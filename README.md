# NOUR SENTINEL

**Intelligent Network Security Engine**

NOUR SENTINEL est un outil modulaire de diagnostic et d'analyse réseau combinant Rust et Python.

- **Rust** : collecte réseau, découverte ARP passive, vérification TCP concurrente et persistance de l'historique.
- **Python** : analyse des observations, classification des services et détection des ports sensibles.
- **SQLite** : conservation locale des scans et de leurs observations.
- **JSON** : communication entre les deux moteurs via stdin/stdout.

## Version actuelle

**0.4.1 — Consolidation & Reliability**

Branche de développement : `feature/v0.4.1`

Statut : v0.4.1 livrée (erreurs d'historique explicites, comparaison limitée aux scans de même périmètre, tests isolés, documentation harmonisée).

Provenance v0.4.0 :

- Historique SQLite transactionnel.
- Détection de changements à trois états (`open`, `closed`, `filtered_or_unreachable`).
- Recommandations de sécurité par port.

## Architecture

```text
NOUR-SENTINEL/
├── rust-engine/       # Moteur réseau Rust (scanner + historique SQLite)
├── python-brain/      # Analyse et détection Python
├── communication/     # Contrat JSON
├── config/            # Configuration
├── data/
│   ├── history/       # Historique des scans SQLite (non versionné)
│   ├── logs/
│   └── reports/
├── tests/
│   ├── python/
│   ├── rust/
│   └── integration/
└── docs/
```

## Prérequis

- Linux (lecture de la table ARP `/proc/net/arp`)
- Rust et Cargo
- Python 3 (bibliothèque standard uniquement)
- SQLite (bibliothèque C incluse via `rusqlite`, feature `bundled`)

## Installation

```bash
cargo build --manifest-path rust-engine/Cargo.toml
```

Aucune dépendance Python n'est à installer : le cerveau Python n'utilise que la bibliothèque standard.

## Configuration

La configuration se trouve dans `config/settings.json`. Les paramètres principaux :

| Section | Paramètre | Rôle |
|---|---|---|
| `application` | `version` | Version affichée et reportée |
| `engines.python` | `executable` | Interpréteur Python utilisé |
| `network` | `targets` | Adresses IP explicitement autorisées |
| `network` | `ports` | Ports TCP vérifiés (définit le périmètre) |
| `network` | `timeout_ms` | Délai de connexion par port |
| `network` | `max_concurrency` | Nombre maximal de workers |
| `analysis` | `sensitive_ports` | Ports déclenchant une alerte |
| `security` | `authorized_scanning_only`, `automatic_actions` | Garde-fous obligatoires |

Variables d'environnement :

- `NOUR_SENTINEL_CONFIG` : chemin d'un fichier de configuration alternatif.
- `NOUR_SENTINEL_HISTORY_DIR` : répertoire de la base d'historique (par défaut `data/history/`). Utilisé par les tests pour ne jamais toucher aux données réelles.

## Exécution

Depuis la racine du projet :

```bash
cargo run --manifest-path rust-engine/Cargo.toml
```

Une configuration alternative peut être utilisée sans modifier `config/settings.json` :

```bash
NOUR_SENTINEL_CONFIG=/chemin/vers/settings.json cargo run --manifest-path rust-engine/Cargo.toml
```

Le rapport JSON final contient un bloc `history` indiquant le résultat réel de la persistance :

```json
"history": { "status": "recorded", "scan_id": 12, "previous_scan_id": 11, "scope_changed": false }
```

Valeurs possibles : `recorded`, `not_recorded` (erreur d'écriture) ou `unavailable` (base inaccessible). En cas d'échec, un avertissement est aussi écrit sur `stderr` : aucun succès n'est affiché alors que l'historique a échoué.

## Historique, sauvegarde et restauration

La base se trouve par défaut dans `data/history/nour_sentinel.db` et n'est pas versionnée.

- Sauvegarde : `cp data/history/nour_sentinel.db sauvegarde-nour.db` (ou `sqlite3 data/history/nour_sentinel.db ".backup sauvegarde-nour.db"`).
- Restauration : arrêter le moteur, remplacer le fichier, relancer.
- Compatibilité : une base v0.4.0 est migrée automatiquement (ajout des colonnes de périmètre) au premier démarrage de la v0.4.1.

## Tests

```bash
cargo test --manifest-path rust-engine/Cargo.toml   # 23 tests unitaires Rust
python3 -m unittest discover -s tests/python         # 7 tests unitaires Python
python3 -m unittest discover -s tests/integration    # 6 tests d'intégration
```

Les tests d'intégration compilent le véritable binaire Rust et utilisent un serveur TCP local temporaire sur `127.0.0.1`. La configuration et l'historique sont placés dans des répertoires temporaires.

## Sécurité

Utiliser cet outil uniquement sur des systèmes et réseaux pour lesquels vous disposez d'une autorisation explicite.

Garanties appliquées par le moteur :

- la découverte ARP est strictement passive (lecture de `/proc/net/arp`) ;
- le scan des appareils découverts par ARP est refusé au démarrage tant qu'il n'est pas implémenté ;
- les actions de sécurité automatiques sont interdites et refusées au démarrage ;
- chaque cible doit être une adresse IP littérale déclarée dans la configuration ;
- les ports enregistrés sont validés (`1..=65535`) avant toute écriture.

## Limites connues

- La comparaison historique porte sur deux scans de périmètre identique ; l'analyse multi-scans n'est pas implémentée.
- Un changement de périmètre est signalé (`scope_changed`) mais n'est pas comparé : aucune apparition ni disparition n'est déduite d'un périmètre différent.
- La découverte ARP n'est pas encore reliée au scan TCP.
