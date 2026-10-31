# NOUR SENTINEL

**Intelligent Network Security Engine**

NOUR SENTINEL est un outil modulaire de diagnostic et d'analyse réseau combinant Rust et Python.

- **Rust** : collecte réseau, découverte ARP passive et vérification TCP concurrente.
- **Python** : analyse des observations, classification des services et détection des ports sensibles.
- **JSON** : communication entre les deux moteurs via stdin/stdout.

## Version actuelle

**0.3.0 — Concurrent TCP Scanner & Integration**

Branche de développement : `feature/v0.3.0`

## Architecture

```text
NOUR-SENTINEL/
├── rust-engine/       # Moteur réseau Rust
├── python-brain/      # Analyse et détection Python
├── communication/     # Contrat JSON
├── config/            # Configuration
├── data/
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

## Installation

```bash
cargo build --manifest-path rust-engine/Cargo.toml
```

Aucune dépendance Python n'est à installer : le cerveau Python n'utilise que la bibliothèque standard.

## Exécution

Depuis la racine du projet :

```bash
cargo run --manifest-path rust-engine/Cargo.toml
```

Une configuration alternative peut être utilisée sans modifier `config/settings.json` :

```bash
NOUR_SENTINEL_CONFIG=/chemin/vers/settings.json cargo run --manifest-path rust-engine/Cargo.toml
```

## Tests

```bash
cargo test --manifest-path rust-engine/Cargo.toml   # tests unitaires Rust
python3 -m unittest discover -s tests/python         # tests unitaires Python
python3 -m unittest discover -s tests/integration    # pipeline complet
```

Les tests d'intégration compilent le véritable binaire Rust et utilisent un serveur TCP local temporaire sur `127.0.0.1`.

## Sécurité

Utiliser cet outil uniquement sur des systèmes et réseaux pour lesquels vous disposez d'une autorisation explicite.

Garanties appliquées par le moteur :

- la découverte ARP est strictement passive (lecture de `/proc/net/arp`) ;
- le scan des appareils découverts par ARP est refusé au démarrage tant qu'il n'est pas implémenté ;
- les actions de sécurité automatiques sont interdites et refusées au démarrage ;
- chaque cible doit être une adresse IP littérale déclarée dans la configuration.
