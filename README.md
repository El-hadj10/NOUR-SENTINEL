
# NOUR SENTINEL

**Intelligent Network Security Engine**

NOUR SENTINEL est un projet de cybersécurité modulaire
combinant Rust et Python.

## Architecture

- Rust : moteur principal et traitement des événements.
- Python : analyse et détection d'anomalies.
- JSON : protocole de communication.

## Fonctionnalités initiales

- Transmission de données entre Rust et Python.
- Analyse des événements réseau.
- Détection de ports potentiellement sensibles.
- Génération de rapports JSON.
- Journalisation des résultats.

## Prérequis

- Kali Linux
- Rust
- Cargo
- Python 3

## Installation

```bash
cd rust-engine
cargo build
```

## Exécution

Depuis la racine du projet :

```bash
cargo run --manifest-path rust-engine/Cargo.toml
```

## Sécurité

Utiliser cet outil uniquement sur des systèmes
et réseaux pour lesquels vous disposez d'une autorisation.

## Projet

NOUR SENTINEL
Version 0.1.0

## Version 0.2.0 - Network Intelligence

Nouveautés :

- Passive ARP neighbor discovery.
- TCP connectivity checks.
- Configurable IP targets and ports.
- Python service classification.
- Structured JSON security reports.

Run:

```bash
cargo run --manifest-path rust-engine/Cargo.toml
