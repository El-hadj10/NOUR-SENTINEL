# NOUR SENTINEL — Tests Rust

## Objectif

Vérifier la fiabilité du moteur Rust, notamment la validation des adresses IP et le comportement du scanner TCP.

## Emplacement des tests

Les tests unitaires sont intégrés directement dans les modules Rust concernés.

Fichier principal :

`rust-engine/src/scanner.rs`

## Tests actuellement implémentés

### 1. rejects_invalid_ip

Vérifie que le scanner ignore une adresse IP invalide et ne génère aucune observation.

### 2. handles_empty_targets

Vérifie que le scanner retourne un résultat vide lorsqu'aucune cible n'est fournie.

## Exécution

Depuis la racine du projet :

```bash
cargo test --manifest-path rust-engine/Cargo.toml
```

## Résultat validé — v0.2.1

- 2 tests exécutés.
- 2 tests réussis.
- 0 échec.

## Évolutions prévues — v0.3.0

- Tests du scanner TCP concurrent.
- Tests de la limite de concurrence.
- Tests de validation des paramètres réseau.
- Tests de gestion des erreurs de connexion.
- Tests de l'intégration contrôlée ARP/TCP.

**NOUR SENTINEL — Rust Engine Testing**
