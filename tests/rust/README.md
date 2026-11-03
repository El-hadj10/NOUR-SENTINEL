# NOUR SENTINEL — Tests Rust

## Objectif

Vérifier la fiabilité du moteur Rust, notamment la validation des paramètres réseau, le scanner TCP concurrent et le comportement du système de traitement parallèle.

## Emplacement des tests

Les tests unitaires sont intégrés directement dans les modules Rust concernés.

Fichier principal :

`rust-engine/src/scanner.rs`

## Tests actuellement implémentés

### 1. rejects_invalid_ip

Vérifie que le scanner ignore une adresse IP invalide.

### 2. handles_empty_targets

Vérifie que le scanner retourne un résultat vide lorsqu'aucune cible n'est fournie.

### 3. handles_empty_ports

Vérifie le comportement du scanner lorsqu'aucun port n'est configuré.

### 4. rejects_zero_concurrency

Vérifie qu'une concurrence configurée à zéro ne lance aucune tâche.

### 5. rejects_zero_timeout

Vérifie qu'un timeout nul ne lance aucune vérification TCP.

### 6. respects_maximum_worker_concurrency

Vérifie que le nombre de workers actifs ne dépasse pas la limite configurée et que plusieurs workers peuvent fonctionner simultanément.

### 7. preserves_result_order

Vérifie que les résultats conservent l'ordre des tâches initiales malgré l'exécution parallèle.

## Exécution

Depuis la racine du projet :

```bash
cargo test --manifest-path rust-engine/Cargo.toml
```

## Résultat validé — v0.4.0

- 15 tests exécutés (7 scanner, 8 historique SQLite).
- 15 tests réussis.
- 0 échec.

## Limites des tests

Les tests unitaires vérifient le fonctionnement du scheduler parallèle et les validations du scanner.

Le test de concurrence mesure les workers actifs du scheduler ; il ne constitue pas une mesure indépendante des connexions réseau.

Les tests Rust ne remplacent pas les tests d'intégration entre Rust et Python.

---

**NOUR SENTINEL — Rust Engine Testing**
