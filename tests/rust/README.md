# NOUR SENTINEL — Tests Rust

## Objectif

Vérifier la fiabilité du moteur Rust : validation des paramètres réseau, scanner TCP concurrent, scheduler parallèle, et couche d'historique SQLite (persistance, migration, validation, comparaison de périmètres).

## Emplacement des tests

Les tests unitaires sont intégrés directement dans les modules Rust concernés.

- `rust-engine/src/scanner.rs` : 7 tests.
- `rust-engine/src/history.rs` : 20 tests.

## Tests du scanner (7)

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

## Tests de l'historique SQLite (20)

### Schéma, stockage et validation

1. `init_creates_required_tables` — les tables `scans` et `scan_events` sont créées et `PRAGMA user_version` est positionné.
2. `foreign_keys_are_enforced` — une clé étrangère invalide est refusée (PRAGMA actif).
3. `save_scan_records_scan_and_events` — le scan, les cibles, les ports et les événements sont enregistrés.
4. `invalid_event_port_is_rejected_without_writing` — un port hors plage `u16` est refusé sans écriture partielle.
5. `invalid_event_ip_is_rejected_without_writing` — une adresse IP invalide est refusée sans écriture partielle.
6. `invalid_event_state_is_rejected_without_writing` — un état inconnu est refusé sans écriture partielle.
7. `invalid_stored_port_is_reported_not_truncated` — un port hors plage déjà stocké produit une erreur, jamais une troncature.
8. `invalid_stored_state_is_reported` — un état inconnu relu depuis la base produit une erreur, jamais une interprétation.
9. `legacy_database_is_migrated` — une base v0.4.0 (sans colonne `scope`) est migrée sans perte.

### Erreurs, emplacement et résumé

10. `corrupt_database_is_reported` — une base illisible produit une erreur explicite.
11. `history_directory_override_is_resolved` — `NOUR_SENTINEL_HISTORY_DIR` et l'emplacement par défaut sont résolus correctement.
12. `summary_returns_recent_scans_first` — le résumé retourne les scans du plus récent au plus ancien.

### Détection de changements

13. `first_scan_has_no_changes` — le premier scan ne produit aucune comparaison.
14. `detect_changes_reports_newly_open_port` — un port ouvert déjà dans le périmètre est signalé comme `new`.
15. `detect_changes_reports_real_closure` — `open → closed` est signalé comme fermeture réelle.
16. `filtered_is_not_reported_as_closed` — `open → filtered_or_unreachable` n'est jamais une fermeture.
17. `unobserved_open_port_is_removed_not_closed` — un port ouvert disparu des observations est `removed`.
18. `scope_change_is_not_a_service_change` — un changement de ports dans le périmètre ne produit ni apparition ni disparition.
19. `target_change_is_not_a_service_change` — un changement de cible est signalé comme changement de périmètre uniquement.
20. `comparable_scope_ignores_declaration_order` — l'ordre de déclaration des cibles et ports n'empêche pas la comparaison.

## Exécution

Depuis la racine du projet :

```bash
cargo test --manifest-path rust-engine/Cargo.toml
```

## Résultat validé — v0.4.1

- 27 tests exécutés (7 scanner, 20 historique SQLite).
- 27 tests réussis.
- 0 échec.

## Isolation

- Chaque test d'historique utilise un répertoire temporaire dédié (`std::env::temp_dir()`), supprimé avant exécution.
- Aucun test n'écrit dans `data/history/` du projet.
- Les tests n'ouvrent aucune connexion réseau externe.

## Limites des tests

Le test de concurrence mesure les workers actifs du scheduler ; il ne constitue pas une mesure indépendante des connexions réseau.

Les tests Rust ne remplacent pas les tests d'intégration entre Rust et Python.

---

**NOUR SENTINEL — Rust Engine Testing**
