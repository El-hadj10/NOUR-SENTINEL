# NOUR SENTINEL — Tests Rust

## Objectif

Vérifier la fiabilité du moteur Rust : scanner TCP, couche d'historique SQLite
et inventaire local des sockets.

## Emplacement des tests

Les tests unitaires sont intégrés dans les modules concernés.

- `rust-engine/src/scanner.rs` : 7 tests.
- `rust-engine/src/history.rs` : 20 tests.
- `rust-engine/src/inventory.rs` : 14 tests.

## Tests du scanner (7)

1. `rejects_invalid_ip` — une adresse IP invalide est ignorée.
2. `handles_empty_targets` — aucune cible ne produit aucun résultat.
3. `handles_empty_ports` — aucun port configuré ne produit aucun résultat.
4. `rejects_zero_concurrency` — une concurrence nulle ne lance aucune tâche.
5. `rejects_zero_timeout` — un timeout nul ne lance aucune vérification.
6. `respects_maximum_worker_concurrency` — la limite de workers est effective.
7. `preserves_result_order` — l'ordre des résultats est conservé.

## Tests de l'historique SQLite (20)

### Schéma, stockage et validation

1. `init_creates_required_tables` — tables et `PRAGMA user_version`.
2. `foreign_keys_are_enforced` — clé étrangère invalide refusée.
3. `save_scan_records_scan_and_events` — scan, cibles, ports et événements.
4. `invalid_event_port_is_rejected_without_writing` — port hors plage refusé.
5. `invalid_event_ip_is_rejected_without_writing` — IP invalide refusée.
6. `invalid_event_state_is_rejected_without_writing` — état inconnu refusé.
7. `invalid_stored_port_is_reported_not_truncated` — port stocké invalide signalé.
8. `invalid_stored_state_is_reported` — état stocké invalide signalé.
9. `legacy_database_is_migrated` — migration d'une base v0.4.0.

### Erreurs, emplacement et résumé

10. `corrupt_database_is_reported` — base illisible signalée.
11. `history_directory_override_is_resolved` — `NOUR_SENTINEL_HISTORY_DIR`.
12. `summary_returns_recent_scans_first` — résumé du plus récent au plus ancien.

### Détection de changements

13. `first_scan_has_no_changes` — pas de comparaison au premier scan.
14. `detect_changes_reports_newly_open_port` — apparition `new`.
15. `detect_changes_reports_real_closure` — fermeture réelle.
16. `filtered_is_not_reported_as_closed` — `filtered` n'est pas une fermeture.
17. `unobserved_open_port_is_removed_not_closed` — disparition `removed`.
18. `scope_change_is_not_a_service_change` — changement de ports neutralisé.
19. `target_change_is_not_a_service_change` — changement de cible neutralisé.
20. `comparable_scope_ignores_declaration_order` — ordre de déclaration sans effet.

## Tests de l'inventaire (14)

### Analyse des tables `/proc`

1. `parses_ipv4_listener` — décodage hexadécimal IPv4 (`0100007F` → `127.0.0.1`).
2. `parses_ipv6_listener` — décodage des mots little-endian de `tcp6`.
3. `ignores_established_sockets` — seules les écoutes `0A` sont retenues.
4. `rejects_malformed_lines` — lignes incomplètes ignorées sans panique.
5. `ignores_zero_port_oddities_gracefully` — port nul non bloquant.

### Attribution

6. `attributes_socket_to_process_and_unit` — inode → PID → `sshd` → `ssh.service`, confiance `confirmed`.
7. `attributes_docker_container` — identifiant de conteneur raccourci à 12 caractères.
8. `detects_container_ids_only_when_long_enough` — un identifiant hexadécimal trop court n'est pas un conteneur.
9. `unattributed_socket_has_unknown_confidence` — confiance `unknown` sans PID.
10. `resolves_owner_without_process_attribution` — `uid`/`user` identifiés depuis `/etc/passwd` même sans accès au processus.
11. `missing_files_produce_empty_inventory` — racine vide → inventaire vide.

### Contexte hôte

12. `reads_host_context` — hostname, noyau, distribution.
13. `reads_interfaces_with_ipv6_addresses` — décodage ordre réseau de `if_inet6`.
14. `parses_ip_json_addresses` — adresses de `ip -j addr show`.

## Exécution

```bash
cargo test --manifest-path rust-engine/Cargo.toml
```

## Résultat validé — v0.5.0

- 41 tests exécutés (7 scanner, 20 historique, 14 inventaire).
- 41 tests réussis, 0 échec.

## Isolation

- Chaque test utilise un répertoire temporaire dédié, supprimé avant exécution.
- L'inventaire est testé avec des fixtures `/proc` et `/sys` sous une racine
  injectable : aucun accès réel au système.
- Aucun test n'écrit dans `data/history/` et aucun n'ouvre de connexion
  réseau externe.

## Limites

Le test de concurrence mesure les workers du scheduler ; il ne mesure pas les
connexions réseau.

Les tests Rust ne remplacent pas les tests d'intégration Rust → Python.

---

**NOUR SENTINEL — Rust Engine Testing**
