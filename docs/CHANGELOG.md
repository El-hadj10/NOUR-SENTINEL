# NOUR SENTINEL — Changelog

## [0.2.1] — En préparation

### Added
- Centralisation de la configuration d'analyse.
- Tests unitaires du détecteur Python.
- Tests unitaires du scanner Rust.
- Tests unitaires de l'analyseur Python.
- Validation de la configuration.

### Changed
- Le détecteur Python reçoit désormais ses règles depuis la configuration.
- Rust transmet les paramètres d'analyse via JSON.
- La sortie standard Python est réservée aux réponses JSON.
- Renforcement de la gestion des erreurs.

### Security
- Validation des adresses IP configurées.
- Scan automatique des appareils découverts par ARP désactivé.
- Actions de sécurité automatiques interdites.

### Validated
- Compilation Rust.
- 2 tests Rust réussis.
- 7 tests Python réussis.
- Exécution complète Rust → Python réussie.

### Planned
- Scanner TCP concurrent avec limite effective.
- Tests automatisés d'intégration.
- Intégration contrôlée de la découverte ARP aux cibles TCP.

### Limitations connues
- Le scanner TCP reste séquentiel.
- `max_concurrency` est configuré et validé, mais pas encore utilisé.
- Les appareils ARP découverts ne sont pas automatiquement scannés.
