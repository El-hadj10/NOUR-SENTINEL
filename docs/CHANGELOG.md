# NOUR SENTINEL — Changelog

## [0.3.0] — En développement

### Added
- Scanner TCP concurrent.
- Pool de workers avec limite effective de concurrence.
- Préservation de l'ordre des résultats.
- Tests de concurrence Rust.
- Tests d'intégration du moteur Python.
- Test de bout en bout Rust → TCP local → Python.
- Support de la variable d'environnement `NOUR_SENTINEL_CONFIG`.
- Configuration temporaire pour les tests sans modification de la configuration principale.

### Changed
- Le scanner TCP utilise désormais `max_concurrency`.
- La configuration applicative et les rapports utilisent la version `0.3.0`.
- La documentation des tests Rust et Python est actualisée.

### Validated
- Compilation Rust réussie.
- 7 tests unitaires Rust réussis.
- 7 tests unitaires Python réussis.
- 5 tests du pipeline Python réussis.
- 1 test de bout en bout Rust → Python réussi.
- Exécution réelle du pipeline Rust → Python réussie.

### Security
- La découverte ARP reste passive.
- Le scan automatique des appareils découverts par ARP reste désactivé.
- Les tests de bout en bout utilisent une cible locale `127.0.0.1`.
- Le test de bout en bout utilise un port TCP temporaire.
- La configuration de test est isolée de la configuration principale.
- Les actions de sécurité automatiques restent interdites.

### Limitations connues
- La découverte ARP n'est pas encore intégrée au scan TCP.
- Les fonctionnalités d'analyse comportementale ne sont pas implémentées.
- L'historique persistant des observations n'est pas implémenté.
- Les tests d'intégration ne remplacent pas encore une validation sur plusieurs environnements Linux.

## [0.2.1] — Configuration hardening and test coverage

### Added
- Centralisation de la configuration d'analyse.
- Tests unitaires du détecteur Python.
- Tests unitaires du scanner Rust.
- Tests unitaires de l'analyseur Python.
- Validation de la configuration.

### Changed
- Le détecteur Python reçoit ses règles depuis la configuration.
- Rust transmet les paramètres d'analyse via JSON.
- La sortie standard Python est réservée aux réponses JSON.
- Renforcement de la gestion des erreurs.

### Security
- Validation des adresses IP configurées.
- Scan automatique des appareils découverts par ARP désactivé.
- Actions de sécurité automatiques interdites.

### Validated
- Compilation Rust.
- 2 tests Rust réussis à cette étape.
- 7 tests Python réussis.
- Exécution complète Rust → Python réussie.

## [0.2.0] — Network Intelligence

### Added
- Découverte passive des voisins ARP.
- Vérification de connectivité TCP.
- Configuration des adresses IP cibles et des ports.
- Classification des services par Python.
- Rapports de sécurité JSON structurés.

## [0.1.0] — Initial working engine

### Added
- Initialisation du moteur Rust.
- Initialisation du moteur Python.
- Première communication JSON.
- Première détection de ports.
