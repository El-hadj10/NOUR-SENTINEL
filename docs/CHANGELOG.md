# NOUR SENTINEL — Changelog

## [0.5.0] — Security Intelligence

### Added
- Inventaire local Rust (`inventory.rs`) : sockets `/proc/net/tcp{,6}`, attribution PID/processus/unité systemd/conteneur, interfaces et adresses, avec racine injectable pour les tests.
- Fingerprinting : signatures de bannières (confiance `probable`) et de processus locaux (confiance `confirmed`).
- Corrélation CVE hors ligne (`advisories.json`) : candidats `to_verify`, note explicite sur les correctifs rétroportés ; clients NVD/OSV/KEV/EPSS optionnels jamais appelés automatiquement.
- Audit TLS : protocoles obsolètes, suites faibles, force de chiffrement, certificats (expiration, auto-signature, clé courte, signature SHA-1/MD5).
- Audit non destructif `sshd_config`, `login.defs` et `sudoers` (aucun secret collecté).
- Détection par journaux journald : rafales d'échecs SSH, succès après échecs, comptes, sudo, services, pare-feu.
- Analyse HTTP : en-têtes de sécurité, divulgation de version, CORS, cookies, méthodes.
- Modèle de constat normalisé (`finding_id`, `evidence`, `confidence`, `confidence_reason`, `exposure`, `status`) et plafonnement des sévérités hautes sans preuve.
- Risk engine : dédoublonnage, score gravité × confiance × exposition, bonus KEV/EPSS, priorités `P1..P4`.
- Adaptateurs optionnels `nmap`, `testssl.sh`, `trivy` (argv en liste, sans shell, sortie parsée).
- Nouvelle documentation `docs/SECURITY_INTELLIGENCE.md`.

### Changed
- Contrat JSON `3.0` : inventaire, `intelligence_config`, `tools_config`, `authorized_targets`, `risk_summary`, `capabilities`.
- `analyzer.py` délègue l'analyse à `intelligence.engine` ; les constats réseau v0.4.x sont convertis au modèle v0.5.0 (`warning` → `medium`).
- La configuration passe en 0.5.0 avec les sections `intelligence` et `tools` (désactivées par défaut).
- Les vérifications actives et les outils restent limités aux cibles de `network.targets`.

### Validated
- 41 tests unitaires Rust réussis (7 scanner, 20 historique, 14 inventaire).
- 82 tests unitaires Python réussis, sans réseau.
- 8 tests d'intégration réussis, dont 2 E2E.
- Fixtures pour `nmap`, `testssl.sh`, `trivy` et journald ; aucune dépendance externe.

### Security
- Aucune exploitation, aucun brute force, aucune collecte de secrets.
- Une alerte haute ou critique sans preuve est plafonnée à `medium`.
- Les outils externes et les sondes actives sont désactivés par défaut.

### Limitations connues
- Base CVE embarquée réduite : aucun constat « applicable confirmée » hors ligne.
- Attribution du processus d'un socket d'un autre utilisateur impossible sans privilèges suffisants ; le propriétaire (`uid`/`user`) reste identifié.
- L'analyse de certificat dépend d'un certificat décodé ou de `testssl.sh`.

## [0.4.1] — Consolidation & Reliability

### Added
- Variable `NOUR_SENTINEL_HISTORY_DIR` pour rediriger la base d'historique.
- `ScanScope` : le périmètre réel (cibles + ports) est enregistré avec chaque scan.
- `detect_scan_changes` : comparaison limitée aux scans de périmètre identique, avec indicateur `scope_changed`.
- Bloc `history` dans le rapport JSON (`recorded`, `not_recorded`, `unavailable`).
- Migration automatique du schéma (`PRAGMA user_version`, colonnes de périmètre).
- Validation des adresses IP et des états observés, avant écriture comme après lecture.
- Plafond de concurrence (256) et rejet explicite du port 0 dans la configuration.
- Sémantique des findings clarifiée : « exposition observée », `confidence: low`, `evidence: port_open`.
- 12 tests Rust supplémentaires : 20 tests d'historique, 27 au total.

### Changed
- Erreurs d'historique explicites (`HistoryError`) : plus aucune erreur d'initialisation, d'écriture ou de comparaison n'est ignorée dans `main.rs`.
- `PRAGMA foreign_keys = ON` et `busy_timeout` activés à l'ouverture de la base.
- Conversion des ports validée (`1..=65535`) avant écriture et à la lecture : refus explicite au lieu d'une troncature.
- Les erreurs de création du répertoire d'historique sont propagées.
- Le test de bout en bout utilise un répertoire d'historique temporaire.
- README dédoublonné, 23 tests Rust documentés, format de `config/settings.json` harmonisé.

### Fixed
- Une différence de périmètre n'est plus interprétée comme une apparition ou une disparition de service.
- Un scan pouvait être annoncé enregistré alors que l'écriture avait échoué.
- L'archive de distribution ne contient ni `target/`, ni base d'historique, ni archive imbriquée.

### Validated
- 27 tests unitaires Rust réussis.
- 7 tests unitaires Python réussis.
- 7 tests d'intégration réussis.
- Pipeline réel Rust → Python → SQLite → rapport JSON réussi.
- Deux scans successifs comparés en E2E : ouverture d'un port détectée (`state_changed`), base isolée.

### Limitations connues
- La comparaison porte sur deux scans consécutifs de périmètre identique ; l'analyse multi-scans n'est pas déployée.
- Un changement de périmètre est signalé mais non comparé.

## [0.4.0] — Behavioral Intelligence & Persistence

### Added
- Historique persistant des scans via SQLite (`init_db`, `save_scan`, `detect_changes`, `get_history_summary`).
- Détection de changements entre deux scans avec trois états : `open`, `closed`, `filtered_or_unreachable`.
- Un port `open` devenu `filtered_or_unreachable` est signalé comme indéterminé, jamais comme fermé.
- Un port ouvert au scan précédent mais absent du scan courant est signalé comme `removed`, pas comme fermé.
- Recommandations de sécurité enrichies par port (SSH, RDP, VNC, MySQL, PostgreSQL, etc.).
- Chaque finding inclut un champ `recommendation` et `risk_level`.

### Changed
- Les écritures d'historique sont atomiques (transaction SQLite).
- La configuration applicative et les rapports utilisent la version `0.4.0`.
- La documentation des tests Rust et Python est actualisée.

### Validated
- Compilation Rust réussie.
- 15 tests unitaires Rust réussis (7 scanner, 8 historique).
- 7 tests unitaires Python réussis.
- 5 tests du pipeline Python réussis.
- 1 test de bout en bout Rust → Python réussi.
- Pipeline réel Rust → Python → rapport JSON réussi.

### Security
- La découverte ARP reste passive.
- Les actions de sécurité automatiques restent interdites.
- L'historique est stocké localement dans `data/history/` et exclu de l'archive de distribution.

### Limitations connues
- La détection de changements compare uniquement deux scans consécutifs.
- L'analyse comportementale sur plusieurs scans n'est pas encore déployée.

## [0.3.0] — Concurrent Scanner & Integration

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
