# NOUR SENTINEL — Changelog

## [0.6.0-beta.3] — Entry Point Hardening

### Fixed
- `python-brain/main.py` exécute l'Auth Gate Argon2id avant de lire le payload.
- `intelligence.engine.analyze()`, `engine.collect_tool_findings()`, `engine.active_checks()` et les fonctions publiques `lab.run_*` refusent de collecter sans autorisation dans le processus courant.
- Les collecteurs publics du laboratoire (`inventory.collect`, `policy.collect`, `journal.collect`, `docker.collect`, `tls.audit`, `service_probe.*`, `OnlineIntel.*`) appellent `authz.require()` avant toute commande ou sonde.
- Rust démarre le cerveau Python avant la configuration, l'ARP et le TCP, puis attend `AUTH_OK` avant toute collecte.
- L'interpréteur du cerveau Python est fixé à `.venv/bin/python` ; le champ obsolète `engines.python.executable` est supprimé de la configuration, du schéma Rust et de la validation.
- `auth_gate.verify()` respecte le verrouillage persistant et enregistre chaque échec dans le compteur : aucune API publique ne permet d'essayer des secrets sans limitation. Un succès remet le compteur à zéro.
- L'état de limitation est plafonné à 4096 octets et refuse un `locked_until` arbitrairement lointain.
- Inspection statique : `adapters.run_tool`, `http_analyzer.probe_http`, `tls.inspect`, `services.probe_banner`, `inventory.run_command`, `engine._journal_findings`, `UrllibTransport.fetch` et les clients externes sont instrumentés et refusés sans jeton.

### Added
- Jeton d'autorisation mémoire non persistant (`authz.py`), délivré uniquement après une vérification Argon2id réussie et révoqué après un échec.
- Test de refus direct de `main.py` sans terminal et tests de refus des fonctions `lab`/`engine` sans autorisation.
- Tests de refus de tous les `lab.run_*`, des collecteurs bas niveau et du chemin outils externes.
- Instrumentation en mémoire de 46 points de collecte (`collection_trace.py`) : chaque tentative est tracée avant l'autorisation, chaque démarrage après. Aucune commande, sonde, écriture de rapport ou accès SQLite n'est atteint sans jeton.
- Attribution TCP/UDP/UDP6 : `/proc/net/udp` et `udp6` sont lus, `protocol` est exposé et l'attribution inode → processus s'applique aussi à UDP.
- Classification des wildcards IPv4/IPv6 : `::`, `[::]`, `0:0:0:0:0:0:0:0`, `::0` et les formes IPv4 mappées sont normalisées.
- Identification système complète : `architecture`, `os_id` et `os_version` sont exposés côté Python et Rust.
- Statut réel des six capacités : `capability_status` distingue `started`, `completed`, `failed`, `disabled`, `no_data` et `blocked_missing_permission`. Un démarrage n'est jamais présenté comme une collecte réussie.
- Inventaire UDP : distinction explicite entre socket lié, processus identifié, application identifiée et réponse applicative vérifiée (`application_verified: false` tant qu'aucune réponse n'est observée).
- Versions harmonisées : `core_version` (0.5.0), `lab_version` (0.6.0-beta.3) et `protocol_version` (3.0) dans les deux rapports et la bannière ; `version`/`base_version` restent pour les anciens lecteurs.
- Frontière Rust : verrou mémoire `gate::require()` dans `scanner::*` et `history::*`, activé uniquement après `AUTH_OK`.
- Les rapports (`reports.write_report`) et la mémoire SQLite (`IntelStore`) exigent désormais une autorisation, y compris hors orchestration.
- Tests P0.3 : registre exhaustif des 46 sites, refus de chaque site avec puits `subprocess`/socket/HTTP/SQLite/rapport instrumentés, absence d'artefact avant authentification.
- Tests P0.4 : 6 authentifications concurrentes, intégrité du compteur, états malformés ou surdimensionnés, permissions 0600, `verify()` verrouillé et limité, cohérence après redémarrage.
- Commandes `discover` (lecture ARP passive, MAC jamais exposées) et `scan` (une IPv4 ARP choisie, `--confirm-authorized`, 32 ports maximum par protocole, aucun balayage de sous-réseau). Chaque commande exige le jeton mémoire ; la résolution de la passerelle par défaut exécute `ip` après autorisation.
- Profils d'agressivité `passif`/`standard`/`agressif` (`profiles.py`) pour `scan`, `fingerprint` et `tls` : dictionnaire de ports, timeout et concurrence. Aucun profil ne contourne la confirmation, la sélection ARP, la liste blanche ou le plafond de 32 ports.
- Correction des auto-doublons : un constat identique n'est plus enregistré comme son propre doublon et un identifiant identique n'est plus ajouté à `metadata.duplicates`.
- `PASS_MAX_DAYS` révisé : 99999 (pas d'expiration) n'est plus signalé ; une rotation < 90 jours est signalée `low`, une valeur illisible `to_verify`. Le seuil de 90 jours est documenté comme contextuel (PCI DSS v4.0 8.3.9), pas comme une règle universelle ; la référence NIST SP 800-63B §5.1.1.2 reste citée.

### Changed
- Le contrôle Rust ne lance plus une seconde authentification : Python est l'unique porte d'entrée, avec handshake avant collecte.
- Les tests d'orchestration autorisent explicitement le contrôle par patch de test ; aucun `grant()` public ne subsiste.
- La cible réseau par défaut devient l'unique passerelle IPv4 RFC1918 résolue
  à l'exécution (`default_gateway`) ; l'ARP passif est désactivé par défaut et
  aucun voisin n'est ajouté au périmètre.

### Validated
- 52 tests Rust (7 scanner, 20 historique, 17 inventaire, 2 auth, 3 gate, 2 gateway, 1 versions).
- 231 tests Python dans le venv complet (dont 14 tests de profils, 5 tests P0.3 et 15 tests P0.4).
- 11 tests d'intégration : 7 pipeline (dont refus direct) + 4 E2E PTY.
- `bash -n` réussi, compilation Python réussie, `git diff --check` propre.

### Limitations connues
- La barrière ne résiste pas à root ni à un compte Linux déjà compromis, ni à du code Python arbitraire exécuté dans le même processus ; l'instrumentation et les guards ne constituent pas un bac à sable.
- `adapters.run_tool()` est désormais instrumenté, mais `subprocess`, `socket`, `urllib` et `rusqlite` restent appelables directement par du code arbitraire dans le même processus. Le verrou Rust `gate::require()` empêche un appel accidentel avant `AUTH_OK`, mais un code injecté peut appeler `gate::authorize()` ou modifier le binaire ; cette limite reste hors du modèle de menace.
- La vérification UDP s'arrête au socket lié et, au mieux, au processus : aucune réponse applicative n'est envoyée, donc `application_verified` reste faux.
- `sshd -T` complet et le processus d'un socket d'un autre utilisateur exigent des privilèges.
- Les résultats OSV/NVD restent `to_verify` tant que le correctif de distribution n'est pas vérifié.

## [0.6.0-beta.2] — Auth Gate Hardening

### Fixed
- Suppression de la session locale forgeable : un `session.json` avec une date future ne peut plus ouvrir l'accès sans la phrase secrète.
- Suppression des fonctions de création, validation et nettoyage de session.
- Un lancement non interactif est refusé avant toute configuration ou collecte réseau.

### Added
- Vérification Argon2id directe à chaque lancement Rust et à chaque commande du CLI.
- Verrou inter-processus `auth.lock` (`flock(LOCK_EX)`) et compteur persistant `auth.attempts.json`.
- Verrouillage après trois échecs : 30 s, puis doublement progressif jusqu'à 15 min ; remise à zéro après succès.
- Lecture des fichiers sensibles avec `O_NOFOLLOW` et validation des métadonnées du descripteur (`fstat`).
- Tests de permissions, liens symboliques, verrou exclusif et progression du verrouillage.
- E2E PTY avec hash Argon2id réel et ancien `session.json` forgé.

### Changed
- Rust utilise un interpréteur déterministe `.venv/bin/python` et transmet uniquement `authenticate` à l'Auth Gate.
- Le CLI vérifie la phrase secrète avant chaque commande opérationnelle.
- Le lanceur ne crée plus de session ni de variable de session ; `--setup-auth`, `--change-auth` et l'exécution restent inchangés pour l'utilisateur.
- Les variables `NOUR_SENTINEL_AUTH_FILE`, `NOUR_SENTINEL_SESSION`, `NOUR_SENTINEL_PYTHON` et `NOUR_SENTINEL_VENV` ne sont plus acceptées.

### Security
- Aucune session réutilisable ; le secret est vérifié à chaque lancement.
- Aucun secret dans les fichiers, arguments, journaux ou variables d'environnement.
- Dossier 0700, fichiers d'authentification 0600, propriétaire courant.
- Aucune exploitation, aucun brute force, aucune remédiation automatique.

### Validated
- 45 tests Rust (7 scanner, 20 historique, 14 inventaire, 4 auth).
- 150 tests Python dans le venv complet.
- 9 tests d'intégration : 6 pipeline + 3 E2E PTY (dont session forgée et mauvais secret verrouillé).
- `bash -n` réussi, JSON valides, `--help`/`--version` exécutés.

### Limitations connues
- La barrière ne résiste pas à root ni à un compte Linux déjà compromis.
- `sshd -T` complet et le processus d'un socket d'un autre utilisateur exigent des privilèges.
- TLS 1.0/1.1 et STARTTLS ne sont pas testés ; un échec de négociation ne prouve pas l'absence de TLS.
- Les résultats OSV/NVD restent `to_verify` tant que le correctif de distribution n'est pas vérifié.

## [0.6.0-beta.1] — Security Intelligence Lab

### Added
- Auth Gate propriétaire Argon2id (`auth_gate.py`) : hash PHC uniquement, fichier 0600, dossier 0700, 3 tentatives avec temporisation, changement vérifié de l'ancien secret.
- Contrôle d'accès Rust (`auth.rs`) exécuté avant la configuration, l'ARP et le TCP ; session locale 0600 plafonnée à 1 h.
- CLI authentifié `inventory`, `full-local`, `fingerprint`, `tls`, `cve --online`.
- Lanceur `lancer-nour-sentinel.sh` : venv, dépendances, Auth Gate, routes `--intel`, nettoyage de session.
- Liste blanche `config/security_intelligence.json` limitée à `127.0.0.1` et `localhost`, refus avant sonde.
- Inventaire dpkg/rpm, services systemd, sockets `ss`, familles locales (OpenSSH, Apache, nginx, Tor, Privoxy, Docker, bases, OpenSSL).
- Sondes uniques : bannière SSH et HEAD HTTP sans redirection ni corps.
- TLS 1.2/1.3 séparés, certificat via OpenSSL (sujet, émetteur, dates, SAN, auto-signature, expiration).
- Politiques effectives `sshd -T`, `login.defs` et `common-password` PAM ; aucun secret lu.
- Inventaire Docker read-only (`docker ps`) et publication de ports signalée.
- Connecteurs OSV, NVD, CISA KEV et FIRST EPSS explicites, avec cache privé, budget de requêtes et refus des redirections.
- Rapports JSON 0600 sous `data/reports/`, base `data/history/nour_sentinel_intel.db`, dossiers 0700.
- Documentation `docs/SECURITY_INTELLIGENCE_LAB.md` et cahier des charges joint.

### Security
- Authentification avant toute opération Rust ou CLI ; sessions 0600 expirantes, symlinks refusés.
- Aucun appel externe sans `--online` et `online.enabled`.
- Aucun mot de passe, hash, clé privée ou journal brut collecté/exporté.
- Aucune exploitation, aucun brute force, aucune remédiation automatique.

### Validated
- 47 tests Rust (7 scanner, 20 historique, 14 inventaire, 6 auth).
- 145 tests Python dans le venv complet (10 tests d'auth ignorés sans argon2).
- 8 tests d'intégration, dont 2 E2E avec session courte.
- JSON valides, `bash -n` réussi, `--help`/`--version` vérifiés.
- Exécution réelle : 2 569 paquets, 43 services, 14 sockets ; `full-local` produit 3 constats avec preuve.

### Limitations connues
- `sshd -T` complet et le processus d'un socket d'un autre utilisateur exigent des privilèges.
- TLS 1.0/1.1 et STARTTLS ne sont pas testés ; un échec de négociation ne prouve pas l'absence de TLS.
- Les résultats OSV/NVD restent `to_verify` tant que le correctif de distribution n'est pas vérifié.

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
