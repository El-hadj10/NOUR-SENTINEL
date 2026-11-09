# NOUR SENTINEL — Roadmap

## VERSION 0.1.0 — Foundation

- [x] Initialisation Rust.
- [x] Initialisation Python.
- [x] Communication JSON.
- [x] Première détection de ports.

## VERSION 0.2.0 — Network Intelligence

- [x] Lecture passive de la table ARP.
- [x] Vérification TCP configurable.
- [x] Transmission des observations à Python.
- [x] Classification des services.

## VERSION 0.2.1 — Hardening & Refactoring

- [x] Audit technique de la v0.2.0.
- [x] Centralisation des règles d'analyse.
- [x] Transmission de la configuration à Python.
- [x] Validation des adresses IP.
- [x] Contrat stdout JSON.
- [x] Tests supplémentaires du détecteur.
- [x] Tests de l'analyseur.
- [x] Premiers tests unitaires Rust.

## VERSION 0.3.0 — Concurrent Scanner & Integration

- [x] Scanner TCP concurrent.
- [x] Limitation effective des workers.
- [x] Préservation de l'ordre des résultats.
- [x] Tests de concurrence Rust.
- [x] Tests d'intégration Python.
- [x] Test de bout en bout Rust → Python.
- [x] Configuration temporaire pour les tests.
- [ ] Intégration contrôlée ARP/TCP.
- [x] Audit final et publication de la version.

## VERSION 0.4.0 — Behavioral Intelligence & Persistence

- [x] Historique persistant des scans via SQLite (transactions atomiques).
- [x] Détection de changements entre deux scans (open / closed / filtered_or_unreachable).
- [x] Tests unitaires de l'historique (8 tests).
- [x] Recommandations de sécurité enrichies par port.
- [x] Chaque finding inclut `recommendation` et `risk_level`.

## VERSION 0.4.1 — Consolidation & Reliability

- [x] Erreurs d'historique explicites et propagées au rapport.
- [x] Clés étrangères SQLite activées et testées.
- [x] Validation des ports reçus et stockés (refus, pas troncature).
- [x] Propagation des erreurs de système de fichiers.
- [x] Migration de schéma via `PRAGMA user_version`.
- [x] Périmètre (cibles + ports) enregistré avec chaque scan.
- [x] Comparaison limitée aux scans de périmètre identique.
- [x] Signalement des changements de périmètre (`scope_changed`).
- [x] Isolation des tests via `NOUR_SENTINEL_HISTORY_DIR`.
- [x] Tests : clé étrangère, port, IP, état invalides, base corrompue, migration, périmètre.
- [x] Validation des états observés avant écriture et après lecture.
- [x] Plafond de concurrence (256) et rejet explicite du port 0.
- [x] Sémantique des findings : exposition observée, confiance `low`, preuve `port_open`.
- [x] Test E2E de deux scans successifs (persistance et ouverture détectée).
- [x] README dédoublonné et documentation des 27 tests Rust.
- [x] Statut de l'historique exposé dans le rapport JSON.

## VERSION 0.5.0 — Security Intelligence

- [x] Inventaire local des sockets (PID, processus, unité systemd, conteneur).
- [x] Fingerprinting local (confiance confirmée) et protocolaire (bannière).
- [x] Corrélation CVE hors ligne, statut `to_verify`, note sur les correctifs rétroportés.
- [x] Audit TLS : protocoles, suites, certificats.
- [x] Audit non destructif SSH, `login.defs` et `sudoers`.
- [x] Détection d'intrusion par journaux journald.
- [x] Analyse HTTP non destructive : en-têtes, cookies, méthodes.
- [x] Modèle de constat normalisé (`finding_id`, `evidence`, `confidence`, `exposure`, `status`).
- [x] Déduplication et priorisation (gravité × confiance × exposition, bonus KEV/EPSS).
- [x] Adaptateurs optionnels nmap, testssl.sh et trivy (désactivés par défaut).
- [x] 41 tests Rust, 82 tests Python, 8 tests d'intégration.
- [x] Documentation dédiée : `docs/SECURITY_INTELLIGENCE.md`.

## VERSION 0.6.0-beta.1 — Security Intelligence Lab

- [x] Auth Gate propriétaire Argon2id (PHC, 0600, 3 essais, session courte).
- [x] Contrôle d'accès Rust avant configuration et réseau.
- [x] CLI authentifié et lanceur `lancer-nour-sentinel.sh`.
- [x] Liste blanche locale, refus des cibles hors périmètre.
- [x] Inventaire dpkg/rpm, systemd, `ss` et familles locales.
- [x] Sondes SSH/HTTP uniques, TLS 1.2/1.3 et certificat.
- [x] `sshd -T`, `login.defs` et PAM ; journald sans logs bruts ; Docker read-only.
- [x] OSV/NVD/KEV/EPSS explicites avec cache et budget.
- [x] Rapports 0600 et base SQLite dédiée.
- [x] 47 tests Rust, 145 tests Python, 8 tests d'intégration.

## VERSION 0.6.0-beta.2 — Auth Gate Hardening

- [x] Suppression des sessions locales et du `session.json` forgeable.
- [x] Vérification Argon2id directe avant chaque lancement Rust et commande CLI.
- [x] Verrou `flock`, compteur persistant et verrouillage progressif jusqu'à 15 min.
- [x] Lecture des fichiers sensibles avec `O_NOFOLLOW` et validation `fstat`.
- [x] Interpréteur déterministe `.venv/bin/python`, sans variable de substitution.
- [x] Tests de permissions, liens symboliques, verrou et progression.
- [x] 3 E2E PTY avec hash réel, session forgée ignorée et mauvais secret verrouillé.
- [x] 45 tests Rust, 150 tests Python, 9 tests d'intégration.

## VERSION 0.6.0-beta.3 — Entry Point Hardening

- [x] Auth Gate Argon2id dans le processus Python avant lecture du payload.
- [x] Handshake Rust → Python : aucune configuration, ARP ou TCP avant `AUTH_OK`.
- [x] Interpréteur déterministe `.venv/bin/python` pour le cerveau Python.
- [x] Jeton d'autorisation mémoire non persistant et refus des appels directs.
- [x] Tests de refus direct de `main.py`, `engine.analyze()` et `lab.run_*`.
- [x] Instrumentation des 46 points de collecte, rapports et SQLite compris.
- [x] `verify()` soumis au même compteur et au même verrouillage qu'`authenticate()`.
- [x] Inspection statique : appels réseau, outils, SQLite et rapports recensés et gardés.
- [x] Auto-doublons corrigés, UDP/UDP6 attribués, wildcards IPv4/IPv6 normalisés.
- [x] Identification système complète et statut réel des six capacités.
- [x] `PASS_MAX_DAYS` révisé, seuil de 90 jours documenté comme contextuel (NIST SP 800-63B, PCI DSS 8.3.9).
- [x] Preuves P0.3 : aucune ARP/TCP/commande/rapport/SQLite avant `AUTH_OK`.
- [x] Preuves P0.4 : concurrence, compteur intègre, états malformés, `verify()` verrouillé, redémarrage cohérent.
- [x] Verrou Rust interne (`gate::require()`) dans `scanner::*` et `history::*`, activé après `AUTH_OK`.
- [x] Six statuts de capacité et inventaire UDP à quatre niveaux de preuve.
- [x] Versions `core_version`/`lab_version`/`protocol_version` dans les rapports et la bannière.
- [x] `discover` passif et `scan` confirmé, bornés à une IPv4 ARP et 32 ports par protocole.
- [x] Profils d'agressivité `passif`/`standard`/`agressif` (ports, timeout, concurrence), sans lever les garde-fous.
- [x] 52 tests Rust, 231 tests Python, 11 tests d'intégration.

Reste pour les itérations suivantes : vérification des correctifs de
distribution, preuves multi-distributions, schéma stable, exécution contrôlée
de testssl.sh/nmap et corrélation actif → version → CVE → KEV/EPSS.

## VERSION 0.6.0 — Fusion stable

- [ ] Rebaser le laboratoire sur v0.5.0 et intégrer par lots.
- [ ] Audit complet, tests Rust/Python/E2E et revue de sécurité.
- [ ] Aucun déplacement de tag existant.

## VERSION 1.0.0 — Production

- [ ] Architecture stabilisée.
- [ ] Tests automatisés complets.
- [ ] Documentation complète.
- [ ] Audit de sécurité.
- [ ] Sécurité renforcée.
