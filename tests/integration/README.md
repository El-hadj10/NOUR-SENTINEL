# NOUR SENTINEL — Tests d'intégration

## 1. Objectif

Les tests d'intégration ont pour objectif de vérifier le fonctionnement global de NOUR SENTINEL et la communication entre ses différents composants.

## 2. Architecture testée

Le scénario d'intégration repose sur les étapes suivantes :

1. Rust exige un terminal puis vérifie Argon2id auprès de l'Auth Gate, avant la configuration (`config/settings.json` ou `NOUR_SENTINEL_CONFIG`). Aucune session n'est acceptée.
2. Rust valide les paramètres de configuration.
3. Rust effectue la collecte des observations réseau.
4. Rust construit le message JSON.
5. Rust transmet les données au moteur Python via stdin.
6. Python analyse les événements.
7. Python retourne un rapport JSON via stdout.
8. Rust enregistre le scan dans SQLite et compare le périmètre au scan précédent.
9. Rust vérifie et affiche le résultat.

## 3. Fichiers de test

`test_rust_python_pipeline.py`

6 tests du contrat JSON entre les deux moteurs, par invocation directe de `python-brain/main.py`, dont un scénario d'inventaire local (service confirmé et exposition générique).

`test_end_to_end.py`

3 tests de bout en bout sous PTY, avec le véritable binaire Rust, un hash Argon2id réel et un répertoire d'historique temporaire :

- pipeline complet TCP local → Rust → Python → SQLite → rapport final ;
- deux scans successifs de périmètre identique, vérifiant la persistance réelle et la détection de l'ouverture d'un port (`state_changed`, `closed` → `open`) ;
- trois mauvais secrets : verrouillage persistant, aucune collecte réseau, aucun rapport.

Chaque scénario place un ancien `session.json` forgé dans le `HOME` isolé : il doit rester ignoré.

## 4. État actuel — 0.6.0-beta.2

- Chargement de la configuration : validé.
- Validation des paramètres : validée.
- Communication Rust → Python : validée automatiquement.
- Transmission JSON : validée.
- Analyse Python : validée par tests unitaires et d'intégration.
- Vérification de la réponse JSON : validée.
- Enregistrement de l'historique : validé (`history.status == "recorded"`).
- Tests automatisés d'intégration : 9 tests, 9 réussis (6 pipeline + 3 E2E PTY).

## 5. Scénarios couverts

- Transmission d'un événement réseau valide.
- Détection d'un port sensible ouvert.
- Port fermé : aucune alerte produite.
- Rejet d'une entrée JSON invalide.
- Absence de message parasite dans `stdout` Python.
- Pipeline complet Rust → TCP local → Python → historique SQLite → rapport de sécurité.
- Deux scans comparés : port fermé puis ouvert, changement `state_changed` attendu, base interrogée directement.
- Inventaire local : `OpenSSH` identifié avec confiance `confirmed`, écoute `0.0.0.0:22` signalée, `capabilities` exposées.
- Authentification directe sous PTY, ancien `session.json` ignoré, mauvais secret verrouillé et aucune base créée.

## 6. Isolation des tests

- La configuration de test est générée dans un répertoire temporaire et transmise via `NOUR_SENTINEL_CONFIG` ; `config/settings.json` n'est jamais modifié.
- L'historique est redirigé via `NOUR_SENTINEL_HISTORY_DIR` vers un répertoire temporaire : la base du développeur (`data/history/nour_sentinel.db`) n'est ni lue ni modifiée.
- Un `HOME` temporaire contient un vrai hash Argon2id 0600 ; le binaire est lancé sous PTY et la phrase secrète est fournie à l'invite.
- Un ancien `session.json` 0600 avec une expiration future est créé volontairement : il ne doit jamais ouvrir l'accès.
- Les variables de session, de hash et d'interpréteur sont retirées de l'environnement des tests.
- La cible est limitée à `127.0.0.1` et le port TCP est éphémère (`bind 127.0.0.1:0`) : aucun port fixe n'est ouvert et aucun trafic ne quitte la machine.
- Le serveur temporaire et le répertoire de test sont nettoyés même en cas d'échec.

## 7. Sécurité

Les tests utilisent exclusivement des systèmes contrôlés ou des cibles explicitement autorisées.

Aucun scan automatique non autorisé et aucune action automatique de sécurité ne sont permis.

## 8. Évolutions prévues

- Intégration contrôlée ARP → TCP, explicitement activée par la configuration.
- Validation sur plusieurs environnements Linux.
- Tests de résistance aux défaillances du moteur Python (binaire absent, arrêt brutal).
- Test d'une base corrompue au niveau intégration.

**NOUR SENTINEL — Integration Testing**
