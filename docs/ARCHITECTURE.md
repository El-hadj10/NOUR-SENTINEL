# NOUR SENTINEL - Architecture

## 1. Présentation

NOUR SENTINEL utilise une architecture hybride
Rust + Python, avec une couche de persistance SQLite.

## 2. Rust Engine

Responsabilités :

- Chargement et validation de la configuration.
- Découverte ARP passive (lecture de `/proc/net/arp`).
- Vérification TCP concurrente avec limite effective de workers.
- Construction du message JSON destiné à Python.
- Persistance de l'historique et comparaison de périmètres.

Frontière : le moteur Rust ne produit aucune conclusion de sécurité ;
il ne transmet que des observations factuelles (`ip`, `port`, `state`).

## 3. Python Brain

Responsabilités :

- Analyse des événements.
- Détection des anomalies.
- Classification des alertes.
- Production des résultats JSON.

Frontière : Python n'écrit pas d'historique et ne modifie jamais le système.
Il reçoit un message sur stdin et répond sur stdout. Les seules opérations
réseau sont des sondes HTTP/TLS ou des outils externes, désactivés par
défaut et limités au périmètre autorisé.

## 4. Communication

Le moteur Rust démarre un processus Python.

Les données sont transmises via stdin.

Les résultats sont récupérés via stdout.

Le format de communication est JSON, décrit dans
`communication/protocol.json`.

`stdout` Python est réservé à la réponse JSON ; tout diagnostic est écrit
sur `stderr`.

## 5. Couche d'historique

`rust-engine/src/history.rs` est la seule couche qui accède à SQLite.

- Tables : `scans` (un enregistrement par scan) et `scan_events`
  (une observation par couple `ip` / `port`).
- Clé étrangère `scan_events.scan_id → scans.id`, appliquée via
  `PRAGMA foreign_keys = ON`.
- Écriture atomique : un scan et ses événements sont insérés dans une
  même transaction ; une donnée invalide fait échouer l'ensemble.
- Périmètre : chaque scan enregistre ses cibles et ses ports. Deux scans
  ne sont comparés que si leur périmètre est identique.
- Migration : `PRAGMA user_version` et ajout automatique des colonnes
  manquantes pour les bases v0.4.0.
- Erreurs : type `HistoryError` (`Database`, `Io`, `InvalidData`) propagé
  jusqu'au rapport ; aucune erreur de stockage n'est ignorée.

Emplacement de la base :

- par défaut `data/history/nour_sentinel.db` ;
- surcharge par `NOUR_SENTINEL_HISTORY_DIR`.

## 6. Configuration

- `config/settings.json` : configuration par défaut.
- `NOUR_SENTINEL_CONFIG` : chemin d'un fichier alternatif (tests).
- `NOUR_SENTINEL_HISTORY_DIR` : répertoire d'historique alternatif (tests).

## 7. Sécurité

- Découverte ARP strictement passive (lecture de `/proc/net/arp`).
- Vérification TCP active, limitée aux cibles IP explicitement configurées.
- Aucune action automatique de blocage ou de remédiation.
- Utilisation sur des réseaux autorisés.
- Validation des entrées (adresses IP, ports, JSON).
- Gestion des erreurs explicite.
- Cible par défaut `default_gateway` : résolution à l'exécution d'une route
  IPv4 RFC1918 unique via `ip -4 route show default`. La cible effective est
  uniquement l'adresse de la box pour le moteur Rust et les sondes TLS /
  fingerprint du laboratoire ; aucune plage n'est incluse. Si la route est
  absente ou ambiguë, le moteur Rust refuse le démarrage.
- Le moteur Rust ne scanne pas automatiquement les voisins ARP. Le CLI Python
  du laboratoire les affiche passivement, puis peut sonder un seul voisin
  IPv4 RFC1918 sélectionné et confirmé par l'utilisateur, avec une limite de
  32 ports par protocole.

## 8. Inventaire local (v0.5.0)

`rust-engine/src/inventory.rs` lit `/proc` et `/sys` sous une racine
injectable (testable avec des fixtures).

- Sockets en écoute : `/proc/net/tcp`, `/proc/net/tcp6`, décodage hexadécimal
  IPv4/IPv6, état `listen` uniquement.
- Attribution : inode de socket → descripteurs `/proc/<pid>/fd` → `comm`,
  `exe`, unité systemd et conteneur (cgroup).
- Confiance : `confirmed` (processus identifié), `probable` (socket seul),
  `unknown` (attribution impossible).
- Contexte hôte : hostname, noyau, distribution, interfaces (MAC, état,
  adresses IPv6 et IPv4 via `ip -j addr` si disponible).

Aucune opération réseau, aucun privilège requis au-delà de la visibilité
`/proc`.

## 9. Security Intelligence (v0.5.0)

`python-brain/intelligence/` regroupe six piliers, un moteur de risque et des
adaptateurs d'outils :

- `fingerprinting/` : signatures de bannières (probable) et de processus
  (confirmé).
- `vulnerabilities/` : corrélation CVE hors ligne, candidats `to_verify`,
  clients NVD/OSV/KEV/EPSS jamais appelés automatiquement.
- `tls/` : protocoles, suites, certificats déjà décodés.
- `passwords/` : `sshd_config`, `login.defs`, `sudoers`, sans secret.
- `intrusion/` : journald parsé hors ligne, constats `to_verify`.
- `applications/` : en-têtes, cookies et méthodes HTTP.
- `risk_engine.py` : dédoublonnage, score, `P1..P4`.
- `tools/` : `nmap`, `testssl.sh`, `trivy`, argv en liste, sans shell,
  désactivés par défaut.

Le contrat JSON `3.0` transporte l'inventaire, la configuration
`intelligence`, `tools` et le périmètre autorisé. Détail complet :
`docs/SECURITY_INTELLIGENCE.md`.

## 10. Laboratoire 0.6.0-beta.3

Couche additive, séparée de la ligne stable v0.5.0. Les moteurs v0.5.0
restent la référence ; le laboratoire ajoute l'accès, le CLI et la
persistance privée.

- **Auth Gate** (`security_intelligence/auth_gate.py`) : Argon2id direct,
hash PHC, dossier 0700, fichiers 0600. Aucune session locale n'est créée,
acceptée ou nettoyée.
- **Stockage d'authentification** : `auth.phc`, `auth.attempts.json` et
`auth.lock` sous `~/.config/nour-sentinel/`. Le compteur persistant verrouille
après trois échecs (30 s, puis doublement jusqu'à 15 min).
- **Verrou** : `auth.lock` ouvert avec `O_NOFOLLOW`, validé par `fstat` et
protégé par `flock(LOCK_EX)` ; les fichiers sensibles sont lus de la même
manière.
- **Rust** (`auth.rs`) : interpréteur fixe `.venv/bin/python`, sans champ de
configuration ni variable de substitution, démarrage de
`python-brain/main.py --handshake` avant la configuration, l'ARP et le TCP.
Rust attend `AUTH_OK` ; aucune collecte ne commence avant.
- **Python** (`main.py`, `authz.py`) : Argon2id sous `/dev/tty`, puis jeton
mémoire non persistant. `engine.analyze()` et `lab.run_*` refusent tout appel
sans ce jeton ; les imports n'ont aucun effet de collecte.
- **CLI** (`security_intelligence/cli.py`) : Argon2id vérifié avant chaque
commande ; stdout réservé au JSON, diagnostics sur stderr.
- **Lanceur** : plus de session temporaire ni de variable de session ;
`--setup-auth` et `--change-auth` restent interactifs.
- **Liste blanche** : `config/security_intelligence.json` résout
`default_gateway` en une IPv4 RFC1918 unique au démarrage ; seule la box est
autorisée. Une route absente ou ambiguë entraîne un refus avant la sonde.
- **Collecteurs** : dpkg/rpm, systemd, `ss`, `sshd -T`, PAM, journald agrégé
et Docker en lecture seule.
- **Intelligence externe** : OSV/NVD/KEV/EPSS uniquement sur `--online`,
avec cache, budget et redirections refusées ; constats `to_verify`.
- **Données** : rapports 0600 sous `data/reports/`, base
`data/history/nour_sentinel_intel.db`, dossiers 0700.

Frontière : un compte Linux compromis ou root peut remplacer le binaire ou
le code ; l'Auth Gate complète le chiffrement disque et les permissions, il
ne les remplace pas. Détail : `docs/SECURITY_INTELLIGENCE_LAB.md`.

## 11. Évolutions

- Vérification des correctifs de distribution avant « applicable confirmée ».
- Corrélation actif → version → CVE → KEV/EPSS dans l'historique.
- Analyse comportementale multi-scans.
- Interface graphique et rapports exportables.
