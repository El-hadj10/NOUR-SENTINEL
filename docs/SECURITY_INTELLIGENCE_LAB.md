# NOUR SENTINEL LAB — 0.6.0-beta.4

## 1. Statut et provenance

- **Ligne stable de référence** : NOUR SENTINEL v0.5.0 (Security Intelligence).
- **Laboratoire** : 0.6.0-beta.4, couche additive au-dessus des moteurs v0.5.0
  présents dans l'arborescence.
- **Branche de cette itération** : `release/v0.6.0-beta.3`.
- **Tag** : `v0.6.0-beta.4` (tableau de bord local) ; `v0.6.0-beta.3`, `v0.6.0-beta.2`
  et les tags précédents ne sont pas déplacés.
- **Fusion** : non effectuée ; rebasage et audit complets requis avant
  intégration. Aucun historique réécrit.

La bêta.2 a supprimé la session locale forgeable. La bêta.3 ferme les
entrées Python directes : `main.py` authentifie avant de lire le payload,
Rust attend `AUTH_OK` avant toute collecte, et `engine.analyze()` comme les
fonctions `lab.run_*` exigent un jeton mémoire délivré par l'Auth Gate.

Le laboratoire ne remplace pas les six moteurs v0.5.0 : il les réutilise
(`intelligence/`) et ajoute l'authentification, le CLI, la liste blanche, les
connecteurs externes, la persistance privée et les collecteurs locaux.

> Une bannière n'est pas une preuve du binaire exact. Un échec de négociation
> TLS ne prouve pas l'absence de TLS. Une alerte journald est une piste, pas
> une compromission. Aucun constat n'est « applicable confirmée » sans
> vérification du paquet de distribution et de son correctif.

## 2. Architecture

```text
lancer-nour-sentinel.sh
│
├── .venv + argon2-cffi                 Auth Gate direct
│   └── auth_gate.py                    Argon2id, PHC 0600, lock, compteur
│
├── no args ──► Rust main.rs            terminal + auth AVANT configuration
│   ├── ARP passif + scan TCP autorisé
│   ├── inventaire /proc (/sys)
│   └── Python intelligence.engine      rapport v0.5.0 + historique SQLite
│
└── --intel <commande> ──► cli.py       auth directe avant chaque commande
    ├── inventory                       dpkg/rpm, systemd, ss
    ├── full-local                      + sshd -T, PAM, journald, Docker
    ├── fingerprint --protocol ssh|http sonde unique autorisée
    ├── tls --target --port             TLS 1.2/1.3 + certificat
    ├── cve --online                    OSV, NVD, KEV, EPSS (explicite)
    └── dashboard                       interface locale + ondes /proc/net/dev
        └── risk_engine (v0.5.0)
            ├── rapport JSON 0600 sous data/reports/
            └── SQLite data/history/nour_sentinel_intel.db
```

### Modules

| Couche | Fichier | Rôle |
|---|---|---|
| Auth Gate | `python-brain/security_intelligence/auth_gate.py` | Argon2id direct, PHC, lock, limitation |
| CLI | `python-brain/security_intelligence/cli.py` | Authentification avant chaque commande, JSON sur stdout |
| Configuration | `security_intelligence/config.py` | Validation, liste blanche, chemins confinés |
| Inventory | `fingerprinting/inventory.py` | OS, dpkg/rpm, systemd, `ss` |
| Sondes | `fingerprinting/service_probe.py` | Bannière SSH, HEAD HTTP |
| Profils | `python-brain/security_intelligence/profiles.py` | Dictionnaire `passif`/`standard`/`agressif` : ports, timeout, concurrence |
| Tableau de bord | `security_intelligence/dashboard.py` + `web/` | Serveur `127.0.0.1`, jeton de session, ondes `/proc/net/dev`, rapport |
| TLS | `tls/analyzer.py` | Négociations 1.2/1.3, certificat OpenSSL |
| Politiques | `passwords/policy.py` | `sshd -T`, `login.defs`, PAM |
| Journald | `intrusion/journal.py` | Indicateurs agrégés, aucun log brut |
| Docker | `applications/docker.py` | `docker ps` en lecture seule |
| Externe | `vulnerabilities/online.py` | OSV/NVD/KEV/EPSS, cache et budget |
| Rapports | `reports.py`, `store.py` | JSON 0600, SQLite 0600, dossiers 0700 |
| Rust | `rust-engine/src/auth.rs` | Interpréteur `.venv` fixe, handshake avant configuration/réseau |
| Autorisation | `python-brain/authz.py` | Jeton mémoire non persistant, refus des appels directs |
| Entrée Python | `python-brain/main.py` | Auth Gate avant lecture du payload |

## 3. Authentification propriétaire

### Stockage

| Élément | Emplacement / règle |
|---|---|
| Hash secret | `~/.config/nour-sentinel/auth.phc` — PHC Argon2id, 0600 |
| Dossier | `~/.config/nour-sentinel/` — propriétaire courant, 0700 |
| Compteur | `auth.attempts.json` — 0600, échecs et date de déverrouillage |
| Verrou | `auth.lock` — 0600, `flock(LOCK_EX)` |
| Phrase secrète | 16 caractères minimum, saisie masquée `getpass` |
| Tentatives | 3 échecs consécutifs ; 30 s puis doublement jusqu'à 15 min |

Paramètres Argon2id : `time_cost=3`, `memory_cost=65536 KiB`,
`parallelism=4`, `hash_len=32`, `salt_len=16`. Seul le hash PHC est écrit ;
la phrase n'est jamais enregistrée, passée en argument ou journalisée.

### Parcours

1. Rust démarre `python-brain/main.py --handshake` avec l'interpréteur fixe
   `.venv/bin/python`, avant la configuration, l'ARP et le TCP.
2. `main.py` ouvre `/dev/tty` et exécute l'Auth Gate ; un lancement sans
   terminal est refusé.
3. Python affiche une invite masquée ; Argon2id compare la saisie au hash.
4. Un échec met à jour le compteur ; aucune collecte ne démarre. Trois échecs
   déclenchent le verrouillage.
5. Un succès remet le compteur à zéro, délivre un jeton mémoire et émet
   `AUTH_OK` ; Rust poursuit alors seulement vers la configuration et la
   collecte.
6. `intelligence.engine.analyze()` et chaque `lab.run_*` exigent ce jeton ;
   un appel direct sans Auth Gate est refusé.
7. Le CLI `--intel` effectue la même vérification avant chaque commande.

### Verrou et limitations

`auth.lock` est ouvert avec `O_NOFOLLOW`, contrôlé par `fstat` (fichier
ordinaire, propriétaire courant, 0600), puis verrouillé par `flock(LOCK_EX)`.
Le noyau libère le verrou à la fermeture du descripteur, y compris après une
interruption. Le compteur est lu et écrit sous ce verrou ; trois échecs
consécutifs donnent 30 s, puis 60 s, 120 s, 240 s, 480 s et 900 s au maximum.
Un succès remet le compteur à zéro.

Les fichiers sensibles sont ouverts avec `O_NOFOLLOW` et validés via
`fstat` : type ordinaire, propriétaire courant, permissions exactes 0600. Le
dossier dédié doit être 0700. Un lien symbolique ou des permissions larges
sont refusés.

Commandes :

```bash
./lancer-nour-sentinel.sh --setup-deps
./lancer-nour-sentinel.sh --setup-auth
./lancer-nour-sentinel.sh --change-auth
./lancer-nour-sentinel.sh
./lancer-nour-sentinel.sh --intel inventory
```

**Limites assumées** :

- cette barrière empêche un lancement occasionnel sans le secret ; elle ne
  résiste pas à root ni à un compte Linux déjà compromis ;
- une personne contrôlant le même compte peut modifier l'environnement, le
  code, le binaire ou les fichiers privés ; `HOME` et l'environnement
  d'exécution doivent rester fiables ;
- les 46 points de collecte sont instrumentés (`collection_trace.py`) : la
  tentative est tracée avant `authz.require()`, le démarrage après. Les
  rapports (`reports.write_report`), la mémoire SQLite (`IntelStore`),
  `adapters.run_tool()`, les sondes basses et les clients externes sont eux
  aussi refusés sans autorisation ;
- `subprocess`, `socket`, `urllib`, `rusqlite` et les fonctions Rust restent
  néanmoins appelables par du code Python arbitraire ou un binaire modifié
  dans le même processus. L'instrumentation n'est pas un bac à sable : ce
  n'est pas une frontière contre un code déjà compromis ;
- l'état de limitation (`auth.attempts.json`) est refusé au-delà de 4096
  octets, avec permissions 0600 et propriétaire courant ; un état altéré ou
  incohérent provoque un refus explicite plutôt qu'un déverrouillage ;
- `authz._grant()` est privé et n'est appelé que par l'Auth Gate ; un code
  Python arbitraire pourrait toutefois le rendre public ou modifier l'état
  mémoire. La protection réelle repose aussi sur les permissions du compte,
  le chiffrement du disque et l'intégrité du code ;
- la protection doit être complétée par un compte Linux protégé, des
  permissions système correctes et le chiffrement du disque.

## 4. Commandes du laboratoire

```bash
./lancer-nour-sentinel.sh --intel inventory
./lancer-nour-sentinel.sh --intel full-local
./lancer-nour-sentinel.sh --intel discover
./lancer-nour-sentinel.sh --intel scan --target 192.168.1.1 --protocol both --profile agressif --confirm-authorized
GATEWAY="$(ip -4 route show default | awk '$1 == "default" && $2 == "via" {print $3}')"
./lancer-nour-sentinel.sh --intel tls --target "$GATEWAY" --port 8443
./lancer-nour-sentinel.sh --intel fingerprint --target "$GATEWAY" --port 22 --protocol ssh
./lancer-nour-sentinel.sh --intel cve --online
./lancer-nour-sentinel.sh --intel cve --online --package openssh-server --version 9.6p1
```

- `inventory` : OS, paquets dpkg/rpm, services systemd, sockets `ss`, familles
  locales connues (OpenSSH, Apache, nginx, Tor, Privoxy, Docker, bases,
  OpenSSL). Aucun réseau.
- `full-local` : inventaire + `sshd -T` + `login.defs` + PAM + journald
  (désactivé par défaut) + Docker read-only. Aucun scan réseau.
- `discover` : affiche les IPv4 RFC1918 avec une entrée complète dans la table
  ARP locale ; lecture passive, aucune sonde et aucune persistance des
  résultats. Le rapport contient `mode` (`network_discovery`),
  `neighbor_count`, `neighbors` (`ip`, `interface`) et `active_probes`
  (toujours faux) : les adresses MAC ne sont jamais exposées.
- `scan` : après sélection manuelle d'une IP affichée par `discover`, exécute
  des sondes TCP, UDP ou les deux sur cet hôte seulement. La commande exige
  `--confirm-authorized`, accepte uniquement une IPv4 RFC1918 et au plus
  32 ports par protocole, et ne parcourt ni sous-réseau ni liste de voisins.
  `--tcp-ports` et `--udp-ports` acceptent des ports séparés par des virgules,
  sans plages. Les données de découverte et de sondage restent sur stdout et
  ne sont pas écrites dans les rapports ou la base. Le rapport contient
  `mode` (`network_scan`), `target`, `protocols` (`tcp` et/ou `udp`, chacun
  avec `port` et `state`), `limits` et `udp_note`. États TCP : `open`,
  `closed`, `filtered_or_timeout`, `unreachable` ; états UDP : `open`,
  `closed`, `open_or_filtered`, `unreachable`. Avec les listes par défaut
  (20 TCP + 11 UDP à 0,5 s), la durée maximale est d'environ 16 secondes.
- Un timeout UDP est rapporté `open_or_filtered` : l'absence de réponse ne
  permet pas de distinguer un port ouvert silencieux d'un filtrage. Un état
  `closed` en UDP provient d'un ICMP port unreachable, jamais d'une réponse
  applicative.
- `fingerprint` : une seule bannière SSH ou un seul HEAD HTTP.
- `tls` : TLS 1.2 et TLS 1.3 séparément, certificat (sujet, émetteur, dates,
  SAN), expiration et auto-signature.

### Profils d'agressivité

`--profile` (commandes `scan`, `fingerprint`, `tls`) choisit une entrée du
dictionnaire `security_intelligence/profiles.py` :

| Profil | Ports TCP/UDP par défaut | Timeout | Sondes simultanées |
|---|---|---|---|
| `passif` | 4 / 2 | ×2 (scan 1,0 s) | 1 |
| `standard` (défaut) | 20 / 11 | ×1 (scan 0,5 s) | 1 |
| `agressif` | 32 / 14 | ×0,5 (scan 0,25 s) | 4 |

Un profil ne lève aucun garde-fou : `--confirm-authorized`, l'IPv4 présente
dans la table ARP, la liste blanche et le plafond de 32 ports par protocole
restent obligatoires. Une liste `--tcp-ports`/`--udp-ports` explicite prime
sur les ports du profil. Les commandes actives seulement sont concernées :
`discover` reste une lecture ARP passive, sans profil.
- `cve --online` : OSV par paquet, NVD par mots-clés, KEV et EPSS. Sans
  `--online`, aucun appel externe n'est effectué.

### Tableau de bord local

`--intel dashboard [--port 8765]` sert une page unique sur `127.0.0.1`, après
l'Auth Gate. Ce n'est pas une seconde porte d'entrée : le processus a déjà
vérifié Argon2id, le serveur ne répond qu'à `Host` loopback, aucune route API
n'existe sans le jeton de session affiché au lancement, et chaque option
déclenche, après le clic sur « Exécuter », une fonction `lab`/`network_scan`
déjà instrumentée.

| Zone | Contenu |
|---|---|
| Panneau gauche | Boutons d'options (sélection seule), cible, port, protocole, profil, confirmation, bouton « Exécuter » |
| Colonne droite, haut | Ondes du trafic réel (deltas de `/proc/net/dev`, boucle locale exclue) et débit de chaque interface, triées par trafic décroissant, 6 au plus |
| Colonne droite, bas | Rapport détaillé sous les ondes : résumé, `risk_summary`, constats, ports, erreurs, JSON |

Règles appliquées :

- Sélection et exécution sont séparées : cliquer un bouton d'option ne
  collecte rien, seul « Exécuter » met la capacité en file.
- Le panneau des ondes n'affiche que les interfaces qui bougent (boucle locale
  exclue), par débit décroissant : les interfaces virtuelles inactives
  (`docker0`, `veth…`, ponts) ne masquent pas celle qui porte le trafic. Sans
  activité, une mention l'indique au lieu de chips vides.
- Jeton `secrets.token_urlsafe(24)` dans le fragment d'URL, envoyé en en-tête
  `X-Nour-Token` ; il n'est ni dans l'URL des requêtes, ni journalisé, ni dans
  le HTML servi.
- Contrôle `Host` et `Origin`, `Content-Security-Policy` restrictive,
  `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, corps
  limité à 8 Kio, routes inconnues refusées.
- Les capacités s'exécutent dans le thread principal, le seul à détenir le
  jeton `authz` : les handlers HTTP mettent en file et attendent, ils ne
  collectent jamais eux-mêmes.
- `scan` exige la case de confirmation côté page **et** `confirm=true` côté
  serveur ; `cve` exige l'accès en ligne explicite. Ni le profil, ni le
  tableau de bord ne lèvent la liste blanche ou le plafond de 32 ports.
- Le rapport produit reste identique à celui du CLI : même JSON, même fichier
  0600 sous `data/reports/`, même enregistrement SQLite.

## 5. Liste blanche réseau

`config/security_intelligence.json` conserve le marqueur `default_gateway`,
résolu en une IPv4 privée RFC1918 unique uniquement au moment d'une sonde TLS
ou fingerprint. La résolution exécute `ip -4 route show default` et exige le
jeton mémoire, comme toute commande. L'adresse n'est pas enregistrée dans le
dépôt. Une route
absente ou ambiguë entraîne un refus. `discover` et `scan` sont distincts de
cette liste blanche : `scan` exige une IP ARP choisie par l'utilisateur et
une confirmation d'autorisation, sans balayage automatique. `full-local` et
`inventory` ne lancent aucune sonde réseau et ne requièrent pas de route par
défaut.

Règles :

- la cible par défaut est l'unique passerelle IPv4 privée RFC1918 ;
- une configuration personnalisée peut utiliser des IP littérales ;
- `default_gateway` doit être l'unique entrée de la liste d'autorisation ;
- `localhost` est résolu en `127.0.0.1` pour les sondes ;
- aucune redirection HTTP n'est suivie ;
- aucun corps HTTP n'est téléchargé (HEAD uniquement) ;
- aucune authentification SSH n'est tentée.

## 6. Intelligence externe

| Source | Usage | Garde-fou |
|---|---|---|
| OSV | `POST /v1/query` par paquet/version/écosystème | paquet local, budget |
| NVD 2.0 | recherche par mots-clés | faux positifs documentés |
| CISA KEV | catalogue des vulnérabilités exploitées | cache, marque `kev` |
| FIRST EPSS | score par CVE | cache, marque `epss` |

- `online.enabled` **et** `--online` sont requis.
- Cache JSON privé sous `data/cache/intel/`, TTL 24 h par défaut.
- Budget par exécution (20 requêtes par défaut, plafond 100).
- Redirections refusées, réponses plafonnées à 2 Mo.
- Tout constat reste `status: to_verify` ; aucun constat « applicable
  confirmée » n'est produit.

## 7. Données et confidentialité

- Rapports : `data/reports/<horodatage>-<mode>.json`, mode 0600, dossier 0700.
- Base : `data/history/nour_sentinel_intel.db`, mode 0600.
- Caches : `data/cache/intel/`, mode 0600/0700.
- `auth.phc`, `auth.attempts.json`, `auth.lock`, le venv, `data/`, les
  rapports, bases et caches sont exclus de Git.
- Aucun mot de passe, hash de mot de passe, clé privée ou journal brut n'est
  collecté ni exporté.
- Les constats journald ne conservent qu'un compteur et un indicateur
  (`metadata.raw_logs = not_exported`).
- Docker est interrogé uniquement par `docker ps` : aucune création, arrêt,
  suppression ou modification.

## 8. Validation effectuée

Environnement de vérification : Ubuntu, Python 3.14, Rust/Cargo, OpenSSL 3.5,
systemd 259, Docker 29, `dpkg`, `ss`.

| Contrôle | Résultat |
|---|---|
| Rust (`cargo test`) | **52/52** (7 scanner, 20 historique, 17 inventaire, 2 auth, 3 gate, 2 gateway, 1 versions) |
| Python, venv complet | **253/253** |
| Intégration | **11/11** : 7 pipeline (dont refus direct) + 4 E2E PTY |
| Tableau de bord | **22/22** : jeton obligatoire, origine croisée, confirmation `scan`, port invalide, refus sans authentification, débits et remise à zéro des compteurs |
| E2E PTY | pipeline complet, persistance deux scans, mauvais secret verrouillé |
| Ancien `session.json` forgé | ignoré : l'invite Argon2id reste obligatoire |
| `bash -n lancer-nour-sentinel.sh` | réussi |
| JSON | `settings.json`, `security_intelligence.json`, `protocol.json` valides |
| `--help` / `--version` | exécutés |
| Entrées directes sans TTY | `main.py` exit 2, CLI exit 2, lanceur `--intel` exit 2 |
| Collecteurs publics | refus `AuthorizationError` avant commande/sonde |
| Outils externes via moteur | refus avant `adapters.run_tool()` |
| Cycle PTY Python | invite, `AUTH_OK`, puis `analysis_completed` |
| Instrumentation collecte | 46/46 sites refusés avant tout puits (`subprocess`, socket, HTTP, SQLite, rapport) |
| Profils d'agressivité | 3 profils bornés ; ports, timeout, concurrence ; confirmation, ARP, liste blanche et plafond de 32 ports conservés |
| Inspection statique | tous les appels réseau, outils, SQLite et rapports recensés ; entrées opérationnelles gardées |
| `verify()` | même compteur, même verrou et même remise à zéro qu'`authenticate()` |
| UDP/UDP6 | socket lié, processus identifié, application identifiée et réponse vérifiée sont des champs distincts ; `application_verified` reste faux sans réponse |
| `PASS_MAX_DAYS` | 99999 accepté, rotation < 90 j signalée, valeur illisible `to_verify` ; seuil contextuel documenté (PCI DSS 8.3.9, NIST SP 800-63B) |
| Versions | `core_version` 0.5.0, `lab_version` 0.6.0-beta.4, `protocol_version` 3.0 ; `version`/`base_version` conservés |
| Frontière Rust | `gate::require()` actif dans `scanner::*`/`history::*` ; binaire compilé sans le contournement de test |
| Compteur persistant | 6 processus concurrents : 3 échecs comptés, 3 refus sans perte |
| `verify()` verrouillé | refus pendant le verrou, compteur inchangé, aucun contournement |

Les E2E utilisent un `HOME` temporaire, un hash Argon2id réel, un PTY et un
`session.json` forgé. Aucun secret n'est passé en variable d'environnement.
Les 30 tests d'authentification sont ignorés sans `argon2-cffi` ; le venv du
laboratoire les exécute tous.

Limites de validation : le test réel de `sshd -T` complet dépend de
l'environnement (privilèges, clés d'hôte). Sans clés d'hôte accessibles,
`sshd -T` échoue et l'erreur est conservée dans `errors` ; elle n'est pas
masquée.

### 8.1 Statuts de capacité

| Statut | Signification |
|---|---|
| `started` | La capacité a été lancée, sans preuve de résultat exploitable. |
| `completed` | Une donnée a été produite (socket, produit, constat) ou une lecture s'est terminée avec des événements exploitables. |
| `failed` | L'exécution a rencontré une erreur. |
| `disabled` | La configuration exclut la capacité. |
| `no_data` | La capacité est autorisée mais aucune cible/produit ne la déclenche. |
| `blocked_missing_permission` | L'erreur est un refus de privilège (`Permission denied`, `EACCES`, etc.). |

Le nombre d'entrées journald réellement analysées fait partie du statut : un
`journalctl` qui réussit sans aucune entrée donne `no_data`, jamais
`completed`. Une erreur reste prioritaire sur ce décompte.

### 8.2 Inventaire UDP

Un port UDP n'est jamais présenté comme un service disponible :

1. **socket lié** : présence dans `/proc/net/udp` ou `ss -lunH` ;
2. **processus identifié** : inode attribué à un PID (ou `pid`/`process` fourni) ;
3. **application identifiée** : signature de processus connue (`application_identified`) ;
4. **réponse applicative vérifiée** : `application_verified`, toujours `false` en inventaire passif.

### 8.3 Frontière de sécurité Rust

Le modèle de menace retenu est celui d'un opérateur qui lance le binaire
non modifié. L'ordre `Auth Gate → AUTH_OK → collecte` suffit contre une
régression accidentelle, mais pas contre un futur remaniement : `gate::require()`
ajoute un verrou mémoire dans `scanner::*` et `history::*`, activé uniquement
après `AUTH_OK`. Il ne prétend pas empêcher un administrateur de modifier le
programme, ni du code injecté d'appeler `authorize()` ; cette limite reste
explicitement hors périmètre.

## 9. Garde-fous

- Aucune exploitation, aucun brute force, aucun cassage de mot de passe.
- Aucune lecture de `/etc/shadow`, aucun hash, aucun essai de connexion.
- Aucune session forgable ni jeton local réutilisable.
- Aucun scan automatique des voisins ARP.
- Aucune remédiation ni blocage automatique.
- Aucune redirection HTTP inter-hôte, aucun corps HTTP.
- Les sondes actives sont limitées à la liste blanche.
- Aucun profil d'agressivité ne lève la confirmation, la sélection ARP, la
  liste blanche ou le plafond de 32 ports par protocole.
- Une sévérité haute ou critique sans preuve reste plafonnée par le modèle
  v0.5.0.
- Le tableau de bord n'écoute que sur `127.0.0.1`, n'ouvre aucune route sans
  son jeton de session et ne lève aucun des garde-fous ci-dessus.

## 10. Installation sur Kali Linux

```bash
unzip NOUR-SENTINEL-LAB-0.6.0-beta3.zip
cd NOUR-SENTINEL-LAB-0.6.0-beta3
chmod +x lancer-nour-sentinel.sh

# Si python3-venv manque :
sudo apt update
sudo apt install python3-venv python3-pip

./lancer-nour-sentinel.sh --setup-deps
./lancer-nour-sentinel.sh --setup-auth
./lancer-nour-sentinel.sh
./lancer-nour-sentinel.sh --intel inventory
./lancer-nour-sentinel.sh --intel full-local
```

Tests :

```bash
PYTHONPATH=python-brain .venv/bin/python -m unittest discover -s tests/python -v
cargo test --manifest-path rust-engine/Cargo.toml
PYTHONPATH=python-brain .venv/bin/python -m unittest discover -s tests/integration -v
bash -n lancer-nour-sentinel.sh
```

## 11. Feuille de route du laboratoire

| Itération | Objectif | Critère de sortie |
|---|---|---|
| 0.6.0-beta.1 | Auth, six modules, CLI, stockage | suites vertes, limites documentées |
| 0.6.0-beta.2 | Supprimer la session forgeable, durcir l'Auth Gate | Argon2id direct, lock, compteur, E2E PTY |
| 0.6.0-beta.3 | Fermer les entrées Python directes | jeton mémoire, handshake, tests de refus |
| 0.6.0-beta.3 | Profils d'agressivité des sondes | dictionnaire borné, garde-fous inchangés |
| 0.6.0-beta.3 | Durcissement CVE/TLS et corrélation | preuves, faux positifs, actif → CVE |
| 0.6.0-beta.4 | Tableau de bord local | serveur `127.0.0.1`, jeton, ondes, 22/22 |
| Fusion | Rebaser sur v0.5.0 puis intégrer par lots | audit complet, tests E2E, revue sécurité |

## 12. Références

- OWASP — Password Storage Cheat Sheet (Argon2id)
- OSV — API `POST /v1/query`
- NVD — Vulnerability API 2.0
- CISA — Known Exploited Vulnerabilities
- FIRST — EPSS API
- Python — `ssl`, `getpass`, `fcntl`
- systemd — `journalctl`

---

**NOUR SENTINEL LAB — dossier de livraison 0.6.0-beta.4**
