# NOUR SENTINEL LAB — 0.6.0-beta.2

## 1. Statut et provenance

- **Ligne stable de référence** : NOUR SENTINEL v0.5.0 (Security Intelligence).
- **Laboratoire** : 0.6.0-beta.2, couche additive au-dessus des moteurs v0.5.0
  présents dans l'arborescence.
- **Branche de cette itération** : `feature/security-intelligence-lab-beta2`.
- **Tag** : `v0.6.0-beta.2`, ajouté sans déplacer les tags existants.
- **Fusion** : non effectuée ; rebasage et audit complets requis avant
  intégration. Aucun historique réécrit.

La bêta.2 corrige la faiblesse de la bêta.1 : un fichier `session.json`
contenant une date d'expiration future pouvait ouvrir l'accès sans vérifier la
phrase secrète. **Aucune session locale n'existe plus.** Chaque lancement
opérationnel vérifie directement le hash Argon2id.

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
    └── cve --online                    OSV, NVD, KEV, EPSS (explicite)
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
| TLS | `tls/analyzer.py` | Négociations 1.2/1.3, certificat OpenSSL |
| Politiques | `passwords/policy.py` | `sshd -T`, `login.defs`, PAM |
| Journald | `intrusion/journal.py` | Indicateurs agrégés, aucun log brut |
| Docker | `applications/docker.py` | `docker ps` en lecture seule |
| Externe | `vulnerabilities/online.py` | OSV/NVD/KEV/EPSS, cache et budget |
| Rapports | `reports.py`, `store.py` | JSON 0600, SQLite 0600, dossiers 0700 |
| Rust | `rust-engine/src/auth.rs` | Terminal requis, Auth Gate avant configuration/réseau |

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

1. Le binaire Rust exige un **terminal interactif**.
2. Rust appelle `auth_gate.py authenticate` avec l'interpréteur fixe
   `.venv/bin/python` du projet ; aucune variable ne peut le substituer.
3. Python affiche une invite masquée ; Argon2id compare la saisie au hash.
4. Un échec met à jour le compteur persistant ; la collecte réseau ne démarre
   pas. Trois échecs déclenchent le verrouillage.
5. Un succès remet le compteur à zéro et Rust poursuit vers la configuration.
6. Le CLI `--intel` effectue exactement la même vérification avant chaque
   commande opérationnelle.

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
- la protection doit être complétée par un compte Linux protégé, des
  permissions système correctes et le chiffrement du disque.

## 4. Commandes du laboratoire

```bash
./lancer-nour-sentinel.sh --intel inventory
./lancer-nour-sentinel.sh --intel full-local
./lancer-nour-sentinel.sh --intel tls --target 127.0.0.1 --port 8443
./lancer-nour-sentinel.sh --intel fingerprint --target 127.0.0.1 --port 22 --protocol ssh
./lancer-nour-sentinel.sh --intel cve --online
./lancer-nour-sentinel.sh --intel cve --online --package openssh-server --version 9.6p1
```

- `inventory` : OS, paquets dpkg/rpm, services systemd, sockets `ss`, familles
  locales connues (OpenSSH, Apache, nginx, Tor, Privoxy, Docker, bases,
  OpenSSL). Aucun réseau.
- `full-local` : inventaire + `sshd -T` + `login.defs` + PAM + journald
  (désactivé par défaut) + Docker read-only. Aucun scan réseau.
- `fingerprint` : une seule bannière SSH ou un seul HEAD HTTP.
- `tls` : TLS 1.2 et TLS 1.3 séparément, certificat (sujet, émetteur, dates,
  SAN), expiration et auto-signature.
- `cve --online` : OSV par paquet, NVD par mots-clés, KEV et EPSS. Sans
  `--online`, aucun appel externe n'est effectué.

## 5. Liste blanche réseau

`config/security_intelligence.json` n'autorise par défaut que `127.0.0.1` et
`localhost`. Toute autre cible est refusée **avant** la sonde, avec code de
sortie 3. `full-local` et `inventory` ne lancent aucune sonde réseau.

Règles :

- une cible doit être une IP littérale ou `localhost` ;
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
| Rust (`cargo test`) | **45/45** (7 scanner, 20 historique, 14 inventaire, 4 auth) |
| Python, venv complet | **150/150** |
| Intégration | **9/9** : 6 pipeline + 3 E2E PTY |
| E2E PTY | pipeline complet, persistance deux scans, mauvais secret verrouillé |
| Ancien `session.json` forgé | ignoré : l'invite Argon2id reste obligatoire |
| `bash -n lancer-nour-sentinel.sh` | réussi |
| JSON | `settings.json`, `security_intelligence.json`, `protocol.json` valides |
| `--help` / `--version` | exécutés |

Les E2E utilisent un `HOME` temporaire, un hash Argon2id réel, un PTY et un
`session.json` forgé. Aucun secret n'est passé en variable d'environnement.
Les 15 tests d'authentification sont ignorés sans `argon2-cffi` ; le venv du
laboratoire les exécute tous.

Limites de validation : le test réel de `sshd -T` complet dépend de
l'environnement (privilèges, clés d'hôte). Sans clés d'hôte accessibles,
`sshd -T` échoue et l'erreur est conservée dans `errors` ; elle n'est pas
masquée.

## 9. Garde-fous

- Aucune exploitation, aucun brute force, aucun cassage de mot de passe.
- Aucune lecture de `/etc/shadow`, aucun hash, aucun essai de connexion.
- Aucune session forgable ni jeton local réutilisable.
- Aucun scan automatique des voisins ARP.
- Aucune remédiation ni blocage automatique.
- Aucune redirection HTTP inter-hôte, aucun corps HTTP.
- Les sondes actives sont limitées à la liste blanche.
- Une sévérité haute ou critique sans preuve reste plafonnée par le modèle
  v0.5.0.

## 10. Installation sur Kali Linux

```bash
unzip NOUR-SENTINEL-LAB-0.6.0-beta2.zip
cd NOUR-SENTINEL-LAB-0.6.0-beta2
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
| 0.6.0-beta.3 | Durcissement CVE/TLS et corrélation | preuves, faux positifs, actif → CVE |
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

**NOUR SENTINEL LAB — dossier de livraison 0.6.0-beta.2**
