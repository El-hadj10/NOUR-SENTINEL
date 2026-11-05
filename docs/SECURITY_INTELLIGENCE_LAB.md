# NOUR SENTINEL LAB — 0.6.0-beta.1

## 1. Statut et provenance

- **Ligne stable de référence** : NOUR SENTINEL v0.5.0 (Security Intelligence).
- **Laboratoire** : 0.6.0-beta.1, couche additive au-dessus des moteurs v0.5.0
  présents dans l'arborescence.
- **Branche prévue par le cahier des charges** : `feature/security-intelligence-lab`.
- **Fusion** : non effectuée ; rebasage et audit complets requis avant
  intégration. Aucun tag déplacé, aucun historique réécrit.

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
├── .venv + argon2-cffi                 Auth Gate
│   └── auth_gate.py                    Argon2id, PHC 0600, session courte
│
├── no args ──► Rust main.rs            auth::enforce() AVANT configuration
│   ├── ARP passif + scan TCP autorisé
│   ├── inventaire /proc (/sys)
│   └── Python intelligence.engine      rapport v0.5.0 + historique SQLite
│
└── --intel <commande> ──► cli.py       auth vérifiée avant toute opération
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
| Auth Gate | `python-brain/security_intelligence/auth_gate.py` | Argon2id, PHC, permissions, sessions |
| CLI | `python-brain/security_intelligence/cli.py` | Commandes authentifiées, JSON sur stdout |
| Configuration | `security_intelligence/config.py` | Validation, liste blanche, chemins confinés |
| Inventory | `fingerprinting/inventory.py` | OS, dpkg/rpm, systemd, `ss` |
| Sondes | `fingerprinting/service_probe.py` | Bannière SSH, HEAD HTTP |
| TLS | `tls/analyzer.py` | Négociations 1.2/1.3, certificat OpenSSL |
| Politiques | `passwords/policy.py` | `sshd -T`, `login.defs`, PAM |
| Journald | `intrusion/journal.py` | Indicateurs agrégés, aucun log brut |
| Docker | `applications/docker.py` | `docker ps` en lecture seule |
| Externe | `vulnerabilities/online.py` | OSV/NVD/KEV/EPSS, cache et budget |
| Rapports | `reports.py`, `store.py` | JSON 0600, SQLite 0600, dossiers 0700 |
| Rust | `rust-engine/src/auth.rs` | Session valide avant configuration/réseau |

## 3. Authentification propriétaire

| Élément | Choix appliqué |
|---|---|
| Algorithme | Argon2id (`argon2-cffi`), sel aléatoire, paramètres OWASP |
| Secret | phrase de 16 caractères minimum, saisie masquée, terminal requis |
| Stockage | `~/.config/nour-sentinel/auth.phc`, hash PHC uniquement |
| Permissions | dossier 0700, fichier 0600, propriétaire courant, symlinks refusés |
| Tentatives | 3 par lancement, temporisation progressive (0,5 s puis 1 s) |
| Changement | ancien secret vérifié, nouveau secret différent |
| Session | fichier 0600, expiration 300 s par défaut, plafond absolu 1 h |
| Rust | `auth::enforce()` avant configuration, ARP et TCP |

Commandes :

```bash
./lancer-nour-sentinel.sh --setup-deps
./lancer-nour-sentinel.sh --setup-auth
./lancer-nour-sentinel.sh --change-auth
./lancer-nour-sentinel.sh
```

**Limite assumée** : une protection logicielle locale ne résiste pas à un
compte Linux compromis ni à un administrateur root capable de remplacer le
binaire ou le code. Elle complète le chiffrement du disque, les permissions du
compte et les mises à jour ; elle ne les remplace pas.

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
- Le fichier `auth.phc`, le venv, `data/`, les rapports, bases et caches sont
  exclus de Git.
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
| Rust (`cargo test`) | **47/47** (7 scanner, 20 historique, 14 inventaire, 6 auth) |
| Python, venv complet | **145/145** |
| Python, système sans argon2 | **145 exécutés, 10 tests d'auth ignorés** |
| Intégration Rust → Python | **8/8**, dont 2 E2E avec session |
| `bash -n lancer-nour-sentinel.sh` | réussi |
| JSON | `settings.json`, `security_intelligence.json`, `protocol.json` valides |
| `--help` / `--version` | exécutés |
| `inventory` réel | 2 569 paquets, 43 services, 14 sockets, 6 familles identifiées |
| `full-local` réel | 3 constats (2 medium, 1 info), 3/3 avec preuve, rapport 0600 |

Le test E2E fournit une session courte 0600, équivalente à un lancement
authentifié, et n'utilise jamais de secret en variable d'environnement.

Limites de validation : le test réel de l'Auth Gate interactif et de
`sshd -T` complet dépend de l'environnement (TTY, privilèges, clés d'hôte).
Sans clés d'hôte accessibles, `sshd -T` échoue et l'erreur est conservée dans
`errors` ; elle n'est pas masquée.

## 9. Garde-fous

- Aucune exploitation, aucun brute force, aucun cassage de mot de passe.
- Aucune lecture de `/etc/shadow`, aucun hash, aucun essai de connexion.
- Aucun scan automatique des voisins ARP.
- Aucune remédiation ni blocage automatique.
- Aucune redirection HTTP inter-hôte, aucun corps HTTP.
- Les sondes actives sont limitées à la liste blanche.
- Une sévérité haute ou critique sans preuve reste plafonnée par le modèle
  v0.5.0.

## 10. Installation sur Kali Linux

```bash
unzip NOUR-SENTINEL-LAB-0.6.0-beta1.zip
cd NOUR-SENTINEL-LAB-0.6.0-beta1
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
PYTHONPATH=python-brain python3 -m unittest discover -s tests/python -v
cargo test --manifest-path rust-engine/Cargo.toml
PYTHONPATH=python-brain python3 -m unittest discover -s tests/integration -v
```

Pour exécuter les 10 tests Argon2id sans venv système :

```bash
.venv/bin/python -m unittest discover -s tests/python
```

## 11. Feuille de route du laboratoire

| Itération | Objectif | Critère de sortie |
|---|---|---|
| 0.6.0-beta.1 | Auth, six modules, CLI, stockage | suites vertes, limites documentées |
| 0.6.0-beta.2 | Durcir CVE/TLS/journaux | preuves et faux positifs documentés |
| 0.6.0-beta.3 | Corrélation multi-source | actif → version → CVE → KEV/EPSS |
| Fusion | Rebaser sur v0.5.0 puis intégrer par lots | audit complet, tests E2E, revue sécurité |

## 12. Références

- OWASP — Password Storage Cheat Sheet (Argon2id)
- OSV — API `POST /v1/query`
- NVD — Vulnerability API 2.0
- CISA — Known Exploited Vulnerabilities
- FIRST — EPSS API
- Python — `ssl`
- systemd — `journalctl`

---

**NOUR SENTINEL LAB — dossier de livraison 0.6.0-beta.1**
