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

Frontière : Python ne réalise aucune opération réseau et n'écrit pas
d'historique ; il reçoit un message sur stdin et répond sur stdout.

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

## 8. Évolutions

- Collecteur réseau étendu.
- Analyseur de journaux.
- Analyse comportementale multi-scans.
- Interface graphique.
- Moteur de détection avancé.
