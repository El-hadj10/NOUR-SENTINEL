# NOUR SENTINEL — Audit technique v0.2.0

**Date :** 31 octobre 2026  
**Statut :** Audit technique réalisé  
**Version auditée :** 0.2.0  
**Version corrective :** 0.2.1

---

## 1. Présentation du projet

NOUR SENTINEL est un outil de diagnostic et d'analyse de sécurité réseau reposant sur une architecture hybride composée de deux moteurs complémentaires :

- **Rust Engine :** collecte des observations réseau, vérifie les ports TCP et orchestre les opérations.
- **Python Brain :** analyse les événements, identifie les services et produit les constats de sécurité.

La communication entre les deux moteurs repose sur un échange de données JSON via stdin/stdout.

Le projet privilégie une approche défensive, contrôlée et sans action automatique sur les systèmes analysés.

## 2. Points forts identifiés

- Architecture hybride Rust et Python.
- Séparation des responsabilités entre collecte et analyse.
- Communication interprocessus basée sur JSON.
- Distinction des états TCP : `open`, `closed` et `filtered_or_unreachable`.
- Découverte passive des voisins via la table ARP.
- Détecteur Python modulaire.
- Configuration externe au code source.
- Dépendances limitées.
- Tests unitaires présents.
- Politique interdisant les actions automatiques.

## 3. Anomalies identifiées

### 3.1 Configuration

- Les ports sensibles étaient initialement définis directement dans le code Python.
- Rust ne chargeait qu'une partie des paramètres de configuration.
- Certaines options de sécurité n'étaient pas suffisamment contrôlées.

### 3.2 Performance

- Le scanner TCP fonctionnait de manière séquentielle.
- La limite de concurrence n'était pas effectivement appliquée.

### 3.3 Tests

- La couverture des tests Python était partielle.
- Les tests Rust étaient insuffisants.
- Les tests automatisés d'intégration étaient absents.

### 3.4 Communication interprocessus

- Le contrat de sortie JSON devait être renforcé.
- La séparation entre stdout et stderr devait être clarifiée.
- La gestion des erreurs devait être formalisée.

### 3.5 Collecte réseau

- La découverte ARP n'était pas reliée aux cibles du scanner TCP.
- Les appareils découverts n'étaient pas automatiquement analysés.

## 4. Corrections réalisées en v0.2.1

- Centralisation de la configuration d'analyse.
- Validation des paramètres.
- Ajout de tests unitaires Rust.
- Ajout de tests unitaires Python.
- Séparation des sorties stdout et stderr.
- Validation de la réponse JSON de Python.

## 5. Points reportés

- Concurrence TCP limitée et effective.
- Tests automatisés d'intégration.
- Intégration contrôlée de la découverte ARP aux cibles TCP.

## 6. Résultats des tests v0.2.1

Les vérifications effectuées ont produit les résultats suivants :

| Vérification | Résultat |
|---|---|
| Compilation Rust (`cargo check`) | Réussie |
| Tests unitaires Rust | 2 réussis |
| Tests unitaires Python | 7 réussis |
| Lecture de la configuration JSON | Réussie |
| Communication Rust → Python | Réussie |
| Analyse des événements | Réussie |
| Génération du rapport JSON | Réussie |

### Résultat de l'exécution

- 3 voisins détectés dans la table ARP.
- 5 observations TCP réalisées sur la cible configurée `127.0.0.1`.
- 2 ports ouverts observés : 22 (SSH) et 80 (HTTP).
- 2 constats générés par le moteur Python.
- Statut final : `analysis_completed`.

**Remarque :** les observations TCP sur `127.0.0.1` concernent la machine locale. Elles ne représentent pas un scan des trois voisins ARP détectés.

## 7. Sécurité et limites connues

Les règles de sécurité suivantes sont maintenues :

- Les cibles doivent être des adresses IP valides.
- Les analyses doivent être réalisées uniquement sur des systèmes explicitement autorisés.
- Le scan automatique des appareils découverts par ARP reste désactivé.
- Les actions automatiques de sécurité restent interdites.
- La découverte ARP est passive.
- Le paramètre `max_concurrency` est configuré et validé, mais son application effective est reportée.

Le paramètre `authorized_scanning_only` représente une politique de fonctionnement. Il ne constitue pas, à lui seul, une vérification technique de l'autorisation du propriétaire d'une cible.

## 8. Feuille de route corrective

### Version 0.2.1

- Centralisation des paramètres d'analyse.
- Renforcement de la validation de configuration.
- Amélioration de la communication Rust/Python.
- Ajout de tests unitaires.
- Vérification du fonctionnement complet des deux moteurs.

### Version 0.3.0 — Évolutions prévues

- Implémentation d'un scanner TCP concurrent.
- Application effective de la limite de concurrence.
- Création de tests automatisés d'intégration.
- Intégration contrôlée des appareils ARP comme cibles potentielles.
- Renforcement de la traçabilité des opérations.
- Amélioration de la gestion des erreurs réseau.

## 9. Critères de validation

La version 0.2.1 doit passer les tests unitaires Rust et Python ainsi que le scénario d'exécution complet Rust → Python.

La publication officielle doit également tenir compte des limites et fonctionnalités reportées décrites dans cet audit.

---

**NOUR SENTINEL — Audit technique**  
*Architecture hybride • Analyse défensive • Contrôle réseau*
