# NOUR SENTINEL — Tests d'intégration

## 1. Objectif

Les tests d'intégration ont pour objectif de vérifier le fonctionnement global de NOUR SENTINEL et la communication entre ses différents composants.

## 2. Architecture testée

Le scénario d'intégration repose sur les étapes suivantes :

1. Rust charge `config/settings.json`.
2. Rust valide les paramètres de configuration.
3. Rust effectue la collecte des observations réseau.
4. Rust construit le message JSON.
5. Rust transmet les données au moteur Python via stdin.
6. Python analyse les événements.
7. Python retourne un rapport JSON via stdout.
8. Rust vérifie et affiche le résultat.

## 3. État actuel — v0.2.1

- Chargement de la configuration : validé.
- Validation des paramètres : validée.
- Communication Rust → Python : validée manuellement.
- Transmission JSON : fonctionnelle.
- Analyse Python : validée par tests unitaires.
- Vérification de la réponse JSON : implémentée.
- Tests automatisés d'intégration : à développer.

## 4. Scénarios prévus

- Transmission d'un événement réseau valide.
- Traitement d'une entrée JSON vide.
- Gestion d'une erreur du moteur Python.
- Rejet d'une réponse JSON invalide.
- Vérification de la cohérence du rapport final.
- Vérification du comportement en cas de configuration invalide.

## 5. Sécurité

Les tests doivent utiliser exclusivement des systèmes contrôlés ou des cibles explicitement autorisées.

Aucun scan automatique non autorisé et aucune action automatique de sécurité ne sont permis.

## 6. Évolutions prévues — v0.3.0

- Automatisation des tests Rust → Python.
- Vérification des échanges JSON.
- Tests de résistance aux erreurs.
- Intégration contrôlée de la découverte ARP.
- Validation des cibles avant toute vérification TCP.

**NOUR SENTINEL — Integration Testing**
