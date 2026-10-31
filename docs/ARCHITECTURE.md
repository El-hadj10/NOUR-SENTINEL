
# NOUR SENTINEL - Architecture

## 1. Présentation

NOUR SENTINEL utilise une architecture hybride
Rust + Python.

## 2. Rust Engine

Responsabilités :

- Initialisation.
- Gestion des événements.
- Transmission des données.
- Communication interprocessus.
- Réception des résultats.

## 3. Python Brain

Responsabilités :

- Analyse des événements.
- Détection des anomalies.
- Classification des alertes.
- Production des résultats JSON.

## 4. Communication

Le moteur Rust démarre un processus Python.

Les données sont transmises via stdin.

Les résultats sont récupérés via stdout.

Le format de communication est JSON.

## 5. Sécurité

- Aucune action automatique de blocage.
- Analyse passive des données fournies.
- Utilisation sur des réseaux autorisés.
- Validation des entrées.
- Gestion des erreurs.

## 6. Évolutions

- Collecteur réseau.
- Analyseur de journaux.
- Base de données.
- Interface graphique.
- Moteur de détection avancé.
