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
- [ ] Audit final et publication de la version.

## VERSION 0.4.0 — Behavioral Intelligence

- [ ] Analyse des journaux système.
- [ ] Détection comportementale.
- [ ] Historique des observations.
- [ ] Classification avancée des risques.

## VERSION 0.5.0 — Dashboard

- [ ] Interface utilisateur.
- [ ] Visualisation réseau.
- [ ] Statistiques.
- [ ] Rapports exportables.

## VERSION 1.0.0 — Production

- [ ] Architecture stabilisée.
- [ ] Tests automatisés complets.
- [ ] Documentation complète.
- [ ] Audit de sécurité.
- [ ] Sécurité renforcée.
