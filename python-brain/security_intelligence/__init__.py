"""NOUR SENTINEL — Laboratoire Security Intelligence (0.6.0-beta.1).

Le laboratoire est une couche additive au-dessus de la ligne stable v0.5.0.
Il ajoute l'authentification propriétaire, la liste blanche réseau, les
connecteurs d'intelligence externe, la persistance des rapports et le CLI.

Rien ici ne remplace les moteurs v0.5.0 : les modules de détection éprouvés
sont réutilisés, et chaque nouvelle capacité reste explicable.
"""

VERSION = "0.6.0-beta.1"
BASE_VERSION = "0.5.0"
LAB_NAME = "NOUR SENTINEL LAB"

__all__ = ["VERSION", "BASE_VERSION", "LAB_NAME"]
