"""NOUR SENTINEL — Laboratoire Security Intelligence (0.6.0-beta.4).

Le laboratoire est une couche additive au-dessus de la ligne stable v0.5.0.
Il ajoute l'authentification propriétaire, la liste blanche réseau, les
connecteurs d'intelligence externe, la persistance des rapports et le CLI.

Rien ici ne remplace les moteurs v0.5.0 : les modules de détection éprouvés
sont réutilisés, et chaque nouvelle capacité reste explicable.
"""

from version import CORE_VERSION, LAB_VERSION, PROTOCOL_VERSION

VERSION = LAB_VERSION
BASE_VERSION = CORE_VERSION
LAB_NAME = "NOUR SENTINEL LAB"

__all__ = [
    "VERSION",
    "BASE_VERSION",
    "CORE_VERSION",
    "LAB_VERSION",
    "PROTOCOL_VERSION",
    "LAB_NAME",
]
