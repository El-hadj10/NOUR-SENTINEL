"""Versions canoniques de NOUR SENTINEL.

- ``CORE_VERSION`` : moteur réseau/analyse stable (v0.5.0) ;
- ``LAB_VERSION`` : couche laboratoire additive (0.6.0-beta.4) ;
- ``PROTOCOL_VERSION`` : contrat JSON Rust -> Python.

Les rapports conservent ``version`` et ``base_version`` pour les anciens
lecteurs ; les trois champs ci-dessous sont additifs.
"""

CORE_VERSION = "0.5.0"
LAB_VERSION = "0.6.0-beta.4"
PROTOCOL_VERSION = "3.0"

__all__ = ["CORE_VERSION", "LAB_VERSION", "PROTOCOL_VERSION"]
