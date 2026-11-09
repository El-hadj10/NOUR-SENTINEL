"""Autorisation opérationnelle en mémoire, sans session persistante.

Le jeton n'est pas un secret : il matérialise le fait que l'Auth Gate a vérifié
Argon2id dans ce processus. Il disparaît à la fin du processus et n'est jamais
écrit sur disque.

Cette barrière protège les entrées applicatives contre un appel direct
accidentel. Elle ne prétend pas résister à du code Python arbitraire exécuté
dans le même processus ni à un compte Linux compromis.
"""

from contextvars import ContextVar
from secrets import token_hex

_AUTHORIZATION = ContextVar("nour_sentinel_authorization", default=None)


class AuthorizationError(RuntimeError):
    """Collecte ou analyse refusée faute d'authentification préalable."""


def _grant():
    """Délivre une autorisation ; réservé à l'Auth Gate après Argon2id."""

    token = token_hex(32)
    _AUTHORIZATION.set(token)
    return token


def require():
    """Refuse toute opération si l'Auth Gate n'a pas réussi dans ce processus."""

    if not _AUTHORIZATION.get():
        raise AuthorizationError(
            "authentification requise avant toute collecte ou analyse; "
            "utilisez ./lancer-nour-sentinel.sh"
        )


def is_granted():
    return bool(_AUTHORIZATION.get())


def reset():
    """Révoque l'autorisation courante, notamment après un échec d'auth."""

    _AUTHORIZATION.set(None)


__all__ = ["AuthorizationError", "is_granted", "require", "reset"]
