"""Erros comuns às sondas de protocolo (TLS, SSH)."""

from __future__ import annotations


class ProbeConnectionError(OSError):
    """Não foi possível conversar com o alvo (porta fechada, timeout, reset)."""
