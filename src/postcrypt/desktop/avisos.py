"""Caixa de mensagem do sistema, para erros que a pessoa precisa ver."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import TextIO

MB_OK = 0x0
MB_ICONERROR = 0x10
MB_ICONINFORMATION = 0x40
LIMITE_TEXTO = 2000

Aviso = Callable[[str, str], None]


def _limpar(texto: str) -> str:
    """Corta textos longos e remove caracteres de controle (exceto quebra de linha)."""
    limpo = "".join(c for c in texto if c == "\n" or c.isprintable())
    return limpo[:LIMITE_TEXTO]


def mostrar_erro(titulo: str, texto: str) -> None:
    _mostrar(titulo, texto, MB_ICONERROR)


def mostrar_informacao(titulo: str, texto: str) -> None:
    """Bloqueia até a pessoa clicar em OK: é assim que o modo navegador sabe quando encerrar."""
    _mostrar(titulo, texto, MB_ICONINFORMATION)


def _mostrar(titulo: str, texto: str, icone: int, *, saida: TextIO | None = None) -> None:
    titulo, texto = _limpar(titulo), _limpar(texto)
    if sys.platform == "win32":
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, texto, titulo, MB_OK | icone)
        return
    destino = saida or sys.stderr
    if destino is not None:
        print(f"{titulo}: {texto}", file=destino)
    if icone == MB_ICONINFORMATION and sys.stdin is not None and sys.stdin.isatty():
        input("Tecle Enter para encerrar o Post-Crypt. ")
