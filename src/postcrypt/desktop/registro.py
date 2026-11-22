"""Pasta de dados do usuário e log em arquivo.

O executável não tem console: sem um log em arquivo, um erro some sem deixar rastro.
O log nunca recebe o token do painel nem dados de varredura, só eventos do programa.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Protocol, TextIO

NOME_DA_PASTA = "Post-Crypt"
ARQUIVO_DE_LOG = "post-crypt.log"
TAMANHO_MAXIMO_LOG = 1_000_000  # bytes por arquivo
ARQUIVOS_GUARDADOS = 3
FORMATO = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class SaidasPadrao(Protocol):
    stdout: TextIO | None
    stderr: TextIO | None


def pasta_de_dados(env: Mapping[str, str], plataforma: str, home: Path) -> Path:
    """Onde o programa guarda o log: no Windows, ``%LOCALAPPDATA%\\Post-Crypt``.

    Uma variável de ambiente relativa ou vazia é ignorada: o log nunca cai numa pasta
    escolhida por quem controla o diretório atual.
    """
    if plataforma == "win32":
        base = _absoluta(env.get("LOCALAPPDATA")) or home / "AppData" / "Local"
        return base / NOME_DA_PASTA
    base = _absoluta(env.get("XDG_STATE_HOME")) or home / ".local" / "state"
    return base / NOME_DA_PASTA.lower()


def _absoluta(valor: str | None) -> Path | None:
    if not valor:
        return None
    caminho = Path(valor)
    return caminho if caminho.is_absolute() else None


def configurar_registro(pasta: Path, *, nivel: int = logging.INFO) -> Path:
    """Liga o log rotativo em ``<pasta>/logs`` e devolve o caminho do arquivo."""
    logs = pasta / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    arquivo = logs / ARQUIVO_DE_LOG
    manipulador = RotatingFileHandler(
        arquivo,
        maxBytes=TAMANHO_MAXIMO_LOG,
        backupCount=ARQUIVOS_GUARDADOS,
        encoding="utf-8",
    )
    manipulador.setFormatter(logging.Formatter(FORMATO))
    raiz = logging.getLogger()
    for antigo in [h for h in raiz.handlers if getattr(h, "_postcrypt", False)]:
        raiz.removeHandler(antigo)
        antigo.close()
    manipulador._postcrypt = True  # type: ignore[attr-defined]
    raiz.addHandler(manipulador)
    raiz.setLevel(nivel)
    return arquivo


def garantir_saidas_padrao(sistema: SaidasPadrao) -> None:
    """No executável sem console, ``sys.stdout`` e ``sys.stderr`` são ``None``.

    Bibliotecas que escrevem neles quebrariam; elas passam a escrever em ``os.devnull``.
    """
    if sistema.stdout is None:
        sistema.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    if sistema.stderr is None:
        sistema.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
