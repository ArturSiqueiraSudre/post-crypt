"""Confere, sem janela, se o programa empacotado responde.

Usado no CI depois de gerar o executável (``Post-Crypt.exe --autoteste``): a página
precisa carregar com o token, e a API precisa aceitar o token e recusar quem não o tem.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from postcrypt.desktop.janela import validar_url_local

PRAZO_S = 5.0
MAX_RESPOSTA = 2_000_000
_TOKEN = re.compile(r'<meta name="pc-token" content="([A-Za-z0-9_\-]{20,100})">')


class FalhaAutoteste(RuntimeError):
    """O programa não respondeu como deveria."""


@dataclass(frozen=True)
class Resposta:
    status: int
    corpo: bytes


Buscar = Callable[[str, dict[str, str]], Resposta]


def buscar(url: str, cabecalhos: dict[str, str]) -> Resposta:
    """GET com prazo e limite de tamanho, sem proxy (o painel é local)."""
    validar_url_local(url)
    pedido = urllib.request.Request(url, headers=cabecalhos)  # noqa: S310 - só 127.0.0.1
    abridor = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with abridor.open(pedido, timeout=PRAZO_S) as resposta:
            return Resposta(resposta.status, resposta.read(MAX_RESPOSTA))
    except urllib.error.HTTPError as erro:
        return Resposta(erro.code, b"")


def executar(url: str, versao: str, *, buscar: Buscar = buscar) -> dict[str, str]:
    """Levanta ``FalhaAutoteste`` com o motivo; devolve um resumo quando tudo confere."""
    validar_url_local(url)
    pagina = buscar(url, {})
    if pagina.status != 200:
        raise FalhaAutoteste(f"a página do painel respondeu {pagina.status}")
    achado = _TOKEN.search(pagina.corpo.decode("utf-8", "replace"))
    if achado is None:
        raise FalhaAutoteste("a página do painel veio sem o token")
    token = achado.group(1)

    if buscar(url + "api/info", {}).status != 403:
        raise FalhaAutoteste("a API respondeu a um pedido sem token")
    info = buscar(url + "api/info", {"X-Post-Crypt-Token": token})
    if info.status != 200:
        raise FalhaAutoteste(f"a API respondeu {info.status} com o token")
    try:
        dados = json.loads(info.corpo)
    except ValueError as exc:
        raise FalhaAutoteste("a API devolveu algo que não é JSON") from exc
    if not isinstance(dados, dict):
        raise FalhaAutoteste("a API devolveu outra versão do programa")
    campos = cast("dict[str, object]", dados)
    if campos.get("versao") != versao:
        raise FalhaAutoteste("a API devolveu outra versão do programa")
    if not campos.get("regras"):
        raise FalhaAutoteste("as regras não foram carregadas")
    return {"versao": str(campos["versao"]), "regras": str(campos["regras"])}
