"""Mostra o painel: numa janela própria (WebView2) ou, se não houver, no navegador.

A janela só abre endereços do próprio painel em 127.0.0.1; qualquer outra URL é recusada
antes de chegar ao componente de navegador.
"""

from __future__ import annotations

import logging
import sys
import webbrowser
from collections.abc import Callable
from types import ModuleType
from urllib.parse import urlsplit

TITULO = "Post-Crypt"
LARGURA, ALTURA = 1280, 860
TAMANHO_MINIMO = (900, 640)

log = logging.getLogger(__name__)

CarregarWebview = Callable[[], ModuleType]


class UrlRecusada(ValueError):
    """A URL não é a do painel local."""


def validar_url_local(url: str) -> str:
    """Só ``http://127.0.0.1:<porta>``: nada de outro host, esquema ou credencial na URL."""
    partes = urlsplit(url)
    porta_valida = partes.port is not None and 0 < partes.port < 65536
    if (
        partes.scheme != "http"
        or partes.hostname != "127.0.0.1"
        or not porta_valida
        or partes.username
        or partes.password
    ):
        raise UrlRecusada("o aplicativo só abre o painel local")
    return url


def _carregar_webview() -> ModuleType:
    import webview  # dependência opcional: só existe no aplicativo de computador

    return webview


def abrir_janela(
    url: str,
    *,
    icone: str | None = None,
    carregar: CarregarWebview = _carregar_webview,
    plataforma: str = sys.platform,
) -> bool:
    """Abre a janela e só volta quando a pessoa a fecha.

    Devolve ``False`` (sem levantar) quando não há componente de janela utilizável,
    para que o chamador caia no navegador.
    """
    validar_url_local(url)
    try:
        webview = carregar()
    except ImportError:
        log.warning("componente de janela ausente; o painel vai abrir no navegador")
        return False
    try:
        webview.settings["ALLOW_DOWNLOADS"] = True  # botão "Baixar JSON" do resultado
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
        webview.create_window(
            TITULO,
            url,
            width=LARGURA,
            height=ALTURA,
            min_size=TAMANHO_MINIMO,
            text_select=True,  # copiar achados e nomes de algoritmos
            zoomable=True,
        )
        # No Windows, exige o WebView2 (Edge). Sem ele, falha aqui e o navegador assume.
        gui = "edgechromium" if plataforma == "win32" else None
        webview.start(gui=gui, private_mode=True, icon=icone)
    except Exception:  # qualquer falha do componente de janela leva ao navegador
        log.exception("a janela do painel não abriu; o painel vai abrir no navegador")
        return False
    return True


def abrir_no_navegador(url: str, *, abrir: Callable[[str], bool] = webbrowser.open) -> bool:
    """Abre o painel no navegador padrão; devolve se o sistema aceitou o pedido."""
    validar_url_local(url)
    try:
        return bool(abrir(url))
    except webbrowser.Error:
        log.exception("o navegador padrão não abriu")
        return False
