import types
import webbrowser

import pytest

from postcrypt.desktop import janela

URL = "http://127.0.0.1:51234/"


class FalsoWebview(types.ModuleType):
    def __init__(self, *, falha_ao_iniciar=None):
        super().__init__("webview")
        self.settings = {"ALLOW_DOWNLOADS": False, "OPEN_EXTERNAL_LINKS_IN_BROWSER": False}
        self.janelas = []
        self.inicios = []
        self._falha = falha_ao_iniciar

    def create_window(self, titulo, url, **opcoes):
        self.janelas.append((titulo, url, opcoes))

    def start(self, **opcoes):
        if self._falha:
            raise self._falha
        self.inicios.append(opcoes)


def test_abre_janela_com_downloads_e_o_painel_local():
    wv = FalsoWebview()
    assert janela.abrir_janela(URL, icone="x.ico", carregar=lambda: wv, plataforma="win32")
    titulo, url, opcoes = wv.janelas[0]
    assert (titulo, url) == ("Post-Crypt", URL)
    assert opcoes["text_select"] is True and opcoes["min_size"] == janela.TAMANHO_MINIMO
    assert wv.settings["ALLOW_DOWNLOADS"] is True
    assert wv.inicios == [{"gui": "edgechromium", "private_mode": True, "icon": "x.ico"}]


def test_fora_do_windows_deixa_o_pywebview_escolher():
    wv = FalsoWebview()
    janela.abrir_janela(URL, carregar=lambda: wv, plataforma="linux")
    assert wv.inicios[0]["gui"] is None


def test_sem_pywebview_instalado_devolve_false():
    def ausente():
        raise ImportError("webview")

    assert janela.abrir_janela(URL, carregar=ausente) is False


def test_sem_webview2_devolve_false_para_cair_no_navegador():
    wv = FalsoWebview(falha_ao_iniciar=RuntimeError("WebView2 não encontrado"))
    assert janela.abrir_janela(URL, carregar=lambda: wv, plataforma="win32") is False


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:51234/",
        "http://localhost:51234/",
        "http://127.0.0.1/",
        "http://127.0.0.1:0/",
        "http://evil.com:80/",
        "http://user:senha@127.0.0.1:51234/",
        "http://127.0.0.1.evil.com:51234/",
        "file:///C:/Windows/System32/",
        "javascript:alert(1)",
        "",
    ],
)
def test_url_que_nao_e_o_painel_local_e_recusada(url):
    with pytest.raises(janela.UrlRecusada):
        janela.validar_url_local(url)
    wv = FalsoWebview()
    with pytest.raises(janela.UrlRecusada):
        janela.abrir_janela(url, carregar=lambda: wv)
    assert wv.janelas == []
    with pytest.raises(janela.UrlRecusada):
        janela.abrir_no_navegador(url, abrir=lambda u: True)


def test_navegador_recebe_a_url_do_painel():
    abertas = []
    assert janela.abrir_no_navegador(URL, abrir=lambda u: abertas.append(u) or True)
    assert abertas == [URL]


def test_navegador_que_falha_devolve_false():
    def quebra(_u):
        raise webbrowser.Error("sem navegador")

    assert janela.abrir_no_navegador(URL, abrir=quebra) is False
    assert janela.abrir_no_navegador(URL, abrir=lambda u: False) is False
