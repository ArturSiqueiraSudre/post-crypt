"""O aplicativo de verdade: servidor real em 127.0.0.1 e o autoteste contra ele."""

import urllib.error
import urllib.request

import pytest

from postcrypt import __version__
from postcrypt.desktop import app, autoteste
from postcrypt.desktop.servidor import ServidorPainel


def test_servidor_real_passa_no_autoteste():
    servidor = ServidorPainel(app.criar_app_do_painel())
    url = servidor.iniciar()
    try:
        assert autoteste.executar(url, __version__)["versao"] == __version__
    finally:
        servidor.parar()
    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(url, timeout=1)  # noqa: S310 - porta já fechada


def test_main_em_modo_autoteste_sobe_confere_e_desliga(tmp_path, capsys):
    deps = app.Dependencias(pasta_de_dados=lambda: tmp_path)
    assert app.main(["--autoteste"], deps) == 0
    assert "autoteste ok" in capsys.readouterr().out
    assert "autoteste ok" in (tmp_path / "logs" / "post-crypt.log").read_text(encoding="utf-8")


def test_log_do_aplicativo_nao_guarda_o_token(tmp_path):
    deps = app.Dependencias(pasta_de_dados=lambda: tmp_path)
    tokens: list[str] = []
    original = autoteste._TOKEN.search

    class Espiao:
        def search(self, texto):
            achado = original(texto)
            if achado:
                tokens.append(achado.group(1))
            return achado

    autoteste._TOKEN, guardado = Espiao(), autoteste._TOKEN
    try:
        assert app.main(["--autoteste"], deps) == 0
    finally:
        autoteste._TOKEN = guardado
    assert tokens
    assert tokens[0] not in (tmp_path / "logs" / "post-crypt.log").read_text(encoding="utf-8")
