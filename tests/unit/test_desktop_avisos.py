import io
import sys
import types

import pytest

from postcrypt.desktop import avisos


def test_texto_perde_caracteres_de_controle_e_e_cortado():
    sujo = "linha 1\nlinha\x1b[31m 2\x00\x07" + "x" * 5000
    limpo = avisos._limpar(sujo)
    assert "\x1b" not in limpo and "\x00" not in limpo and "\x07" not in limpo
    assert limpo.startswith("linha 1\nlinha[31m 2")
    assert len(limpo) == avisos.LIMITE_TEXTO


def test_fora_do_windows_escreve_na_saida(monkeypatch):
    monkeypatch.setattr(avisos.sys, "platform", "linux")
    monkeypatch.setattr(avisos.sys, "stdin", None)
    saida = io.StringIO()
    avisos._mostrar("Post-Crypt", "falhou\x1b[2J", avisos.MB_ICONERROR, saida=saida)
    assert saida.getvalue() == "Post-Crypt: falhou[2J\n"


def test_sem_saida_nenhuma_nao_quebra(monkeypatch):
    monkeypatch.setattr(avisos.sys, "platform", "linux")
    monkeypatch.setattr(avisos.sys, "stderr", None)
    monkeypatch.setattr(avisos.sys, "stdin", None)
    avisos.mostrar_erro("Post-Crypt", "sem console")
    avisos.mostrar_informacao("Post-Crypt", "sem console")


def test_informacao_no_terminal_espera_enter(monkeypatch):
    monkeypatch.setattr(avisos.sys, "platform", "linux")

    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(avisos.sys, "stdin", Terminal())
    pedidos = []
    monkeypatch.setattr("builtins.input", lambda texto: pedidos.append(texto) or "")
    avisos._mostrar("Post-Crypt", "aberto", avisos.MB_ICONINFORMATION, saida=io.StringIO())
    assert pedidos and "Enter" in pedidos[0]


@pytest.mark.parametrize(
    ("funcao", "icone"),
    [
        (avisos.mostrar_erro, avisos.MB_ICONERROR),
        (avisos.mostrar_informacao, avisos.MB_ICONINFORMATION),
    ],
)
def test_no_windows_usa_a_caixa_de_mensagem_do_sistema(monkeypatch, funcao, icone):
    chamadas = []
    user32 = types.SimpleNamespace(MessageBoxW=lambda *a: chamadas.append(a) or 1)
    ctypes_falso = types.SimpleNamespace(windll=types.SimpleNamespace(user32=user32))
    monkeypatch.setattr(avisos.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "ctypes", ctypes_falso)
    funcao("Post-Crypt", "texto\x00")
    assert chamadas == [(None, "texto", "Post-Crypt", avisos.MB_OK | icone)]
