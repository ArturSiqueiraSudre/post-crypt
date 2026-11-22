import json

import pytest

from postcrypt.desktop import autoteste
from postcrypt.desktop.autoteste import FalhaAutoteste, Resposta
from postcrypt.desktop.janela import UrlRecusada

URL = "http://127.0.0.1:51234/"
TOKEN = "a" * 43
PAGINA = f'<html><meta name="pc-token" content="{TOKEN}"></html>'.encode()


def servidor(pagina=PAGINA, info=None, sem_token=403, com_token=200, status_pagina=200):
    corpo_info = json.dumps(info or {"versao": "0.1.0", "regras": "2026-11-20"}).encode()
    pedidos = []

    def buscar(url, cabecalhos):
        pedidos.append((url, dict(cabecalhos)))
        if url == URL:
            return Resposta(status_pagina, pagina)
        if cabecalhos.get("X-Post-Crypt-Token") == TOKEN:
            return Resposta(com_token, corpo_info)
        return Resposta(sem_token, b"")

    return buscar, pedidos


def test_painel_saudavel_passa():
    buscar, pedidos = servidor()
    assert autoteste.executar(URL, "0.1.0", buscar=buscar) == {
        "versao": "0.1.0",
        "regras": "2026-11-20",
    }
    assert [p[0] for p in pedidos] == [URL, URL + "api/info", URL + "api/info"]


@pytest.mark.parametrize(
    ("ajuste", "motivo"),
    [
        ({"status_pagina": 500}, "respondeu 500"),
        ({"pagina": b"<html></html>"}, "sem o token"),
        ({"pagina": b'<meta name="pc-token" content="{{TOKEN}}">'}, "sem o token"),
        ({"sem_token": 200}, "sem token"),
        ({"com_token": 403}, "403 com o token"),
        ({"info": {"versao": "9.9.9", "regras": "x"}}, "outra versão"),
        ({"info": {"versao": "0.1.0", "regras": ""}}, "regras"),
    ],
)
def test_cada_defeito_vira_falha_com_motivo(ajuste, motivo):
    buscar, _ = servidor(**ajuste)
    with pytest.raises(FalhaAutoteste, match=motivo):
        autoteste.executar(URL, "0.1.0", buscar=buscar)


def test_api_que_devolve_lixo_vira_falha():
    def buscar(url, cab):
        if url == URL:
            return Resposta(200, PAGINA)
        return Resposta(200 if cab else 403, b"<html>nao e json")

    with pytest.raises(FalhaAutoteste, match="não é JSON"):
        autoteste.executar(URL, "0.1.0", buscar=buscar)


def test_api_que_devolve_lista_vira_falha():
    def buscar(url, cab):
        if url == URL:
            return Resposta(200, PAGINA)
        return Resposta(200 if cab else 403, b"[1, 2]")

    with pytest.raises(FalhaAutoteste, match="outra versão"):
        autoteste.executar(URL, "0.1.0", buscar=buscar)


def test_autoteste_so_conversa_com_o_painel_local():
    with pytest.raises(UrlRecusada):
        autoteste.executar(
            "http://exemplo.com:80/", "0.1.0", buscar=lambda u, c: Resposta(200, b"")
        )
    with pytest.raises(UrlRecusada):
        autoteste.buscar("http://169.254.169.254:80/latest/meta-data/", {})
