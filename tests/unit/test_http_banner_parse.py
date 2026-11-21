"""Leitura do cabeçalho HTTP devolvido pelo servidor varrido: tudo aqui é hostil."""

import pytest

from postcrypt.http_banner.parse import (
    MAX_FIELDS,
    MAX_HEAD_BYTES,
    MAX_LINE_BYTES,
    MAX_VALUE_CHARS,
    HTTPHeadError,
    parse_response_head,
    split_head,
)


def head(*lines: str, status: str = "HTTP/1.1 200 OK") -> bytes:
    return ("\r\n".join([status, *lines]) + "\r\n\r\n").encode("latin-1")


# ---------- caminho feliz ----------


def test_le_status_e_so_os_cabecalhos_de_software():
    raw = head(
        "Server: Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13",
        "X-Powered-By: PHP/8.1.2",
        "Set-Cookie: sessao=segredo",
        "Content-Type: text/html",
    )
    parsed = parse_response_head(raw)
    assert parsed.status_code == 200
    assert parsed.headers == {
        "server": "Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13",
        "x-powered-by": "PHP/8.1.2",
    }
    assert parsed.dropped_fields == 0


def test_nome_do_cabecalho_nao_diferencia_maiusculas():
    parsed = parse_response_head(head("SERVER: nginx/1.30.6"))
    assert parsed.headers == {"server": "nginx/1.30.6"}


def test_corpo_depois_do_cabecalho_e_ignorado():
    raw = head("Server: nginx") + b"<html>qualquer coisa \x00\x1b</html>"
    assert parse_response_head(raw).headers == {"server": "nginx"}


@pytest.mark.parametrize("status", ["HTTP/1.0 301", "HTTP/1.1 404 Not Found", "HTTP/1.1 503 "])
def test_qualquer_status_http_1x_vale(status):
    assert parse_response_head(head("Server: x", status=status)).status_code == int(status[9:12])


# ---------- limites ----------


def test_resposta_vazia():
    with pytest.raises(HTTPHeadError, match="não respondeu"):
        parse_response_head(b"")


def test_resposta_sem_fim_de_cabecalho_e_incompleta():
    with pytest.raises(HTTPHeadError, match="incompleta"):
        parse_response_head(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n")


def test_cabecalho_maior_que_o_teto_e_recusado():
    raw = b"HTTP/1.1 200 OK\r\nX-A: " + b"a" * MAX_HEAD_BYTES
    with pytest.raises(HTTPHeadError, match="longo demais"):
        parse_response_head(raw)


def test_fim_do_cabecalho_alem_do_teto_nao_e_aceito():
    raw = b"HTTP/1.1 200 OK\r\n" + b"X-A: b\r\n" * (MAX_HEAD_BYTES // 8 + 10) + b"\r\n"
    with pytest.raises(HTTPHeadError):
        split_head(raw)


def test_numero_maximo_de_campos():
    ok = head(*["X-A: b"] * MAX_FIELDS, "Server: nginx")
    with pytest.raises(HTTPHeadError, match="campos demais"):
        parse_response_head(ok)
    assert parse_response_head(head(*["X-A: b"] * (MAX_FIELDS - 1), "Server: nginx")).headers


def test_valor_longo_e_cortado():
    parsed = parse_response_head(head("Server: " + "n" * (MAX_VALUE_CHARS + 50)))
    assert len(parsed.headers["server"]) == MAX_VALUE_CHARS


def test_linha_longa_demais_e_descartada():
    parsed = parse_response_head(head("Server: " + "n" * MAX_LINE_BYTES))
    assert parsed.headers == {} and parsed.dropped_fields == 1


def test_valor_vazio_nao_vira_evidencia():
    assert parse_response_head(head("Server:   ")).headers == {}


# ---------- entradas maliciosas ----------


@pytest.mark.parametrize(
    "raw",
    [
        b"SSH-2.0-OpenSSH_9.6\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        b"HTTP/2 200\r\nserver: nginx\r\n\r\n",
        b"HTTP/1.1 999 Bad\r\n\r\n",
        b"<html><body>oi</body></html>\r\n\r\n",
        b"\x16\x03\x03\x00\x02\x02\x28\r\n\r\n",
    ],
)
def test_resposta_que_nao_e_http_1x_e_recusada(raw):
    with pytest.raises(HTTPHeadError, match="não é HTTP"):
        parse_response_head(raw)


@pytest.mark.parametrize(
    "linha",
    [
        "Server: nginx\x1b[31m vermelho",  # sequência de terminal
        "Server: nginx\x00/1.0",
        "Server: nginx\rX-Injetado: 1",  # CR solto tentando abrir outro campo
        "Server: ngiñx/1.0",  # fora do ASCII
        "Ser ver: nginx",  # nome com espaço
        ": nginx",  # sem nome
        "Server nginx",  # sem dois-pontos
        " Server: nginx",  # continuação obsoleta (obs-fold)
    ],
)
def test_campo_fora_do_formato_e_descartado_e_contado(linha):
    parsed = parse_response_head(head(linha))
    assert "server" not in parsed.headers
    assert parsed.dropped_fields == 1


def test_status_com_byte_de_controle_e_recusado():
    with pytest.raises(HTTPHeadError):
        parse_response_head(head("Server: nginx", status="HTTP/1.1 200 O\x1bK"))


def test_cabecalho_repetido_nao_sobrescreve_o_primeiro():
    parsed = parse_response_head(head("Server: nginx/1.30.6", "Server: falso/9.9"))
    assert parsed.headers["server"] == "nginx/1.30.6"


def test_html_no_valor_fica_como_texto_e_nunca_e_interpretado_aqui():
    parsed = parse_response_head(head("Server: <script>alert(1)</script>"))
    assert parsed.headers["server"] == "<script>alert(1)</script>"
