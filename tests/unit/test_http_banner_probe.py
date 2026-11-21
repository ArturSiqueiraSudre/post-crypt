"""Adaptador do pedido HEAD: tudo com conexão e relógio falsos, sem rede."""

import socket
import time

import pytest

from postcrypt.http_banner.parse import MAX_HEAD_BYTES
from postcrypt.http_banner.probe import (
    MAX_TIMEOUT_S,
    USER_AGENT,
    BannerRequest,
    BannerUnavailable,
    build_head_request,
    default_connector,
    fetch_banner,
    host_header,
    read_head,
)

RESPOSTA = b"HTTP/1.1 200 OK\r\nServer: nginx/1.30.6\r\n\r\n"


class Relogio:
    def __init__(self, passo: float = 0.0):
        self.agora = 0.0
        self.passo = passo

    def __call__(self) -> float:
        self.agora += self.passo
        return self.agora


class Conexao:
    """Stream falso: devolve os pedaços em ordem e registra o que recebeu."""

    def __init__(self, pedacos=(), *, erro_no_recv=None, infinito=None):
        self.pedacos = list(pedacos)
        self.erro_no_recv = erro_no_recv
        self.infinito = infinito
        self.enviado = b""
        self.timeouts: list[float | None] = []
        self.fechada = False
        self.leituras = 0

    def sendall(self, data):
        self.enviado += data

    def recv(self, n):
        self.leituras += 1
        if self.erro_no_recv:
            raise self.erro_no_recv
        if self.infinito is not None:
            return self.infinito[:n]
        return self.pedacos.pop(0)[:n] if self.pedacos else b""

    def settimeout(self, valor):
        self.timeouts.append(valor)

    def close(self):
        self.fechada = True


def conector(conexao, pedidos=None, prazos=None):
    def abrir(pedido, prazo):
        if pedidos is not None:
            pedidos.append(pedido)
        if prazos is not None:
            prazos.append(prazo)
        return conexao

    return abrir


# ---------- caminho feliz ----------


def test_pedido_e_um_head_fixo_com_connection_close():
    conexao = Conexao([RESPOSTA])
    bruto = fetch_banner(
        BannerRequest("10.0.0.5", 8443, "app.exemplo.com.br", 5), connector=conector(conexao)
    )
    assert bruto == RESPOSTA
    assert conexao.enviado == (
        b"HEAD / HTTP/1.1\r\nHost: app.exemplo.com.br:8443\r\n"
        + f"User-Agent: {USER_AGENT}\r\n".encode()
        + b"Accept: */*\r\nConnection: close\r\n\r\n"
    )
    assert conexao.fechada


def test_resposta_em_varios_pedacos_e_juntada():
    conexao = Conexao([b"HTTP/1.1 200 OK\r\nSer", b"ver: x\r\n", b"\r\n"])
    assert fetch_banner(BannerRequest("a.exemplo", 443, None, 5), connector=conector(conexao)) == (
        b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n"
    )


@pytest.mark.parametrize(
    ("host", "sni", "porta", "esperado"),
    [
        ("www.exemplo.com.br", "www.exemplo.com.br", 443, "www.exemplo.com.br"),
        ("10.0.0.5", "api.fornecedor.com.br", 8443, "api.fornecedor.com.br:8443"),
        ("10.0.0.5", None, 443, "10.0.0.5"),
        ("2001:db8::1", None, 8443, "[2001:db8::1]:8443"),
    ],
)
def test_cabecalho_host(host, sni, porta, esperado):
    assert host_header(host, sni, porta) == esperado


# ---------- limites e falhas ----------


def test_prazo_total_nunca_passa_do_teto():
    pedidos: list[BannerRequest] = []
    conexao = Conexao([RESPOSTA])
    fetch_banner(BannerRequest("a.exemplo", 443, None, 60), connector=conector(conexao, pedidos))
    assert pedidos[0].timeout == MAX_TIMEOUT_S
    assert all(t is not None and t <= MAX_TIMEOUT_S for t in conexao.timeouts)


@pytest.mark.parametrize("timeout", [0, -1])
def test_timeout_invalido(timeout):
    with pytest.raises(ValueError, match="timeout"):
        fetch_banner(BannerRequest("a.exemplo", 443, None, timeout), connector=conector(Conexao()))


def test_servidor_que_fecha_sem_responder_devolve_vazio():
    conexao = Conexao([])
    assert (
        fetch_banner(BannerRequest("a.exemplo", 443, None, 5), connector=conector(conexao)) == b""
    )
    assert conexao.fechada


def test_timeout_na_leitura_vira_banner_indisponivel():
    conexao = Conexao(erro_no_recv=TimeoutError("lento"))
    with pytest.raises(BannerUnavailable, match="a tempo"):
        fetch_banner(BannerRequest("a.exemplo", 443, None, 5), connector=conector(conexao))
    assert conexao.fechada


def test_queda_no_meio_vira_mensagem_nossa_sem_texto_do_servidor():
    conexao = Conexao(erro_no_recv=ConnectionResetError("\x1b[31mmensagem hostil"))
    with pytest.raises(BannerUnavailable) as exc:
        fetch_banner(BannerRequest("a.exemplo", 443, None, 5), connector=conector(conexao))
    assert "hostil" not in str(exc.value)


def test_falha_ao_abrir_tls_vira_banner_indisponivel():
    def recusa(_pedido, _prazo):
        raise ConnectionRefusedError("recusado")

    with pytest.raises(BannerUnavailable, match="abrir TLS"):
        fetch_banner(BannerRequest("a.exemplo", 443, None, 5), connector=recusa)


# ---------- entradas maliciosas ----------


def test_servidor_sem_fim_para_no_teto_de_bytes():
    conexao = Conexao(infinito=b"A" * 4096)
    bruto = fetch_banner(BannerRequest("a.exemplo", 443, None, 5), connector=conector(conexao))
    assert len(bruto) == MAX_HEAD_BYTES


def test_slowloris_nao_segura_a_varredura():
    """Um byte por leitura, para sempre: o prazo é do pedido inteiro, não de cada leitura."""
    conexao = Conexao(infinito=b"A")
    with pytest.raises(BannerUnavailable, match="a tempo"):
        read_head(conexao, deadline=5.0, clock=Relogio(passo=1.0))
    assert conexao.leituras < 10


@pytest.mark.parametrize(
    "host",
    [
        "a.exemplo\r\nX-Injetado: 1",
        "a.exemplo/../../etc/passwd",
        "a exemplo",
        "a.exemplo@evil.example",
        "",
    ],
)
def test_host_que_injetaria_cabecalho_e_recusado(host):
    with pytest.raises(ValueError):
        host_header(host, None, 443)


@pytest.mark.parametrize("valor", ["a.exemplo\r\n", "a.exemplo:443:1", "a.exemplo:abc", "[::1"])
def test_pedido_so_monta_com_host_valido(valor):
    with pytest.raises(ValueError):
        build_head_request(valor)


# ---------- prazo total também no connect e no handshake ----------


def test_conector_recebe_o_instante_limite_do_pedido():
    prazos: list[float] = []
    relogio = Relogio()
    fetch_banner(
        BannerRequest("a.exemplo", 443, None, 60),
        connector=conector(Conexao([RESPOSTA]), prazos=prazos),
        clock=relogio,
    )
    assert prazos == [MAX_TIMEOUT_S]  # relógio em 0 no início: limite = 0 + teto


class Abridor:
    """TCP falso: devolve uma ponta de socketpair cuja outra ponta nunca fala TLS."""

    def __init__(self, relogio, gasto):
        self.relogio = relogio
        self.gasto = gasto
        self.timeouts: list[float] = []
        self.pares: list[socket.socket] = []

    def __call__(self, _endereco, timeout):
        self.timeouts.append(timeout)
        self.relogio.agora += self.gasto  # o connect consumiu parte do prazo
        cliente, servidor = socket.socketpair()
        self.pares += [cliente, servidor]
        return cliente


def test_handshake_so_recebe_o_tempo_que_o_connect_deixou():
    relogio = Relogio()
    abridor = Abridor(relogio, gasto=4.7)
    inicio = time.monotonic()
    with pytest.raises((TimeoutError, OSError)):
        default_connector(
            BannerRequest("a.exemplo", 443, None, 5), 5.0, clock=relogio, open_tcp=abridor
        )
    decorrido = time.monotonic() - inicio
    for s in abridor.pares:
        s.close()
    assert abridor.timeouts == [5.0]
    assert decorrido < 1.5  # sobraram 0,3 s para o handshake, não os 5 s inteiros


def test_prazo_esgotado_no_connect_nem_tenta_o_handshake():
    relogio = Relogio()
    abridor = Abridor(relogio, gasto=6.0)
    with pytest.raises(BannerUnavailable, match="prazo"):
        default_connector(
            BannerRequest("a.exemplo", 443, None, 5), 5.0, clock=relogio, open_tcp=abridor
        )
    for s in abridor.pares:
        s.close()
