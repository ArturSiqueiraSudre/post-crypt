"""Prazo total da troca da sonda TLS: conexão e relógio falsos, sem rede."""

import struct

import pytest

from postcrypt.tls.probe import ProbeConnectionError, exchange


def server_hello_record() -> bytes:
    body = (
        struct.pack("!H", 0x0303)
        + b"\x01" * 32
        + bytes([32])
        + b"\x11" * 32
        + struct.pack("!H", 0xC02F)
        + b"\x00"
        + struct.pack("!H", 0)
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


class Relogio:
    def __init__(self, passo: float):
        self.agora = 0.0
        self.passo = passo

    def __call__(self) -> float:
        self.agora += self.passo
        return self.agora


class Conexao:
    """Socket falso que entrega ``dados`` em pedaços de ``tamanho`` bytes."""

    def __init__(self, dados: bytes, tamanho: int):
        self.dados = dados
        self.tamanho = tamanho
        self.leituras = 0
        self.timeouts: list[float] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def sendall(self, _data):
        pass

    def settimeout(self, valor):
        self.timeouts.append(valor)

    def recv(self, _n):
        self.leituras += 1
        parte, self.dados = self.dados[: self.tamanho], self.dados[self.tamanho :]
        return parte


def troca(conexao, relogio, timeout=3.0):
    return exchange(
        "127.0.0.1",
        443,
        b"hello",
        timeout=timeout,
        clock=relogio,
        connect=lambda _endereco, _timeout: conexao,
    )


# ---------- caminho feliz ----------


def test_resposta_rapida_e_lida_normalmente():
    resp = troca(Conexao(server_hello_record(), 16384), Relogio(passo=0.01))
    assert resp.kind == "server_hello" and resp.cipher_suite == 0xC02F


def test_cada_leitura_so_recebe_o_que_resta_do_prazo():
    conexao = Conexao(server_hello_record(), 10)
    troca(conexao, Relogio(passo=0.1), timeout=3.0)
    assert len(conexao.timeouts) == conexao.leituras > 1  # um prazo novo antes de cada leitura
    assert conexao.timeouts == sorted(conexao.timeouts, reverse=True)
    assert all(0 < t <= 3.0 for t in conexao.timeouts)


# ---------- limites e falhas ----------


def test_servidor_que_goteja_para_no_prazo_total():
    """Um byte por leitura, 1 s por leitura no relógio: com prazo de 3 s, no máximo 3 leituras."""
    conexao = Conexao(server_hello_record(), 1)
    resp = troca(conexao, Relogio(passo=1.0), timeout=3.0)
    assert resp.kind == "no_response"
    assert conexao.leituras <= 3


def test_prazo_esgotado_no_meio_da_resposta_nao_inventa_resultado():
    conexao = Conexao(server_hello_record(), 20)  # 20 bytes por leitura, 2 s cada no relógio
    resp = troca(conexao, Relogio(passo=2.0), timeout=3.0)
    assert resp.kind == "no_response"


def test_conexao_recusada_continua_sendo_erro_de_conexao():
    def recusa(_endereco, _timeout):
        raise ConnectionRefusedError("recusado")

    with pytest.raises(ProbeConnectionError):
        exchange("127.0.0.1", 443, b"hello", timeout=3.0, connect=recusa)


# ---------- entradas maliciosas ----------


def test_resposta_que_nao_e_tls_continua_recusada_dentro_do_prazo():
    resp = troca(Conexao(b"SSH-2.0-OpenSSH_9.6\r\n", 1), Relogio(passo=0.01))
    assert resp.kind == "not_tls"
