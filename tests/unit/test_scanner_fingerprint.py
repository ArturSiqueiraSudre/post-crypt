"""Orquestração do fingerprint no scanner: quando o pedido HTTP sai e quando não sai."""

import pytest

from postcrypt.classify import load_rules
from postcrypt.fingerprint import NOT_AUTHORIZED, NOT_OBSERVED, OBSERVED, UNAVAILABLE
from postcrypt.http_banner.probe import BannerRequest, BannerUnavailable
from postcrypt.scanner import observe_fingerprint
from postcrypt.scope import Target
from postcrypt.tls.probe import ServerHelloShape, TLSObservation

RULES = load_rules()
TLS_OK = TLSObservation(
    tls12=True, server_hello=ServerHelloShape("server_hello", 0x0303, 0xC02F, (0xFF01,))
)


class Coletor:
    """Adaptador falso: registra cada pedido e devolve a resposta combinada."""

    def __init__(self, resposta=b"HTTP/1.1 200 OK\r\nServer: nginx/1.30.6\r\n\r\n", erro=None):
        self.resposta = resposta
        self.erro = erro
        self.pedidos: list[BannerRequest] = []

    def __call__(self, pedido: BannerRequest) -> bytes:
        self.pedidos.append(pedido)
        if self.erro:
            raise self.erro
        return self.resposta


def alvo(autorizado=True):
    return Target("10.0.0.5", 8443, label="app", sni="app.exemplo", http_fingerprint=autorizado)


# ---------- caminho feliz ----------


def test_alvo_autorizado_recebe_um_pedido_no_mesmo_host_e_porta():
    coletor = Coletor()
    fp = observe_fingerprint(alvo(), TLS_OK, RULES, 5.0, coletor)
    assert fp.status == OBSERVED
    assert coletor.pedidos == [BannerRequest("10.0.0.5", 8443, "app.exemplo", 5.0)]
    assert fp.tls_stack is not None


# ---------- limites e falhas ----------


def test_sem_autorizacao_nenhum_pedido_sai():
    coletor = Coletor()
    fp = observe_fingerprint(alvo(autorizado=False), TLS_OK, RULES, 5.0, coletor)
    assert fp.status == NOT_AUTHORIZED and coletor.pedidos == []


@pytest.mark.parametrize("obs", [None, TLSObservation(not_tls=True)])
def test_sem_tls_nenhum_pedido_sai_mesmo_autorizado(obs):
    coletor = Coletor()
    fp = observe_fingerprint(alvo(), obs, RULES, 5.0, coletor)
    assert fp.status == UNAVAILABLE and coletor.pedidos == []


def test_adaptador_que_falha_vira_nao_observado():
    coletor = Coletor(erro=BannerUnavailable("o servidor não respondeu ao pedido HTTP a tempo"))
    fp = observe_fingerprint(alvo(), TLS_OK, RULES, 5.0, coletor)
    assert fp.status == NOT_OBSERVED and "a tempo" in fp.http.error
    assert len(coletor.pedidos) == 1  # falhou: não tenta de novo


# ---------- entradas maliciosas ----------


@pytest.mark.parametrize(
    "resposta",
    [b"SSH-2.0-OpenSSH_9.6\r\n", b"\x00" * 64, b"HTTP/1.1 200 OK\r\nServer: x", b""],
)
def test_resposta_hostil_ou_quebrada_vira_nao_observado(resposta):
    fp = observe_fingerprint(alvo(), TLS_OK, RULES, 5.0, Coletor(resposta))
    assert fp.status == NOT_OBSERVED and fp.products == ()
    assert "\x00" not in fp.detail and "SSH" not in fp.detail  # o motivo é nosso, não do servidor
