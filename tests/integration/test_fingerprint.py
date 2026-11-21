"""Fingerprint contra servidores TLS reais (locais) com banner conhecido de antemão."""

import pytest

from postcrypt.classify import load_rules
from postcrypt.fingerprint import NOT_AUTHORIZED, NOT_OBSERVED, OBSERVED, UNSUPPORTED
from postcrypt.http_banner.probe import BannerRequest, fetch_banner
from postcrypt.scanner import scan_target
from postcrypt.scope import Target
from tests.support.pki import TestPKI
from tests.support.tls_server import TLSServer

pytestmark = pytest.mark.integration
RULES = load_rules()
BANNER = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13\r\n\r\n"


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return TestPKI(tmp_path_factory.mktemp("pki"))


def alvo(port, *, autorizado=True, sni="banner.lab"):
    return Target("127.0.0.1", port, label="banner", sni=sni, http_fingerprint=autorizado)


def test_banner_conhecido_e_identificado_com_um_unico_pedido(pki):
    cert = pki.issue("banner.lab")
    with TLSServer("classical", cert.cert_path, cert.key_path, http_response=BANNER) as srv:
        result = scan_target(alvo(srv.port), RULES, timeout=3)
    fp = result.fingerprint
    assert fp.status == OBSERVED
    assert {(p.name, p.version, p.support) for p in fp.products} == {
        ("Apache httpd", "2.4.58", "supported"),
        ("OpenSSL", "3.0.13", UNSUPPORTED),
    }
    assert len(srv.http_requests) == 1
    pedido = srv.http_requests[0]
    assert pedido.startswith(b"HEAD / HTTP/1.1\r\n")
    assert f"Host: banner.lab:{srv.port}".encode() in pedido
    assert fp.tls_stack is not None


def test_sem_autorizacao_o_servidor_nunca_recebe_pedido_http(pki):
    cert = pki.issue("banner.lab")
    with TLSServer("classical", cert.cert_path, cert.key_path, http_response=BANNER) as srv:
        result = scan_target(alvo(srv.port, autorizado=False), RULES, timeout=3)
    assert result.fingerprint.status == NOT_AUTHORIZED
    assert srv.http_requests == []


def test_servico_tls_que_nao_fala_http_e_nao_observado(pki):
    cert = pki.issue("mudo.lab")
    with TLSServer("classical", cert.cert_path, cert.key_path) as srv:
        result = scan_target(alvo(srv.port, sni="mudo.lab"), RULES, timeout=2)
    assert result.fingerprint.status == NOT_OBSERVED
    assert result.fingerprint.products == ()


def test_resposta_malformada_do_servidor_e_nao_observado(pki):
    cert = pki.issue("quebrado.lab")
    lixo = b"\x1b[2J\x00HTTP/9.9 xyz\r\n\r\n"
    with TLSServer("classical", cert.cert_path, cert.key_path, http_response=lixo) as srv:
        result = scan_target(alvo(srv.port, sni="quebrado.lab"), RULES, timeout=2)
    assert result.fingerprint.status == NOT_OBSERVED
    assert "\x1b" not in result.fingerprint.detail


def test_adaptador_fala_com_servidor_legado_de_troca_de_chave_rsa(pki):
    cert = pki.issue("legado.lab", key_type="rsa")
    with TLSServer("tls12-rsa", cert.cert_path, cert.key_path, http_response=BANNER) as srv:
        bruto = fetch_banner(BannerRequest("127.0.0.1", srv.port, "legado.lab", 3))
    assert bruto.startswith(b"HTTP/1.1 200 OK")


def test_servidor_so_tls13_tem_assinatura_pelo_hello_retry_request(pki):
    """Sem TLS 1.2, o sinal de pilha sai do HelloRetryRequest da tentativa clássica."""
    cert = pki.issue("tls13.lab")
    with TLSServer("tls13-classical", cert.cert_path, cert.key_path, http_response=BANNER) as srv:
        result = scan_target(alvo(srv.port, sni="tls13.lab"), RULES, timeout=3)
    stack = result.fingerprint.tls_stack
    assert result.observation is not None and not result.observation.tls12
    assert stack is not None and stack.basis == "hello_retry_request"
    assert stack.signature.startswith("h13")
