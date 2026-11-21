"""Fingerprint de versão: lógica pura, montada em memória com as regras do pacote."""

import copy

import pytest

from postcrypt.classify import load_rules
from postcrypt.fingerprint import (
    NOT_AUTHORIZED,
    NOT_OBSERVED,
    OBSERVED,
    SUPPORTED,
    UNAVAILABLE,
    UNKNOWN,
    UNSUPPORTED,
    evaluate_support,
    fingerprint_target,
    identify_products,
    identify_tls_stack,
    parse_product_tokens,
    parse_version,
    tls_stack_signature,
)
from postcrypt.http_banner.parse import HTTPResponseHead
from postcrypt.tls.probe import ServerHelloShape

RULES = load_rules()
HELLO = ServerHelloShape("server_hello", 0x0303, 0xC02C, (0xFF01, 0x000B, 0x0017))


def cabecalho(**headers):
    return HTTPResponseHead(200, {k.replace("_", "-"): v for k, v in headers.items()})


def produtos(**headers):
    return {(p.name, p.version): p for p in identify_products(cabecalho(**headers), RULES)}


def alvo(**kw):
    base = {
        "authorized": True,
        "tls_reachable": True,
        "server_hello": HELLO,
        "head": None,
        "http_error": None,
        "rules": RULES,
    }
    return fingerprint_target(**{**base, **kw})


# ---------- caminho feliz ----------


def test_banner_completo_do_apache_com_openssl():
    tokens = parse_product_tokens("Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13", "server")
    assert [(t.name, t.version, t.comment) for t in tokens] == [
        ("Apache", "2.4.58", "Ubuntu"),
        ("OpenSSL", "3.0.13", None),
    ]


def test_versao_com_suporte_e_sem_suporte():
    achados = produtos(server="Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13")
    apache = achados[("Apache httpd", "2.4.58")]
    openssl = achados[("OpenSSL", "3.0.13")]
    assert apache.support == SUPPORTED and apache.key == "apache" and apache.note is None
    assert openssl.support == UNSUPPORTED
    assert openssl.supported == "3.5.x ou 4.0 ou mais nova"
    assert "ML-KEM" in openssl.note and "Ubuntu" in openssl.note  # a distro vale para o pacote


@pytest.mark.parametrize(
    ("banner", "suporte"),
    [
        ("nginx/1.30.6", SUPPORTED),
        ("nginx/1.31.8", SUPPORTED),
        ("nginx/1.28.3", UNSUPPORTED),
        ("nginx/1.24.0", UNSUPPORTED),
        ("OpenSSL/3.5.9", SUPPORTED),
        ("OpenSSL/4.1.0", SUPPORTED),
        ("OpenSSL/3.6.5", UNSUPPORTED),
        ("OpenSSL/1.1.1w", UNSUPPORTED),
        ("Microsoft-IIS/10.0", SUPPORTED),
        ("Microsoft-IIS/8.5", UNSUPPORTED),
        ("Apache/2.2.34", UNSUPPORTED),
    ],
)
def test_suporte_por_produto(banner, suporte):
    (produto,) = identify_products(cabecalho(server=banner), RULES)
    assert produto.support == suporte


def test_x_powered_by_tambem_identifica():
    achados = produtos(server="nginx/1.30.6", x_powered_by="PHP/8.1.2")
    assert achados[("PHP", "8.1.2")].support == UNSUPPORTED
    assert achados[("PHP", "8.1.2")].source == "x-powered-by"


def test_observado_resume_o_que_o_servidor_declarou():
    fp = alvo(head=cabecalho(server="Apache/2.4.58 OpenSSL/3.0.13"))
    assert fp.status == OBSERVED
    assert fp.http.requested and fp.http.status_code == 200
    assert "Sem suporte do fabricante: OpenSSL 3.0.13" in fp.detail
    assert fp.to_dict()["products"][1]["support"] == UNSUPPORTED


def test_assinatura_da_pilha_tls_e_deterministica_e_no_layout_ja4s():
    assinatura = tls_stack_signature(HELLO)
    assert assinatura == tls_stack_signature(copy.deepcopy(HELLO))
    prefixo, suite, resumo = assinatura.split("_")
    assert prefixo == "t120300" and suite == "c02c" and len(resumo) == 12


def test_ordem_das_extensoes_muda_a_assinatura():
    invertido = ServerHelloShape("server_hello", 0x0303, 0xC02C, tuple(reversed(HELLO.extensions)))
    assert tls_stack_signature(invertido) != tls_stack_signature(HELLO)


def test_pilha_so_ganha_nome_quando_cadastrada():
    regras = copy.deepcopy(RULES)
    assert identify_tls_stack(HELLO, regras).stack is None
    regras["fingerprint"]["tls_stacks"] = {tls_stack_signature(HELLO): "OpenSSL 3.5 (lab)"}
    assert identify_tls_stack(HELLO, regras).stack == "OpenSSL 3.5 (lab)"
    fp = alvo(head=cabecalho(server="nginx/1.30.6"), rules=regras)
    assert "OpenSSL 3.5 (lab) (estimativa)" in fp.detail


# ---------- limites e falhas ----------


def test_sem_conexao_tls_nao_ha_o_que_identificar():
    fp = alvo(tls_reachable=False, server_hello=None)
    assert fp.status == UNAVAILABLE and not fp.http.requested and fp.tls_stack is None


def test_sem_autorizacao_nao_ha_pedido_mas_a_assinatura_fica():
    fp = alvo(authorized=False)
    assert fp.status == NOT_AUTHORIZED
    assert fp.http.requested is False and fp.products == ()
    assert fp.tls_stack is not None and fp.tls_stack.signature.startswith("t12")


def test_autorizado_sem_resposta_e_nao_observado_com_o_motivo():
    fp = alvo(http_error="o servidor não respondeu ao pedido HTTP")
    assert fp.status == NOT_OBSERVED
    assert fp.http.requested and fp.http.error == "o servidor não respondeu ao pedido HTTP"
    assert "não respondeu" in fp.detail


def test_resposta_http_sem_cabecalho_de_software_nao_vira_chute():
    fp = alvo(head=HTTPResponseHead(200, {}))
    assert fp.status == NOT_OBSERVED and fp.products == ()


def test_versao_escondida_fica_sem_avaliacao():
    (produto,) = identify_products(cabecalho(server="nginx"), RULES)
    assert produto.version is None and produto.support == UNKNOWN
    assert "esconde" in produto.note


def test_produto_sem_regra_e_registrado_mas_nao_avaliado():
    (produto,) = identify_products(cabecalho(server="Caddy/2.8.4"), RULES)
    assert produto.key is None and produto.support == UNKNOWN
    assert produto.version == "2.8.4" and "sem regra" in produto.note


def test_produto_repetido_nos_dois_cabecalhos_conta_uma_vez():
    achados = identify_products(cabecalho(server="PHP/8.1.2", x_powered_by="PHP/8.1.2"), RULES)
    assert len(achados) == 1


@pytest.mark.parametrize(
    ("texto", "esperado"),
    [
        ("1.18.0", (1, 18, 0)),
        ("3.0.13", (3, 0, 13)),
        ("1.1.1w", (1, 1, 1)),
        ("8.1.2-1ubuntu2.19", (8, 1, 2)),
        ("10.0", (10, 0)),
        ("1.2.3.4.5.6.7", (1, 2, 3, 4, 5)),
        ("v1.0", None),
        ("", None),
        (None, None),
    ],
)
def test_parte_numerica_da_versao(texto, esperado):
    assert parse_version(texto) == esperado


@pytest.mark.parametrize(
    ("versao", "regras", "esperado"),
    [
        ((3, 5, 9), ["3.5", ">=4.0"], SUPPORTED),
        ((4, 0), ["3.5", ">=4.0"], SUPPORTED),
        ((3, 4, 8), ["3.5", ">=4.0"], UNSUPPORTED),
        ((1, 30), [">=1.30"], SUPPORTED),
        (None, [">=1.30"], UNKNOWN),
        ((1, 30), [], UNKNOWN),
        ((1, 30), "não é lista", UNKNOWN),
        ((1, 30), ["qualquer", 7, None], UNKNOWN),  # regra ilegível nunca aprova
        ((1, 24), ["qualquer", ">=1.30"], UNSUPPORTED),
    ],
)
def test_avaliacao_de_suporte(versao, regras, esperado):
    assert evaluate_support(versao, regras) == esperado


def test_regras_sem_secao_de_fingerprint_nao_quebram():
    regras = {k: v for k, v in RULES.items() if k != "fingerprint"}
    (produto,) = identify_products(cabecalho(server="nginx/1.30.6"), regras)
    assert produto.support == UNKNOWN and produto.key is None
    assert identify_tls_stack(HELLO, regras).stack is None


# ---------- entradas maliciosas ----------


@pytest.mark.parametrize(
    "regras_fingerprint",
    [
        "texto",
        {"products": "texto", "tls_stacks": ["lista"]},
        {"products": {"nginx": "texto"}},
        {"products": {"nginx": {"tokens": "nginx", "supported": ">=1.0"}}},
        {"products": {"nginx": {"tokens": ["nginx"], "supported": [{"$ne": 1}]}}},
    ],
)
def test_regras_malformadas_falham_fechado(regras_fingerprint):
    regras = {**RULES, "fingerprint": regras_fingerprint}
    for produto in identify_products(cabecalho(server="nginx/1.18.0"), regras):
        assert produto.support == UNKNOWN


@pytest.mark.parametrize(
    "banner",
    [
        "nginx/<script>alert(1)</script>",
        "../../etc/passwd",
        "nginx/1.0 ((((((((((((sem fim",
        "a/1 b/2 c/3 d/4 e/5 f/6 g/7 h/8 i/9 j/10 k/11",
        "\"'; DROP TABLE alvos; --",
        "(só comentário)",
        "/1.0",
    ],
)
def test_banner_hostil_nao_quebra_nem_inventa_versao(banner):
    tokens = parse_product_tokens(banner, "server")
    assert len(tokens) <= 8
    for t in tokens:
        assert t.name and all(ch not in "<>()\"' " for ch in t.name + (t.version or ""))
    assert all(p.support != SUPPORTED for p in identify_products(cabecalho(server=banner), RULES))


def test_comentario_aninhado_fecha_no_parentese_certo():
    tokens = parse_product_tokens("nginx/1.30.6 (a (b (c (d (e))))) OpenSSL/3.5.9", "server")
    assert [(t.name, t.comment) for t in tokens] == [
        ("nginx", "a (b (c (d (e))))"),
        ("OpenSSL", None),
    ]


@pytest.mark.parametrize("banner", ["nginx/1.0 " + "(" * 5000, "nginx/1.0 " + ")" * 5000])
def test_parenteses_desbalanceados_nao_quebram(banner):
    tokens = parse_product_tokens(banner, "server")
    assert tokens[0].name == "nginx" and tokens[0].version == "1.0"


# ---------- distribuição: aviso só para quem recebe correção sem mudar a versão ----------


@pytest.mark.parametrize(
    ("banner", "distro"),
    [
        ("Apache/2.2.34 (Ubuntu) OpenSSL/1.0.2", "Ubuntu"),
        ("Apache/2.2.34 (Red Hat Enterprise Linux) OpenSSL/1.0.2", "Red Hat"),
        ("Apache/2.2.34 (Debian)", "Debian"),
    ],
)
def test_aviso_de_distribuicao_quando_conhecida(banner, distro):
    for produto in identify_products(cabecalho(server=banner), RULES):
        assert f"Pacotes de distribuição ({distro})" in produto.note


@pytest.mark.parametrize("banner", ["Apache/2.2.34 (Win64) OpenSSL/1.0.2", "Apache/2.2.34 (Unix)"])
def test_sem_aviso_de_distribuicao_quando_nao_e_pacote(banner):
    for produto in identify_products(cabecalho(server=banner), RULES):
        assert "distribuição" not in (produto.note or "")


@pytest.mark.parametrize("lista", ["Ubuntu", [None, 7, ""], {"Ubuntu": 1}])
def test_lista_de_distribuicoes_malformada_nao_gera_aviso(lista):
    regras = copy.deepcopy(RULES)
    regras["fingerprint"]["distributions"] = lista
    (produto,) = identify_products(cabecalho(server="nginx/1.24.0 (Ubuntu)"), regras)
    assert produto.support == UNSUPPORTED and "distribuição" not in (produto.note or "")


def test_assinatura_com_muitas_extensoes_fica_no_formato():
    enorme = ServerHelloShape("hello_retry_request", 0x0304, 0x1302, tuple(range(500)))
    assinatura = tls_stack_signature(enorme)
    assert assinatura.startswith("h139900_1302_")


def test_nome_de_pilha_hostil_nas_regras_e_cortado():
    regras = copy.deepcopy(RULES)
    regras["fingerprint"]["tls_stacks"] = {tls_stack_signature(HELLO): "x" * 500}
    assert len(identify_tls_stack(HELLO, regras).stack) == 80
