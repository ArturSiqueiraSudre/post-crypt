"""Painel web local: API, regras de escopo e proteções da página."""

import re
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from postcrypt.classify import HNDL, UNREACHABLE
from postcrypt.painel import create_app
from postcrypt.painel.app import ESTATICOS
from postcrypt.painel.laboratorio import Laboratorio
from postcrypt.scope import parse_scope
from tests.support.pki import TestPKI
from tests.support.tls_server import TLSServer, closed_port

pytestmark = pytest.mark.integration
TOKEN = "token-de-teste"  # noqa: S105
RAIZ = Path(__file__).resolve().parents[2]


@pytest.fixture
def client():
    app = create_app(token=TOKEN, laboratorio=Laboratorio(None))
    with TestClient(app, base_url="http://127.0.0.1:8765") as c:
        c.headers["X-Post-Crypt-Token"] = TOKEN
        yield c


def escopo(*alvos, by="Ana Lima (TI)", date="2026-11-10"):
    return {"authorization": {"by": by, "date": date, "reference": ""}, "targets": list(alvos)}


def esperar(client, vid, limite_s=20):
    fim = time.monotonic() + limite_s
    while time.monotonic() < fim:
        estado = client.get(f"/api/varreduras/{vid}").json()
        if estado["estado"] != "rodando":
            return estado
        time.sleep(0.1)
    raise AssertionError("a varredura não terminou")


# ---------- funcionamento ----------


def test_pagina_entrega_token_e_cabecalhos_de_seguranca(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert f'content="{TOKEN}"' in resp.text
    csp = resp.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_info_sem_laboratorio(client):
    info = client.get("/api/info").json()
    assert info["laboratorio"]["disponivel"] is False
    assert client.post("/api/laboratorio/ligar", json={}).status_code == 404


def test_formulario_normaliza_campos_vazios_e_porta_em_texto(client):
    alvo = {"host": " vpn.exemplo.com.br ", "port": "443", "label": "", "sni": "", "owner": "self"}
    resp = client.post("/api/escopo/validar", json=escopo(alvo))
    assert resp.status_code == 200, resp.text
    t = resp.json()["targets"][0]
    assert (t["host"], t["port"], t["label"], t["sni"]) == (
        "vpn.exemplo.com.br",
        443,
        None,
        "vpn.exemplo.com.br",
    )


def test_importar_e_salvar_escopo_ida_e_volta(client):
    texto = (RAIZ / "examples" / "escopo-exemplo.yaml").read_text(encoding="utf-8")
    importado = client.post("/api/escopo/importar", json={"texto": texto}).json()
    assert len(importado["targets"]) == 2
    salvo = client.post("/api/escopo/yaml", json=importado).json()["texto"]
    assert parse_scope(yaml.safe_load(salvo)) == parse_scope(yaml.safe_load(texto))


def test_importar_yaml_quebrado(client):
    resp = client.post("/api/escopo/importar", json={"texto": "targets: [\n"})
    assert resp.status_code == 422
    assert "YAML" in resp.json()["erro"]


def test_varredura_pelo_painel_classifica_os_alvos(client, tmp_path):
    cert = TestPKI(tmp_path).issue("painel.lab")
    fechada = closed_port()
    with TLSServer("classical", cert.cert_path, cert.key_path) as srv:
        pedido = {
            "escopo": escopo(
                {"host": "127.0.0.1", "port": srv.port, "label": "clássico", "sni": "painel.lab"},
                {"host": "127.0.0.1", "port": fechada, "label": "fora do ar"},
            ),
            "timeout": 2,
        }
        inicio = client.post("/api/varreduras", json=pedido)
        assert inicio.status_code == 202, inicio.text
        estado = esperar(client, inicio.json()["id"])
    assert estado["estado"] == "concluida"
    assert estado["feitos"] == estado["total"] == 2
    resultado = estado["resultado"]
    assert resultado["authorization"]["by"] == "Ana Lima (TI)"
    assert [r["assessment"]["status"] for r in resultado["results"]] == [HNDL, UNREACHABLE]


# ---------- segurança ----------


def test_api_recusa_pedido_sem_token(client):
    resp = client.get("/api/info", headers={"X-Post-Crypt-Token": "outro"})
    assert resp.status_code == 403


def test_api_recusa_host_estranho_dns_rebinding(client):
    resp = client.get("/api/info", headers={"Host": "atacante.example:8765"})
    assert resp.status_code == 400


@pytest.mark.parametrize(
    ("alvo", "trecho"),
    [
        ({"host": "10.0.0.0/24", "port": 443}, "faixa ou curinga"),
        ({"host": "*.exemplo.com", "port": 443}, "faixa ou curinga"),
        ({"host": "exemplo.com", "port": 70000}, "porta inválida"),
        ({"host": "exemplo.com", "port": 443, "extra": "x"}, "campos desconhecidos"),
    ],
)
def test_varredura_com_escopo_invalido_nao_comeca(client, alvo, trecho):
    resp = client.post("/api/varreduras", json={"escopo": escopo(alvo)})
    assert resp.status_code == 422
    assert trecho in resp.json()["erro"]


def test_varredura_sem_autorizacao_nao_comeca(client):
    resp = client.post(
        "/api/varreduras", json={"escopo": escopo({"host": "exemplo.com", "port": 443}, by="")}
    )
    assert resp.status_code == 422
    assert "authorization" in resp.json()["erro"]


def test_pagina_nunca_monta_html_com_dados_da_varredura():
    """Nomes de certificado vêm do servidor varrido; só podem entrar como texto."""
    js = (ESTATICOS / "painel.js").read_text(encoding="utf-8")
    codigo = re.sub(r"//.*", "", js)  # o comentário do topo cita innerHTML de propósito
    for proibido in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert proibido not in codigo, proibido


def test_laboratorio_do_repositorio_e_encontrado():
    from postcrypt.painel.laboratorio import encontrar_raiz

    assert encontrar_raiz(RAIZ / "tests") == RAIZ
