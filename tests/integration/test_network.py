"""Correlação de rede contra servidores TLS de verdade (locais).

É o caso reproduzível do Estágio 1: dois servidores com certificados emitidos
pela mesma CA clássica precisam aparecer juntos, no JSON e no terminal.
"""

import json
import time

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from postcrypt.classify import load_rules
from postcrypt.cli import app
from postcrypt.network import analyze_network
from postcrypt.painel import create_app
from postcrypt.painel.laboratorio import Laboratorio
from postcrypt.scanner import run_scan
from postcrypt.scope import parse_scope
from tests.support.pki import TestPKI
from tests.support.tls_server import TLSServer, closed_port

pytestmark = pytest.mark.integration
RULES = load_rules()
AUTH = {"by": "Teste", "date": "2026-11-14"}
TOKEN = "token-de-teste"  # noqa: S105


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return TestPKI(tmp_path_factory.mktemp("pki-rede"))


def _alvo(porta, nome):
    return {"host": "127.0.0.1", "port": porta, "label": nome, "sni": f"{nome}.lab"}


def test_cli_mostra_ca_compartilhada_no_json_e_no_terminal(pki, tmp_path):
    a, b = pki.issue("a.lab"), pki.issue("b.lab")
    fechada = closed_port()
    with (
        TLSServer("classical", a.cert_path, a.key_path) as sa,
        TLSServer("classical", b.cert_path, b.key_path) as sb,
    ):
        escopo = tmp_path / "escopo.yaml"
        escopo.write_text(
            json.dumps(
                {
                    "authorization": AUTH,
                    "targets": [_alvo(sa.port, "a"), _alvo(sb.port, "b"), _alvo(fechada, "c")],
                }
            ),
            encoding="utf-8",
        )
        saida = tmp_path / "resultado.json"
        res = CliRunner().invoke(app, ["scan", str(escopo), "--json", str(saida), "--timeout", "3"])
    assert res.exit_code == 0, res.output
    assert "Rede" in res.output and "autoridade certificadora" in res.output

    rede = json.loads(saida.read_text(encoding="utf-8"))["network"]
    assert rede["total_targets"] == 3
    por_id = {f["id"]: f for f in rede["findings"]}
    ca = por_id["NET_SHARED_CLASSICAL_CA"]
    assert set(ca["assets"]) == {f"127.0.0.1:{sa.port}", f"127.0.0.1:{sb.port}"}
    assert ca["blast_radius"] == 2 and ca["priority"] == 6
    assert ca["evidence"]["ca_observed"] is True and ca["evidence"]["ca_key"] == "EC secp384r1"
    assert set(por_id["NET_HNDL_EXPOSURE"]["assets"]) == set(ca["assets"])
    assert por_id["NET_VISIBILITY_GAP"]["assets"] == [f"127.0.0.1:{fechada}"]
    assert "NET_DUPLICATE_LEAF" not in por_id


def test_mesmo_certificado_em_dois_servidores(pki):
    cert = pki.issue("repetido.lab")
    with (
        TLSServer("classical", cert.cert_path, cert.key_path) as s1,
        TLSServer("classical", cert.cert_path, cert.key_path) as s2,
    ):
        alvos = [_alvo(s1.port, "repetido"), {**_alvo(s2.port, "repetido"), "label": "copia"}]
        scope = parse_scope({"authorization": AUTH, "targets": alvos})
        scan = run_scan(scope, RULES, timeout=3)
    f = {x.id: x for x in analyze_network(scan, RULES).findings}["NET_DUPLICATE_LEAF"]
    assert set(f.assets) == {f"127.0.0.1:{s1.port}", f"127.0.0.1:{s2.port}"}


def test_um_alvo_so_nao_produz_secao_de_rede(pki, tmp_path):
    cert = pki.issue("sozinho.lab")
    with TLSServer("classical", cert.cert_path, cert.key_path) as srv:
        escopo = tmp_path / "escopo.yaml"
        escopo.write_text(
            json.dumps({"authorization": AUTH, "targets": [_alvo(srv.port, "sozinho")]}),
            encoding="utf-8",
        )
        res = CliRunner().invoke(app, ["scan", str(escopo), "--json", "-"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["network"] == {"total_targets": 1, "findings": []}


def test_painel_devolve_os_achados_de_rede_que_a_pagina_mostra(pki):
    a, b = pki.issue("pa.lab"), pki.issue("pb.lab")
    painel = create_app(token=TOKEN, laboratorio=Laboratorio(None))
    with (
        TLSServer("classical", a.cert_path, a.key_path) as sa,
        TLSServer("classical", b.cert_path, b.key_path) as sb,
        TestClient(painel, base_url="http://127.0.0.1:8765") as client,
    ):
        client.headers["X-Post-Crypt-Token"] = TOKEN
        pedido = {
            "escopo": {
                "authorization": {**AUTH, "reference": ""},
                "targets": [_alvo(sa.port, "pa"), _alvo(sb.port, "pb")],
            },
            "timeout": 3,
        }
        vid = client.post("/api/varreduras", json=pedido).json()["id"]
        for _ in range(200):
            estado = client.get(f"/api/varreduras/{vid}").json()
            if estado["estado"] != "rodando":
                break
            time.sleep(0.1)
        assert estado["estado"] == "concluida", estado
    resultado = estado["resultado"]
    chaves = {f"{r['target']['host']}:{r['target']['port']}" for r in resultado["results"]}
    achado = next(
        f for f in resultado["network"]["findings"] if f["id"] == "NET_SHARED_CLASSICAL_CA"
    )
    assert set(achado["assets"]) == chaves
    assert achado["action"] and achado["priority"] == 6
