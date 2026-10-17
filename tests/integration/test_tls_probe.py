"""Sonda TLS contra servidores reais (locais) com gabarito conhecido."""

import json
import socket
import threading

import pytest
from typer.testing import CliRunner

from postcrypt.classify import HNDL, PQC, UNREACHABLE, load_rules
from postcrypt.cli import app
from postcrypt.scanner import scan_target
from postcrypt.scope import Target
from postcrypt.tls.probe import TLSProbe
from tests.support.pki import TestPKI
from tests.support.tls_server import HAS_OPENSSL_35, TLSServer, closed_port

pytestmark = pytest.mark.integration
RULES = load_rules()


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return TestPKI(tmp_path_factory.mktemp("pki"))


@pytest.mark.skipif(not HAS_OPENSSL_35, reason="servidor híbrido exige OpenSSL 3.5+")
def test_hybrid_server_detected(pki):
    cert = pki.issue("hibrido.lab")
    with TLSServer("hybrid", cert.cert_path, cert.key_path) as srv:
        obs = TLSProbe("127.0.0.1", srv.port, sni="hibrido.lab", timeout=3).run()
    assert obs.tls13
    assert "X25519MLKEM768" in obs.pqc_groups
    assert obs.certificates[0].subject.startswith("CN=hibrido.lab")


def test_classical_server_is_hndl(pki):
    cert = pki.issue("classico.lab")
    with TLSServer("classical", cert.cert_path, cert.key_path) as srv:
        result = scan_target(Target("127.0.0.1", srv.port, sni="classico.lab"), RULES, 3)
    assert result.reachable
    assert result.observation.pqc_groups == []
    assert result.observation.classical_group == "secp256r1"
    assert result.assessment.status == HNDL


def test_legacy_rsa_key_transport_and_expired_cert(pki):
    cert = pki.issue("legado.lab", key_type="rsa", valid_from_days=-60, valid_to_days=-2)
    with TLSServer("tls12-rsa", cert.cert_path, cert.key_path) as srv:
        result = scan_target(Target("127.0.0.1", srv.port, sni="legado.lab"), RULES, 3)
    obs = result.observation
    assert not obs.tls13 and obs.tls12
    assert obs.rsa_key_transport
    assert obs.certificates[0].public_key_detail == "RSA-2048"
    ids = {f.id for f in result.assessment.findings}
    assert {"RSA_KEY_TRANSPORT", "CERT_EXPIRED", "NO_TLS13"} <= ids


def test_closed_port_is_a_gap():
    result = scan_target(Target("127.0.0.1", closed_port()), RULES, 2)
    assert not result.reachable
    assert result.assessment.status == UNREACHABLE


def test_non_tls_service_needs_review():
    with socket.create_server(("127.0.0.1", 0)) as srv:
        port = srv.getsockname()[1]
        srv.settimeout(5)

        def banner():
            for _ in range(6):
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                with conn:
                    conn.sendall(b"SSH-2.0-OpenSSH_10.0\r\n")

        t = threading.Thread(target=banner, daemon=True)
        t.start()
        result = scan_target(Target("127.0.0.1", port), RULES, 2)
    assert result.reachable
    assert "NOT_TLS" in {f.id for f in result.assessment.findings}


def test_cli_scan_writes_json(pki, tmp_path):
    cert = pki.issue("cli.lab")
    with TLSServer("classical", cert.cert_path, cert.key_path) as srv:
        scope = tmp_path / "escopo.yaml"
        scope.write_text(
            "authorization: {by: Teste, date: 2026-10-17}\n"
            f"targets:\n  - {{host: 127.0.0.1, port: {srv.port}, label: cli}}\n",
            encoding="utf-8",
        )
        out = tmp_path / "resultado.json"
        res = CliRunner().invoke(
            app, ["scan", str(scope), "--json", str(out), "--fail-on-vulnerable"]
        )
    assert res.exit_code == 1, res.output  # alvo clássico + --fail-on-vulnerable
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["authorization"]["by"] == "Teste"
    assert data["results"][0]["assessment"]["status"] == HNDL
    assert data["summary"] == {HNDL: 1}


@pytest.mark.skipif(not HAS_OPENSSL_35, reason="servidor híbrido exige OpenSSL 3.5+")
def test_scan_only_contacts_listed_targets(pki, monkeypatch):
    """CA6 em miniatura: toda conexão aberta vai para um alvo do escopo."""
    cert = pki.issue("escopo.lab")
    contacted: list[tuple] = []
    real = socket.create_connection

    def spy(address, *args, **kwargs):
        contacted.append(address)
        return real(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", spy)
    with TLSServer("hybrid", cert.cert_path, cert.key_path) as srv:
        result = scan_target(Target("127.0.0.1", srv.port, sni="escopo.lab"), RULES, 3)
    assert result.assessment.status == PQC
    assert contacted and set(contacted) == {("127.0.0.1", srv.port)}
