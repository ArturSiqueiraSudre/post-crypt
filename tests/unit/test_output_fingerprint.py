"""Coluna Software no terminal: o que o servidor declarou, sem marcação nem controle."""

import io

from rich.console import Console

from postcrypt.classify import PQC, Assessment, load_rules
from postcrypt.fingerprint import (
    HTTPEvidence,
    ProductVersion,
    ServiceFingerprint,
    fingerprint_target,
)
from postcrypt.http_banner.parse import HTTPResponseHead
from postcrypt.output import _software_cell, render_table
from postcrypt.scanner import ScanResult, TargetResult
from postcrypt.scope import Authorization, Scope, Target
from postcrypt.tls.probe import TLSObservation

RULES = load_rules()
UNKNOWN = {"status": "unknown", "detail": "Não observado."}


def resultado(fp=None):
    target = Target("10.0.0.1", 443, label="app")
    assessment = Assessment(PQC, "Híbrido PQC", UNKNOWN, UNKNOWN, UNKNOWN, [])
    return TargetResult(target, True, 1, TLSObservation(tls13=True), assessment, fingerprint=fp)


def observado(server):
    return fingerprint_target(
        authorized=True,
        tls_reachable=True,
        server_hello=None,
        head=HTTPResponseHead(200, {"server": server}),
        http_error=None,
        rules=RULES,
    )


def test_celula_marca_o_que_esta_sem_suporte():
    cell = _software_cell(resultado(observado("Apache/2.4.58 OpenSSL/3.0.13")))
    assert cell.splitlines() == ["Apache httpd 2.4.58", "OpenSSL 3.0.13 (sem suporte)"]


def test_celula_sem_fingerprint_ou_sem_autorizacao():
    assert _software_cell(resultado()) == "—"
    nao_autorizado = fingerprint_target(
        authorized=False,
        tls_reachable=True,
        server_hello=None,
        head=None,
        http_error=None,
        rules=RULES,
    )
    assert _software_cell(resultado(nao_autorizado)) == "não autorizado"


def test_versao_hostil_nao_vira_marcacao_no_terminal():
    """O núcleo já barra esses caracteres; a saída protege de novo (defesa em profundidade)."""
    hostil = ProductVersion(None, "[red]x[/red]\x1b[2J", "1.0", "server", "unknown")
    fp = ServiceFingerprint("observed", "", HTTPEvidence(True), (hostil,))
    scope = Scope(Authorization("Teste", "2026-11-20"), (Target("10.0.0.1", 443),))
    scan = ScanResult(
        "id", "2026-11-20T00:00:00+00:00", "2026-11-20T00:00:01+00:00", scope, [resultado(fp)]
    )
    console = Console(file=io.StringIO(), width=220)
    render_table(scan, console)
    saida = console.file.getvalue()
    assert "[red]x[/red]" in saida  # aparece como texto literal, não como cor
    assert "\x1b" not in saida


def test_alvo_ssh_mostra_tipos_de_chave_no_lugar_do_certificado():
    from postcrypt.output import _cert_cell
    from postcrypt.ssh.probe import SSHObservation

    r = resultado()
    r.observation = None
    r.ssh = SSHObservation(host_key=["ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp256"])
    assert _cert_cell(r) == ("ssh-ed25519, rsa-sha2-512 …", "—")
    r.ssh = SSHObservation()
    assert _cert_cell(r) == ("—", "—")
