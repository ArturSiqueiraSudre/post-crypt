"""Roteamento por protocolo no scanner: alvo SSH vai para a sonda SSH, nunca para a TLS."""

from postcrypt.classify import HNDL, PQC, UNREACHABLE, load_rules
from postcrypt.fingerprint import OBSERVED
from postcrypt.probe_errors import ProbeConnectionError
from postcrypt.scanner import run_scan, scan_target
from postcrypt.scope import Authorization, Scope, Target
from postcrypt.ssh.probe import SSHObservation

RULES = load_rules()
SSH = Target("10.0.0.9", 22, protocol="ssh", label="bastion", sni=None)


def sonda(obs=None, erro=None, chamadas=None):
    def probe(host, port, timeout):
        if chamadas is not None:
            chamadas.append((host, port, timeout))
        if erro:
            raise erro
        return obs

    return probe


def nunca_http(_pedido):
    raise AssertionError("alvo SSH não pode receber pedido HTTP")


def test_alvo_ssh_usa_a_sonda_ssh_no_mesmo_host_e_porta():
    chamadas = []
    obs = SSHObservation(
        software="OpenSSH_10.6", kex=["mlkem768x25519-sha256"], host_key=["ssh-ed25519"]
    )
    r = scan_target(SSH, RULES, 3.0, fetch=nunca_http, ssh_probe=sonda(obs, chamadas=chamadas))
    assert chamadas == [("10.0.0.9", 22, 3.0)]
    assert r.assessment.status == PQC and r.ssh is obs and r.observation is None
    assert r.fingerprint.status == OBSERVED and r.fingerprint.products[0].name == "OpenSSH"
    dados = r.to_dict()
    assert dados["tls"] is None and dados["ssh"]["software"] == "OpenSSH_10.6"


def test_alvo_ssh_sem_resposta_e_lacuna():
    r = scan_target(SSH, RULES, 3.0, ssh_probe=sonda(erro=ProbeConnectionError("recusado")))
    assert r.assessment.status == UNREACHABLE and not r.reachable and r.error == "recusado"


def test_alvo_tls_nunca_chama_a_sonda_ssh():
    def proibida(*_a):
        raise AssertionError("alvo TLS não pode usar a sonda SSH")

    tls = Target("127.0.0.1", 1, label="fechado")
    r = scan_target(tls, RULES, 0.5, ssh_probe=proibida)
    assert r.assessment.status == UNREACHABLE and r.ssh is None


def test_varredura_mista_mantem_a_ordem_do_escopo():
    classico = SSHObservation(software="OpenSSH_8.9p1", kex=["curve25519-sha256"])
    scope = Scope(Authorization("Teste", "2026-11-20"), (SSH,))
    scan = run_scan(scope, RULES, timeout=1, ssh_probe=sonda(classico))
    assert [r.assessment.status for r in scan.results] == [HNDL]
