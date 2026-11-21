"""Sonda SSH contra um OpenSSH de verdade (sshd local) e contra servidores falsos hostis."""

import re
import socket
import threading
import time

import pytest

from postcrypt.classify import HNDL, PQC, REVIEW, UNREACHABLE, load_rules
from postcrypt.probe_errors import ProbeConnectionError
from postcrypt.scanner import scan_target
from postcrypt.scope import Target
from postcrypt.ssh.probe import SSHProbe
from tests.support.sshd_server import SSHDServer, find_sshd
from tests.support.tls_server import closed_port

pytestmark = pytest.mark.integration
RULES = load_rules()
SEM_SSHD = find_sshd() is None


def alvo(port):
    return Target("127.0.0.1", port, protocol="ssh", label="ssh", sni=None)


def versao_openssh(texto: str) -> tuple[int, int]:
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", texto)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


# ---------- OpenSSH real (critério de aceite do Estágio 3) ----------


@pytest.mark.skipif(SEM_SSHD, reason="sshd não instalado nesta máquina")
def test_openssh_padrao_aceita_troca_hibrida(tmp_path):
    with SSHDServer(tmp_path) as srv:
        if versao_openssh(srv.version()) < (9, 0):
            pytest.skip("OpenSSH anterior ao 9.0 não oferece troca híbrida")
        obs = SSHProbe("127.0.0.1", srv.port, timeout=5).run()
        result = scan_target(alvo(srv.port), RULES, timeout=5)
    assert obs.software and obs.software.startswith("OpenSSH_")
    assert any(k.startswith(("sntrup761x25519", "mlkem768x25519")) for k in obs.kex)
    assert "ssh-ed25519" in obs.host_key
    assert result.assessment.status == PQC
    assert result.fingerprint is not None and result.fingerprint.products[0].name == "OpenSSH"


@pytest.mark.skipif(SEM_SSHD, reason="sshd não instalado nesta máquina")
def test_openssh_so_classico_e_vulneravel_a_hndl(tmp_path):
    with SSHDServer(tmp_path, extra=["KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256"]) as srv:
        result = scan_target(alvo(srv.port), RULES, timeout=5)
    assert result.ssh is not None and result.ssh.kex == ["curve25519-sha256", "ecdh-sha2-nistp256"]
    assert result.assessment.status == HNDL
    assert "KX_CLASSICAL_ONLY" in {f.id for f in result.assessment.findings}


# ---------- limites e falhas ----------


def test_porta_fechada_e_lacuna_de_visibilidade():
    result = scan_target(alvo(closed_port()), RULES, timeout=2)
    assert result.assessment.status == UNREACHABLE and not result.reachable
    with pytest.raises(ProbeConnectionError):
        SSHProbe("127.0.0.1", closed_port(), timeout=2).run()


class Falso:
    """Servidor TCP que executa ``comportamento(conn)`` a cada conexão."""

    def __init__(self, comportamento):
        self.comportamento = comportamento
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.conexoes = 0
        threading.Thread(target=self._laco, daemon=True).start()

    def _laco(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conexoes += 1
            threading.Thread(target=self._atender, args=(conn,), daemon=True).start()

    def _atender(self, conn):
        try:
            self.comportamento(conn)
        except OSError:
            pass
        finally:
            conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.sock.close()


def test_servidor_tls_numa_porta_declarada_ssh_e_revisar():
    """Servidor que espera o cliente falar primeiro (como TLS): sem banner, nada inventado."""
    with Falso(lambda c: c.recv(1024)) as srv:
        inicio = time.monotonic()
        result = scan_target(alvo(srv.port), RULES, timeout=1)
    assert time.monotonic() - inicio < 3
    assert result.assessment.status == REVIEW and result.ssh is not None and not result.ssh.kex


# ---------- entradas maliciosas ----------


def test_servidor_http_na_porta_ssh_e_recusado():
    with Falso(lambda c: c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")) as srv:
        result = scan_target(alvo(srv.port), RULES, timeout=2)
    assert result.ssh is not None and result.ssh.not_ssh
    assert "NOT_SSH" in {f.id for f in result.assessment.findings}


def test_servidor_que_goteja_o_banner_para_no_prazo():
    def gotejar(conn):
        for _ in range(200):
            conn.sendall(b"x")
            time.sleep(0.2)

    with Falso(gotejar) as srv:
        inicio = time.monotonic()
        obs = SSHProbe("127.0.0.1", srv.port, timeout=1).run()
    assert time.monotonic() - inicio < 2.5
    assert not obs.kex


def test_servidor_com_kexinit_gigante_e_recusado():
    def gigante(conn):
        conn.sendall(b"SSH-2.0-Falso_1.0\r\n")
        conn.recv(256)
        conn.sendall((10_000_000).to_bytes(4, "big") + b"\x04" + b"A" * 4096)

    with Falso(gigante) as srv:
        obs = SSHProbe("127.0.0.1", srv.port, timeout=2).run()
    assert obs.software == "Falso_1.0" and not obs.kex and obs.errors
