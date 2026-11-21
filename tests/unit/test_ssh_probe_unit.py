"""Sonda SSH com conexão e relógio falsos: prazo total, ordem da conversa, falhas."""

import pytest

from postcrypt.probe_errors import ProbeConnectionError
from postcrypt.ssh.messages import build_kexinit, build_packet
from postcrypt.ssh.probe import SSHProbe, observation_from

BANNER = b"SSH-2.0-OpenSSH_10.6\r\n"
LISTAS = [
    ["mlkem768x25519-sha256", "curve25519-sha256", "kex-strict-s-v00@openssh.com"],
    ["ssh-ed25519"],
    ["aes256-gcm@openssh.com"],
    ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
    ["hmac-sha2-256"],
    ["hmac-sha2-256"],
    ["none"],
    ["none", "zlib@openssh.com"],
    [],
    [],
]
KEXINIT = build_packet(build_kexinit(LISTAS))


class Relogio:
    def __init__(self, passo):
        self.agora = 0.0
        self.passo = passo

    def __call__(self):
        self.agora += self.passo
        return self.agora


class Conexao:
    def __init__(self, partes, *, erro=None):
        self.partes = list(partes)
        self.erro = erro
        self.enviado = b""
        self.timeouts = []
        self.leituras = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, valor):
        self.timeouts.append(valor)

    def sendall(self, dados):
        self.enviado += dados

    def recv(self, _n):
        self.leituras += 1
        if self.partes:
            return self.partes.pop(0)
        if self.erro:
            raise self.erro
        return b""


def sonda(conexao, relogio=None, timeout=5.0):
    return SSHProbe(
        "127.0.0.1",
        22,
        timeout=timeout,
        clock=relogio or Relogio(0.01),
        connect=lambda _endereco, _t: conexao,
    )


# ---------- caminho feliz ----------


def test_le_banner_manda_o_proprio_e_le_o_kexinit():
    conexao = Conexao([BANNER, KEXINIT])
    obs = sonda(conexao).run()
    assert conexao.enviado.startswith(b"SSH-2.0-PostCrypt_")
    assert obs.software == "OpenSSH_10.6"
    assert obs.kex == ["mlkem768x25519-sha256", "curve25519-sha256"]
    assert obs.ciphers == ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]
    assert obs.compression == ["none", "zlib@openssh.com"]
    assert obs.strict_kex and not obs.not_ssh and not obs.errors


def test_banner_e_kexinit_no_mesmo_pedaco():
    obs = sonda(Conexao([BANNER + KEXINIT])).run()
    assert obs.kex[0] == "mlkem768x25519-sha256"


def test_pacotes_ignore_antes_do_kexinit_sao_pulados():
    ignore = build_packet(b"\x02" + b"\x00" * 4)
    obs = sonda(Conexao([BANNER, ignore + ignore, KEXINIT])).run()
    assert obs.kex


def test_observacao_sem_kexinit_guarda_so_o_banner():
    from postcrypt.ssh.messages import parse_identification

    obs = observation_from(parse_identification(b"SSH-2.0-dropbear_2022.83"), None)
    assert obs.software == "dropbear_2022.83" and obs.kex == []


# ---------- limites e falhas ----------


def test_conexao_recusada():
    def recusa(_endereco, _t):
        raise ConnectionRefusedError("recusado")

    with pytest.raises(ProbeConnectionError):
        SSHProbe("127.0.0.1", 22, timeout=1, connect=recusa).run()


@pytest.mark.parametrize("timeout", [0, -1])
def test_timeout_invalido(timeout):
    with pytest.raises(ValueError):
        SSHProbe("127.0.0.1", 22, timeout=timeout)


def test_fecha_antes_do_banner():
    obs = sonda(Conexao([])).run()
    assert obs.not_ssh and obs.errors


def test_fecha_depois_do_banner():
    obs = sonda(Conexao([BANNER])).run()
    assert obs.software == "OpenSSH_10.6" and obs.kex == [] and obs.errors


def test_silencio_ate_o_timeout():
    obs = sonda(Conexao([], erro=TimeoutError("lento"))).run()
    assert not obs.not_ssh and obs.software is None
    assert obs.errors == ["o serviço não mandou a identificação SSH a tempo"]


def test_conexao_derrubada_antes_do_banner_nao_vira_timeout():
    obs = sonda(Conexao([], erro=ConnectionResetError("reset"))).run()
    assert not obs.not_ssh and obs.software is None
    assert obs.errors == ["o serviço não mandou a identificação SSH antes de a conexão cair"]


@pytest.mark.parametrize(
    ("erro", "motivo"),
    [
        (TimeoutError("lento"), "a tempo"),
        (ConnectionResetError("reset"), "antes de a conexão cair"),
    ],
)
def test_falha_depois_do_banner_diz_o_motivo(erro, motivo):
    obs = sonda(Conexao([BANNER], erro=erro)).run()
    assert obs.software == "OpenSSH_10.6" and obs.kex == []
    assert obs.errors == [f"o servidor não mandou a lista de algoritmos {motivo}"]


def test_cada_leitura_so_recebe_o_que_resta_do_prazo():
    conexao = Conexao([BANNER[:5], BANNER[5:], KEXINIT[:20], KEXINIT[20:]])
    sonda(conexao, Relogio(0.1), timeout=3.0).run()
    leituras = conexao.timeouts
    assert len(leituras) >= conexao.leituras
    assert leituras == sorted(leituras, reverse=True) and all(0 < t <= 3.0 for t in leituras)


# ---------- entradas maliciosas ----------


def test_servidor_que_goteja_para_no_prazo_total():
    conexao = Conexao([b"x"] * 1000)
    obs = sonda(conexao, Relogio(1.0), timeout=3.0).run()
    assert conexao.leituras <= 3 and not obs.kex


def test_servidor_que_manda_outra_coisa_no_lugar_do_kexinit():
    nao_kexinit = build_packet(b"\x15")  # NEWKEYS antes de KEXINIT
    obs = sonda(Conexao([BANNER, nao_kexinit])).run()
    assert obs.software == "OpenSSH_10.6" and not obs.kex
    assert "lista de algoritmos" in obs.errors[0]


def test_limite_de_pacotes_ignore_antes_do_kexinit():
    from postcrypt.ssh.probe import MAX_SKIPPED_PACKETS

    ignore = build_packet(b"\x02")
    no_limite = sonda(Conexao([BANNER, ignore * MAX_SKIPPED_PACKETS + KEXINIT])).run()
    assert no_limite.kex and not no_limite.errors
    passou = sonda(Conexao([BANNER, ignore * (MAX_SKIPPED_PACKETS + 1) + KEXINIT])).run()
    assert not passou.kex and passou.errors


def test_ignore_infinito_nao_prende_a_sonda():
    ignore = build_packet(b"\x02")
    obs = sonda(Conexao([BANNER, ignore * 50])).run()
    assert not obs.kex and obs.errors


def test_banner_hostil_vira_nao_ssh_sem_ecoar_o_texto():
    obs = sonda(Conexao([b"\x1b[2J<script>alert(1)</script>\r\n" * 30])).run()
    assert obs.not_ssh
    assert all("<script>" not in e and "\x1b" not in e for e in obs.errors)
