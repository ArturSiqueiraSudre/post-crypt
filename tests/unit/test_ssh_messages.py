"""Leitura do banner e do KEXINIT do SSH: tudo em memória, entradas hostis inclusas."""

import struct

import pytest

from postcrypt.ssh.messages import (
    MAX_LINE_BYTES,
    MAX_NAME_LIST_BYTES,
    MAX_NAMES,
    MAX_PACKET_BYTES,
    MAX_PRE_BANNER_LINES,
    BannerReader,
    SSHParseError,
    build_kexinit,
    build_packet,
    client_identification,
    parse_identification,
    parse_kexinit,
    take_packet,
)

LISTAS = [
    ["mlkem768x25519-sha256", "curve25519-sha256", "ext-info-s", "kex-strict-s-v00@openssh.com"],
    ["ssh-ed25519", "rsa-sha2-512"],
    ["chacha20-poly1305@openssh.com", "aes256-ctr"],
    ["chacha20-poly1305@openssh.com", "aes256-ctr"],
    ["hmac-sha2-256-etm@openssh.com"],
    ["hmac-sha2-256-etm@openssh.com"],
    ["none"],
    ["none"],
    [],
    [],
]


# ---------- caminho feliz ----------


def test_identificacao_com_comentario():
    ident = parse_identification(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20")
    assert (ident.protocol, ident.software, ident.comments) == (
        "2.0",
        "OpenSSH_9.6p1",
        "Ubuntu-3ubuntu13.20",
    )


def test_identificacao_compativel_1_99_sem_comentario():
    ident = parse_identification(b"SSH-1.99-Cisco-1.25")
    assert (ident.protocol, ident.software, ident.comments) == ("1.99", "Cisco-1.25", None)


def test_banner_com_linhas_antes_e_resto_depois():
    reader = BannerReader()
    assert not reader.feed(b"Bem-vindo\r\nAcesso monitorado\r\nSSH-2.0-Op")
    assert reader.feed(b"enSSH_10.6\r\n\x00\x00\x01")
    assert reader.identification.software == "OpenSSH_10.6"
    assert reader.rest == b"\x00\x00\x01"


def test_kexinit_separa_marcadores_de_extensao():
    payload, resto = take_packet(build_packet(build_kexinit(LISTAS)) + b"sobra")
    kex = parse_kexinit(payload)
    assert kex.kex == ("mlkem768x25519-sha256", "curve25519-sha256")
    assert kex.kex_extensions == ("ext-info-s", "kex-strict-s-v00@openssh.com")
    assert kex.host_key == ("ssh-ed25519", "rsa-sha2-512")
    assert resto == b"sobra"


def test_identificacao_do_cliente():
    assert client_identification("0.1.0") == b"SSH-2.0-PostCrypt_0.1.0\r\n"


# ---------- limites ----------


def test_pacote_incompleto_espera_mais_bytes():
    pacote = build_packet(build_kexinit(LISTAS))
    assert take_packet(pacote[:10]) == (None, pacote[:10])
    assert take_packet(b"\x00\x00") == (None, b"\x00\x00")


def test_listas_vazias_sao_aceitas():
    kex = parse_kexinit(build_kexinit([[]] * 10))
    assert kex.kex == () and kex.host_key == ()


def test_linha_de_identificacao_no_limite():
    software = "A" * (MAX_LINE_BYTES - len("SSH-2.0-") - 50)
    assert parse_identification(f"SSH-2.0-{software}".encode()).software == software


def test_linhas_demais_antes_da_identificacao():
    reader = BannerReader()
    with pytest.raises(SSHParseError):
        reader.feed(b"x\r\n" * (MAX_PRE_BANNER_LINES + 1))


def test_numero_maximo_de_algoritmos():
    no_limite = build_kexinit([[f"a{i}" for i in range(MAX_NAMES)], *[[]] * 9])
    assert len(parse_kexinit(no_limite).kex) == MAX_NAMES
    with pytest.raises(SSHParseError, match="nomes demais"):
        parse_kexinit(build_kexinit([[f"a{i}" for i in range(MAX_NAMES + 1)], *[[]] * 9]))


@pytest.mark.parametrize("versao", ["0.1-beta", "0 1", "", "1\r\nX-Injetado: 1"])
def test_versao_impropria_para_o_banner_do_cliente(versao):
    with pytest.raises(ValueError):
        client_identification(versao)


# ---------- entradas maliciosas ----------


@pytest.mark.parametrize(
    "linha",
    [
        b"SSH-1.5-Antigo",  # SSH 1 puro: não suportado
        b"HTTP/1.1 400 Bad Request",
        b"SSH-2.0-",  # sem software
        b"SSH-2.0-Open\tSSH",  # tab no lugar do espaço
        b"SSH-2.0-OpenSSH\x1b[31m",  # sequência de terminal
        b"SSH-2.0-OpenSSH_9.6 coment\xc3\xa1rio",  # fora do ASCII
        b"SSH-2.0-" + b"A" * 300,
    ],
)
def test_identificacao_hostil_e_recusada(linha):
    with pytest.raises(SSHParseError):
        parse_identification(linha)


def test_linha_sem_fim_e_recusada():
    with pytest.raises(SSHParseError, match="sem fim"):
        BannerReader().feed(b"A" * (MAX_LINE_BYTES + 10))


@pytest.mark.parametrize(
    "cabecalho",
    [
        struct.pack("!IB", MAX_PACKET_BYTES + 1, 4),  # comprimento acima do teto
        struct.pack("!IB", 100, 2),  # preenchimento menor que 4
        struct.pack("!IB", 3, 4),  # preenchimento maior que o pacote
    ],
)
def test_pacote_fora_do_formato_e_recusado(cabecalho):
    with pytest.raises(SSHParseError, match="pacote"):
        take_packet(cabecalho + b"\x00" * 200)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x15" + b"\x00" * 16,  # NEWKEYS, não KEXINIT
        b"\x14" + b"\x00" * 10,  # cookie truncado
        b"\x14" + b"\x00" * 16 + struct.pack("!I", 50) + b"abc",  # lista truncada
        b"\x14" + b"\x00" * 16 + struct.pack("!I", 9000) + b"a" * 9000,  # lista grande demais
    ],
)
def test_kexinit_truncado_ou_errado_e_recusado(payload):
    with pytest.raises(SSHParseError):
        parse_kexinit(payload)


@pytest.mark.parametrize(
    "nome",
    ["<script>", "a,,b", "nome com espaço", "x" * 65, "ação", "\x1b[2J"],
)
def test_nome_de_algoritmo_hostil_e_recusado(nome):
    lista = nome.encode("utf-8")
    payload = b"\x14" + b"\x00" * 16 + struct.pack("!I", len(lista)) + lista
    with pytest.raises(SSHParseError):
        parse_kexinit(payload)


def test_identificacao_no_limite_de_255_bytes():
    # Software e comentário cabem no formato, mas a linha inteira passa do limite da RFC.
    prefixo = b"SSH-2.0-" + b"a" * 200 + b" "
    no_limite = prefixo + b"c" * (MAX_LINE_BYTES - len(prefixo))
    assert parse_identification(no_limite).software == "a" * 200
    with pytest.raises(SSHParseError, match="longa demais"):
        parse_identification(no_limite + b"c")


def test_lista_de_nomes_validos_mas_longa_demais():
    # 127 nomes de 64 caracteres: menos que o teto de nomes, mais que o teto de bytes.
    nomes = [f"{i:03d}" + "x" * 61 for i in range(MAX_NAMES - 1)]
    assert len(",".join(nomes)) > MAX_NAME_LIST_BYTES
    with pytest.raises(SSHParseError, match="longa demais"):
        parse_kexinit(build_kexinit([nomes, *[[]] * 9]))


@pytest.mark.parametrize(
    "nomes",
    [["a\x1bb"], ["a", "", "b"], ["x" * 65], ["com espaco"], ["\x7f"]],
    ids=["escape", "vazio", "65-caracteres", "espaco", "DEL"],
)
def test_nome_de_algoritmo_invalido(nomes):
    with pytest.raises(SSHParseError, match="nome de algoritmo inválido"):
        parse_kexinit(build_kexinit([nomes, *[[]] * 9]))
