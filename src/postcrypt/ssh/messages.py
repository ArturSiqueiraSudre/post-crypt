"""Leitura do que um servidor SSH anuncia antes de qualquer criptografia (RFC 4253).

Ao conectar, o servidor manda a linha de identificação (``SSH-2.0-<software>
<comentários>``) e, depois da linha do cliente, a mensagem KEXINIT com as
listas de algoritmos que aceita, tudo em claro. É só isso que a sonda lê.

Tudo aqui é hostil: o servidor pode mandar qualquer byte. Cada etapa tem teto
de tamanho e lista de caracteres permitidos, e o que sai do formato vira
``SSHParseError`` (nunca é "consertado").
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

MAX_LINE_BYTES = 255  # RFC 4253, 4.2: a identificação tem no máximo 255 caracteres
MAX_PRE_BANNER_LINES = 20  # linhas que o servidor pode mandar antes da identificação
MAX_PACKET_BYTES = 35000  # RFC 4253, 6.1: todo programa precisa aceitar até 35000
MAX_NAME_LIST_BYTES = 8192
MAX_NAMES = 128
MAX_NAME_CHARS = 64  # RFC 4251, 6: nomes de algoritmo têm no máximo 64 caracteres

MSG_KEXINIT = 20
MSG_IGNORE = 2
MSG_DEBUG = 4

# A RFC 4253 proíbe hífen no software, mas servidores reais o usam ("SSH-1.99-Cisco-1.25"):
# aceitar o hífen não abre nada, porque o resto continua restrito a ASCII visível.
_PROTO = re.compile(rb"SSH-(2\.0|1\.99)-([\x21-\x7e]{1,200})(?: ([\x20-\x7e]{0,200}))?")
_CLIENT_VERSION = re.compile(r"[0-9A-Za-z._+]{1,32}")
_NAME = re.compile(r"[\x21-\x2b\x2d-\x7e]{1,64}")  # ASCII visível sem vírgula

# Pseudo-algoritmos que só sinalizam extensões, não são troca de chave de verdade.
_KEX_MARKERS = ("ext-info-", "kex-strict-")


class SSHParseError(ValueError):
    """O que o servidor mandou não é o protocolo SSH no formato esperado."""


@dataclass(frozen=True)
class Identification:
    protocol: str  # "2.0" (ou "1.99", compatível com 2.0)
    software: str  # ex.: "OpenSSH_9.6p1"
    comments: str | None  # ex.: "Ubuntu-3ubuntu13.20"


@dataclass(frozen=True)
class KexInit:
    """Listas de algoritmos do servidor, na ordem de preferência dele."""

    kex: tuple[str, ...]
    host_key: tuple[str, ...]
    ciphers_c2s: tuple[str, ...]
    ciphers_s2c: tuple[str, ...]
    macs_c2s: tuple[str, ...]
    macs_s2c: tuple[str, ...]
    compression_c2s: tuple[str, ...]
    compression_s2c: tuple[str, ...]
    kex_extensions: tuple[str, ...] = field(default=())  # ext-info-s, kex-strict-s-v00@...


def client_identification(version: str) -> bytes:
    """Linha de identificação do Post-Crypt, sem espaço nem hífen no nome do software."""
    if _CLIENT_VERSION.fullmatch(version) is None:
        raise ValueError("versão imprópria para a identificação SSH")
    return f"SSH-2.0-PostCrypt_{version}\r\n".encode("ascii")


def parse_identification(line: bytes) -> Identification:
    """Linha ``SSH-protoversion-softwareversion SP comentários`` (sem o CRLF)."""
    if len(line) > MAX_LINE_BYTES:
        raise SSHParseError("linha de identificação SSH longa demais")
    match = _PROTO.fullmatch(line)
    if match is None:
        raise SSHParseError("a resposta não é uma identificação SSH 2.0")
    comments = match.group(3)
    return Identification(
        protocol=match.group(1).decode("ascii"),
        software=match.group(2).decode("ascii"),
        comments=(comments.decode("ascii").strip() or None) if comments else None,
    )


class BannerReader:
    """Junta bytes até a linha de identificação e devolve o que sobrou depois dela."""

    def __init__(self) -> None:
        self._buffer = b""
        self._lines = 0
        self.identification: Identification | None = None
        self.rest = b""

    def feed(self, data: bytes) -> bool:
        """Devolve True quando a identificação chegou inteira."""
        self._buffer += data
        while self.identification is None:
            end = self._buffer.find(b"\n")
            if end < 0:
                if len(self._buffer) > MAX_LINE_BYTES + 2:
                    raise SSHParseError("linha sem fim antes da identificação SSH")
                return False
            line = self._buffer[:end].rstrip(b"\r")
            self._buffer = self._buffer[end + 1 :]
            if line.startswith(b"SSH-"):
                self.identification = parse_identification(line)
                self.rest, self._buffer = self._buffer, b""
                return True
            # RFC 4253, 4.2: o servidor pode mandar outras linhas antes; com limite.
            self._lines += 1
            if self._lines > MAX_PRE_BANNER_LINES or len(line) > MAX_LINE_BYTES:
                raise SSHParseError("a resposta não é uma identificação SSH")
        return True


def take_packet(buffer: bytes) -> tuple[bytes | None, bytes]:
    """Retira um pacote binário (sem MAC: antes de NEWKEYS não há) e devolve o payload."""
    if len(buffer) < 5:
        return None, buffer
    packet_length, padding = struct.unpack_from("!IB", buffer, 0)
    if packet_length > MAX_PACKET_BYTES or packet_length < padding + 1 or padding < 4:
        raise SSHParseError("pacote SSH fora do formato")
    if len(buffer) < 4 + packet_length:
        return None, buffer
    payload = buffer[5 : 4 + packet_length - padding]
    return payload, buffer[4 + packet_length :]


def _name_list(payload: bytes, pos: int) -> tuple[tuple[str, ...], int]:
    if pos + 4 > len(payload):
        raise SSHParseError("KEXINIT truncado")
    (length,) = struct.unpack_from("!I", payload, pos)
    pos += 4
    if length > MAX_NAME_LIST_BYTES or pos + length > len(payload):
        raise SSHParseError("lista de algoritmos longa demais ou truncada")
    raw = payload[pos : pos + length]
    pos += length
    if not raw:
        return (), pos
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SSHParseError("lista de algoritmos fora do ASCII") from exc
    names = text.split(",")
    if len(names) > MAX_NAMES:
        raise SSHParseError("lista de algoritmos com nomes demais")
    if any(_NAME.fullmatch(n) is None for n in names):
        raise SSHParseError("nome de algoritmo inválido")
    return tuple(names), pos


def parse_kexinit(payload: bytes) -> KexInit:
    """Interpreta o payload de SSH_MSG_KEXINIT (RFC 4253, 7.1)."""
    if not payload or payload[0] != MSG_KEXINIT:
        raise SSHParseError("a mensagem não é KEXINIT")
    pos = 1 + 16  # tipo + cookie
    if len(payload) < pos:
        raise SSHParseError("KEXINIT truncado")
    lists: list[tuple[str, ...]] = []
    for _ in range(10):
        names, pos = _name_list(payload, pos)
        lists.append(names)
    kex_all = lists[0]
    real = tuple(n for n in kex_all if not n.startswith(_KEX_MARKERS))
    markers = tuple(n for n in kex_all if n.startswith(_KEX_MARKERS))
    return KexInit(
        kex=real,
        host_key=lists[1],
        ciphers_c2s=lists[2],
        ciphers_s2c=lists[3],
        macs_c2s=lists[4],
        macs_s2c=lists[5],
        compression_c2s=lists[6],
        compression_s2c=lists[7],
        kex_extensions=markers,
    )


def build_packet(payload: bytes, block: int = 8) -> bytes:
    """Monta um pacote sem cifra (usado pelos servidores de teste e de laboratório)."""
    padding = block - ((5 + len(payload)) % block)
    if padding < 4:
        padding += block
    length = 1 + len(payload) + padding
    return struct.pack("!IB", length, padding) + payload + b"\x00" * padding


def build_kexinit(lists: list[list[str]], cookie: bytes = b"\x00" * 16) -> bytes:
    """Payload de KEXINIT com as 10 listas dadas (usado em testes e no laboratório)."""
    if len(lists) != 10 or len(cookie) != 16:
        raise ValueError("KEXINIT precisa de 10 listas e cookie de 16 bytes")
    body = bytes([MSG_KEXINIT]) + cookie
    for names in lists:
        text = ",".join(names).encode("ascii")
        body += struct.pack("!I", len(text)) + text
    return body + b"\x00" + struct.pack("!I", 0)
