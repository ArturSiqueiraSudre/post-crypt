"""Montagem de ClientHello e leitura da resposta do servidor.

A sonda não completa o handshake: ela só precisa saber o que o servidor
escolhe. Para TLS 1.3, o ClientHello oferece grupos em ``supported_groups``
mas manda ``key_share`` vazio. Um servidor que aceita algum dos grupos responde
com HelloRetryRequest indicando qual (RFC 8446, 4.1.4); um que não aceita
responde com alerta. Assim dá para testar ML-KEM sem gerar chave pós-quântica.
"""

from __future__ import annotations

import ipaddress
import os
import struct
from dataclasses import dataclass, field

from postcrypt.tls.constants import HRR_RANDOM, SIGNATURE_SCHEMES

# Tipos de registro e de mensagem de handshake
REC_ALERT = 0x15
REC_HANDSHAKE = 0x16
HS_SERVER_HELLO = 0x02
HS_CERTIFICATE = 0x0B
HS_SERVER_HELLO_DONE = 0x0E

# Extensões
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
EXT_KEY_SHARE = 0x0033
EXT_RENEGOTIATION_INFO = 0xFF01


class TLSParseError(ValueError):
    """Resposta do servidor fora do formato esperado."""


def _u8(n: int) -> bytes:
    return struct.pack("!B", n)


def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def _vec8(data: bytes) -> bytes:
    return _u8(len(data)) + data


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _ext(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _vec16(body)


def _is_dns_name(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def build_client_hello(
    *,
    cipher_suites: list[int] | tuple[int, ...],
    groups: list[int] | tuple[int, ...],
    sni: str | None = None,
    tls13: bool = True,
) -> bytes:
    """Monta um registro TLS contendo um ClientHello.

    Com ``tls13=True`` o hello oferece só TLS 1.3 (``supported_versions``) e
    ``key_share`` vazio. Com ``tls13=False`` é um hello TLS 1.2 clássico.
    """
    if not cipher_suites:
        raise ValueError("ao menos uma suíte de cifra é necessária")

    extensions = b""
    if sni and _is_dns_name(sni):
        name = sni.encode("idna")
        server_name = _u8(0) + _vec16(name)  # host_name
        extensions += _ext(EXT_SERVER_NAME, _vec16(server_name))
    if groups:
        extensions += _ext(EXT_SUPPORTED_GROUPS, _vec16(b"".join(_u16(g) for g in groups)))
    extensions += _ext(EXT_EC_POINT_FORMATS, _vec8(b"\x00"))
    extensions += _ext(
        EXT_SIGNATURE_ALGORITHMS, _vec16(b"".join(_u16(s) for s in SIGNATURE_SCHEMES))
    )
    if tls13:
        extensions += _ext(EXT_SUPPORTED_VERSIONS, _vec8(_u16(0x0304)))
        extensions += _ext(EXT_PSK_KEY_EXCHANGE_MODES, _vec8(b"\x01"))
        extensions += _ext(EXT_KEY_SHARE, _vec16(b""))  # vazio de propósito
    else:
        extensions += _ext(EXT_EXTENDED_MASTER_SECRET, b"")
        extensions += _ext(EXT_RENEGOTIATION_INFO, _vec8(b""))

    body = (
        _u16(0x0303)  # legacy_version
        + os.urandom(32)
        + _vec8(os.urandom(32))  # legacy_session_id (modo de compatibilidade)
        + _vec16(b"".join(_u16(c) for c in cipher_suites))
        + _vec8(b"\x00")  # sem compressão
        + _vec16(extensions)
    )
    handshake = _u8(0x01) + _u24(len(body)) + body
    return _u8(REC_HANDSHAKE) + _u16(0x0301) + _vec16(handshake)


@dataclass
class ServerResponse:
    """O que a sonda extraiu da primeira resposta do servidor."""

    kind: str  # "server_hello", "hello_retry_request" ou "alert"
    version: int | None = None  # versão efetivamente escolhida
    cipher_suite: int | None = None
    selected_group: int | None = None  # grupo do HRR ou do key_share
    alert: int | None = None
    certificates: list[bytes] = field(default_factory=list)  # só em TLS 1.2


def _parse_extensions(data: bytes) -> dict[int, bytes]:
    exts: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(data):
        ext_type, length = struct.unpack_from("!HH", data, pos)
        pos += 4
        if pos + length > len(data):
            raise TLSParseError("extensão truncada")
        exts[ext_type] = data[pos : pos + length]
        pos += length
    return exts


def parse_server_hello(body: bytes) -> ServerResponse:
    """Interpreta o corpo de uma mensagem ServerHello (sem cabeçalho de 4 bytes)."""
    if len(body) < 38:
        raise TLSParseError("ServerHello curto demais")
    legacy_version = struct.unpack_from("!H", body, 0)[0]
    random = body[2:34]
    sid_len = body[34]
    pos = 35 + sid_len
    if pos + 3 > len(body):
        raise TLSParseError("ServerHello truncado")
    cipher_suite = struct.unpack_from("!H", body, pos)[0]
    pos += 3  # suíte + compressão
    exts: dict[int, bytes] = {}
    if pos + 2 <= len(body):
        ext_len = struct.unpack_from("!H", body, pos)[0]
        exts = _parse_extensions(body[pos + 2 : pos + 2 + ext_len])

    is_hrr = random == HRR_RANDOM
    version = legacy_version
    if EXT_SUPPORTED_VERSIONS in exts and len(exts[EXT_SUPPORTED_VERSIONS]) >= 2:
        version = struct.unpack_from("!H", exts[EXT_SUPPORTED_VERSIONS], 0)[0]

    selected_group = None
    key_share = exts.get(EXT_KEY_SHARE)
    if key_share is not None and len(key_share) >= 2:
        # No HRR o key_share traz só o grupo; no ServerHello, grupo + chave.
        selected_group = struct.unpack_from("!H", key_share, 0)[0]

    return ServerResponse(
        kind="hello_retry_request" if is_hrr else "server_hello",
        version=version,
        cipher_suite=cipher_suite,
        selected_group=selected_group,
    )


def parse_certificate_tls12(body: bytes) -> list[bytes]:
    """Lista de certificados DER de uma mensagem Certificate do TLS 1.2."""
    if len(body) < 3:
        raise TLSParseError("Certificate curto demais")
    total = int.from_bytes(body[0:3], "big")
    pos, end = 3, min(3 + total, len(body))
    certs: list[bytes] = []
    while pos + 3 <= end:
        length = int.from_bytes(body[pos : pos + 3], "big")
        pos += 3
        certs.append(body[pos : pos + length])
        pos += length
    return certs


class HandshakeReader:
    """Junta registros TLS e entrega mensagens de handshake inteiras."""

    def __init__(self) -> None:
        self._records = b""
        self._handshake = b""
        self.alert: int | None = None

    def feed(self, data: bytes) -> None:
        self._records += data
        while len(self._records) >= 5:
            rec_type, version, length = struct.unpack_from("!BHH", self._records, 0)
            # Valida o cabeçalho antes de esperar o corpo: um banner SSH ou HTTP
            # seria lido como um registro enorme e a sonda ficaria esperando.
            if rec_type not in (0x14, 0x15, 0x16, 0x17) or version >> 8 != 0x03:
                raise TLSParseError("a resposta não é um registro TLS")
            if len(self._records) < 5 + length:
                return
            payload = self._records[5 : 5 + length]
            self._records = self._records[5 + length :]
            if rec_type == REC_ALERT and len(payload) >= 2:
                self.alert = payload[1]
            elif rec_type == REC_HANDSHAKE:
                self._handshake += payload
            elif rec_type not in (0x14, 0x17):  # change_cipher_spec, application_data
                raise TLSParseError(f"tipo de registro inesperado: {rec_type}")

    def messages(self) -> list[tuple[int, bytes]]:
        """Retira e devolve as mensagens completas acumuladas até agora."""
        out: list[tuple[int, bytes]] = []
        while len(self._handshake) >= 4:
            msg_type = self._handshake[0]
            length = int.from_bytes(self._handshake[1:4], "big")
            if len(self._handshake) < 4 + length:
                break
            out.append((msg_type, self._handshake[4 : 4 + length]))
            self._handshake = self._handshake[4 + length :]
        return out
