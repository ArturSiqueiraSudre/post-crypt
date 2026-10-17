"""Testes unitários do ClientHello e da leitura do ServerHello."""

import struct

import pytest

from postcrypt.tls.constants import GROUP_IDS, HRR_RANDOM, TLS13_SUITES
from postcrypt.tls.messages import (
    EXT_KEY_SHARE,
    EXT_SERVER_NAME,
    EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS,
    HandshakeReader,
    TLSParseError,
    _parse_extensions,
    build_client_hello,
    parse_certificate_tls12,
    parse_server_hello,
)


def _split_client_hello(record: bytes) -> tuple[bytes, dict[int, bytes]]:
    assert record[0] == 0x16
    rec_len = struct.unpack_from("!H", record, 3)[0]
    assert rec_len == len(record) - 5
    hs = record[5:]
    assert hs[0] == 0x01
    assert int.from_bytes(hs[1:4], "big") == len(hs) - 4
    body = hs[4:]
    pos = 2 + 32
    pos += 1 + body[pos]  # session id
    suites_len = struct.unpack_from("!H", body, pos)[0]
    suites = body[pos + 2 : pos + 2 + suites_len]
    pos += 2 + suites_len
    pos += 1 + body[pos]  # compressão
    ext_len = struct.unpack_from("!H", body, pos)[0]
    exts = _parse_extensions(body[pos + 2 : pos + 2 + ext_len])
    assert pos + 2 + ext_len == len(body)
    return suites, exts


def _server_hello(*, random: bytes, suite: int, exts: bytes, version: int = 0x0303) -> bytes:
    return (
        struct.pack("!H", version)
        + random
        + bytes([32])
        + b"\x11" * 32
        + struct.pack("!H", suite)
        + b"\x00"
        + struct.pack("!H", len(exts))
        + exts
    )


def _ext(t: int, body: bytes) -> bytes:
    return struct.pack("!HH", t, len(body)) + body


def test_tls13_hello_offers_only_tls13_and_empty_key_share():
    groups = [GROUP_IDS["X25519MLKEM768"]]
    suites, exts = _split_client_hello(
        build_client_hello(cipher_suites=list(TLS13_SUITES), groups=groups, sni="vpn.example")
    )
    assert len(suites) == 2 * len(TLS13_SUITES)
    assert exts[EXT_SUPPORTED_VERSIONS] == b"\x02\x03\x04"
    assert exts[EXT_KEY_SHARE] == b"\x00\x00"
    assert exts[EXT_SUPPORTED_GROUPS] == b"\x00\x02\x11\xec"
    assert b"vpn.example" in exts[EXT_SERVER_NAME]


def test_sni_omitted_for_ip_literal():
    _, exts = _split_client_hello(
        build_client_hello(cipher_suites=[0x1301], groups=[0x001D], sni="10.0.0.5")
    )
    assert EXT_SERVER_NAME not in exts


def test_tls12_hello_has_no_supported_versions():
    _, exts = _split_client_hello(
        build_client_hello(cipher_suites=[0xC02F], groups=[0x0017], tls13=False)
    )
    assert EXT_SUPPORTED_VERSIONS not in exts
    assert EXT_KEY_SHARE not in exts


def test_requires_cipher_suites():
    with pytest.raises(ValueError):
        build_client_hello(cipher_suites=[], groups=[0x001D])


def test_parse_hello_retry_request_selected_group():
    exts = _ext(EXT_SUPPORTED_VERSIONS, b"\x03\x04") + _ext(EXT_KEY_SHARE, b"\x11\xec")
    resp = parse_server_hello(_server_hello(random=HRR_RANDOM, suite=0x1302, exts=exts))
    assert resp.kind == "hello_retry_request"
    assert resp.version == 0x0304
    assert resp.selected_group == 0x11EC
    assert resp.cipher_suite == 0x1302


def test_parse_tls12_server_hello():
    resp = parse_server_hello(_server_hello(random=b"\x01" * 32, suite=0x009D, exts=b""))
    assert resp.kind == "server_hello"
    assert resp.version == 0x0303
    assert resp.selected_group is None


def test_parse_truncated_server_hello_raises():
    with pytest.raises(TLSParseError):
        parse_server_hello(b"\x03\x03" + b"\x00" * 10)


def test_reader_handles_alert_and_fragmented_records():
    body = _server_hello(random=b"\x02" * 32, suite=0xC02F, exts=b"")
    msg = b"\x02" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + struct.pack("!H", len(msg)) + msg
    reader = HandshakeReader()
    reader.feed(record[:7])  # registro chega picado
    assert reader.messages() == []
    reader.feed(record[7:])
    [(msg_type, parsed)] = reader.messages()
    assert msg_type == 0x02 and parsed == body

    alert = HandshakeReader()
    alert.feed(b"\x15\x03\x03\x00\x02\x02\x28")
    assert alert.alert == 40


def test_reader_rejects_non_tls_bytes():
    with pytest.raises(TLSParseError):
        HandshakeReader().feed(b"SSH-2.0-OpenSSH_10.0\r\n")


def test_parse_certificate_list():
    certs = [b"A" * 5, b"B" * 3]
    inner = b"".join(len(c).to_bytes(3, "big") + c for c in certs)
    assert parse_certificate_tls12(len(inner).to_bytes(3, "big") + inner) == certs
