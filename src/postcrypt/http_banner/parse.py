"""Leitura do cabeçalho de resposta HTTP devolvido por um servidor varrido.

Tudo o que chega aqui é hostil: o servidor pode mandar qualquer byte. O parser
aceita só o formato mínimo do HTTP/1.x (linha de status e campos
``Nome: valor`` separados por CRLF), com teto de tamanho em cada etapa, e
devolve apenas os poucos cabeçalhos que identificam software. Campo fora do
formato é descartado e contado, nunca "consertado".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_HEAD_BYTES = 16 * 1024  # cabeçalho inteiro, linha de status incluída
MAX_LINE_BYTES = 4096
MAX_FIELDS = 100
MAX_VALUE_CHARS = 256  # o que passa disso é cortado antes de virar evidência

# Cabeçalhos que dizem qual software responde. Os demais são ignorados de propósito:
# o fingerprint não guarda cookies, caminhos nem nada que identifique pessoas.
INTERESTING_HEADERS = ("server", "x-powered-by", "x-aspnet-version")

_END_OF_HEAD = b"\r\n\r\n"
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e\t]*)?")
_FIELD_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")  # token da RFC 9110
_FIELD_VALUE = re.compile(rb"[\x20-\x7e\t]*")  # ASCII visível, espaço e tab


class HTTPHeadError(ValueError):
    """A resposta não é um cabeçalho HTTP/1.x utilizável."""


@dataclass(frozen=True)
class HTTPResponseHead:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict[str, str])  # nome minúsculo -> valor
    dropped_fields: int = 0  # campos descartados por estarem fora do formato


def split_head(raw: bytes) -> bytes:
    """Recorta o cabeçalho (sem o CRLF duplo final) ou levanta ``HTTPHeadError``."""
    if not raw:
        raise HTTPHeadError("o servidor não respondeu ao pedido HTTP")
    end = raw.find(_END_OF_HEAD, 0, MAX_HEAD_BYTES + len(_END_OF_HEAD))
    if end < 0:
        if len(raw) >= MAX_HEAD_BYTES:
            raise HTTPHeadError("cabeçalho HTTP longo demais")
        raise HTTPHeadError("resposta HTTP incompleta ou fora do formato")
    return raw[:end]


def _parse_status(line: bytes) -> int:
    match = _STATUS_LINE.fullmatch(line)
    if match is None:
        raise HTTPHeadError("a resposta não é HTTP/1.x")
    return int(match.group(1))


def _parse_field(line: bytes) -> tuple[str, str] | None:
    """Um campo ``Nome: valor`` válido, ou None quando a linha está fora do formato."""
    if len(line) > MAX_LINE_BYTES or line[:1] in (b" ", b"\t"):
        return None  # linha longa demais ou continuação obsoleta (obs-fold)
    name, sep, value = line.partition(b":")
    if not sep or _FIELD_NAME.fullmatch(name) is None:
        return None
    value = value.strip(b" \t")
    if _FIELD_VALUE.fullmatch(value) is None:
        return None  # byte de controle, CR/LF solto ou fora do ASCII
    return name.decode("ascii").lower(), value.decode("ascii")[:MAX_VALUE_CHARS]


def parse_response_head(raw: bytes) -> HTTPResponseHead:
    """Interpreta a resposta crua do servidor e guarda só os cabeçalhos de software."""
    lines = split_head(raw).split(b"\r\n")
    status_code = _parse_status(lines[0])
    if len(lines) - 1 > MAX_FIELDS:
        raise HTTPHeadError("campos demais no cabeçalho HTTP")
    headers: dict[str, str] = {}
    dropped = 0
    for line in lines[1:]:
        parsed = _parse_field(line)
        if parsed is None:
            dropped += 1
            continue
        name, value = parsed
        if name in INTERESTING_HEADERS and name not in headers and value:
            headers[name] = value  # a primeira ocorrência vale; repetição não sobrescreve
    return HTTPResponseHead(status_code=status_code, headers=headers, dropped_fields=dropped)
