"""Adaptador de rede: o único pedido HTTP mínimo do fingerprint (decisão 0002).

Só roda em alvo com ``http_fingerprint: true`` no escopo. Abre TLS no mesmo
host e porta já autorizados, manda um ``HEAD /`` com ``Connection: close`` e
lê apenas o cabeçalho da resposta, com prazo total e teto de bytes. Não segue
redirecionamento, não lê corpo, não tenta outro caminho, outra porta nem
outro endereço. O pedido não carrega segredo, cookie nem credencial.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol

from postcrypt import __version__
from postcrypt.http_banner.parse import MAX_HEAD_BYTES

MAX_TIMEOUT_S = 10.0  # prazo total do pedido, por mais alto que venha o --timeout
_RECV_CHUNK = 4096
_HOST_NAME = re.compile(r"[A-Za-z0-9.\-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\]")
_HOST_VALUE = re.compile(r"(?:[A-Za-z0-9.\-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(?::[0-9]{1,5})?")
USER_AGENT = f"post-crypt/{__version__} (identificacao de versao autorizada; 1 pedido)"


class BannerUnavailable(OSError):
    """O pedido HTTP não pôde ser feito ou respondido. A mensagem é nossa, nunca do servidor."""


class Stream(Protocol):
    def sendall(self, data: bytes, /) -> None: ...
    def recv(self, bufsize: int, /) -> bytes: ...
    def settimeout(self, value: float | None, /) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class BannerRequest:
    host: str
    port: int
    sni: str | None
    timeout: float


Clock = Callable[[], float]
# Recebe o pedido e o instante-limite (no relógio monotônico) para conectar e negociar o TLS.
Connector = Callable[[BannerRequest, float], Stream]
TcpOpener = Callable[[tuple[str, int], float], socket.socket]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def host_header(host: str, sni: str | None, port: int) -> str:
    """Valor do cabeçalho Host: o nome do serviço, com a porta quando não é 443."""
    name = sni or host
    if ":" in name and _is_ip(name):
        name = f"[{name}]"  # IPv6 vai entre colchetes
    if _HOST_NAME.fullmatch(name) is None:
        # O escopo já recusa isso; aqui é defesa em profundidade contra injeção de cabeçalho.
        raise ValueError("nome de host impróprio para o cabeçalho Host")
    return name if port == 443 else f"{name}:{port}"


def build_head_request(host: str) -> bytes:
    """Pedido fixo: só o Host varia, e ele precisa casar com a lista de caracteres permitidos."""
    if _HOST_VALUE.fullmatch(host) is None:
        raise ValueError("cabeçalho Host inválido")
    lines = (
        "HEAD / HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {USER_AGENT}",
        "Accept: */*",
        "Connection: close",
    )
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _remaining(deadline: float, clock: Clock) -> float:
    left = deadline - clock()
    if left <= 0:
        raise BannerUnavailable("o prazo do pedido HTTP acabou antes da resposta")
    return left


def _open_tcp(address: tuple[str, int], timeout: float) -> socket.socket:
    return socket.create_connection(address, timeout=timeout)


def default_connector(
    request: BannerRequest,
    deadline: float,
    *,
    clock: Clock = time.monotonic,
    open_tcp: TcpOpener = _open_tcp,
) -> Stream:
    """TLS sem validar certificado: o objetivo é inventariar, e o pedido não leva segredo.

    Connect e handshake dividem o mesmo prazo: o handshake só recebe o tempo que
    o connect deixou. (O CPython aplica o timeout do socket ao handshake inteiro,
    não a cada leitura, então um servidor que goteja o handshake também para aqui.)

    Risco aceito (decisão 0002): suítes antigas e certificado sem validação. O
    pedido não carrega segredo e o banner já é tratado como não confiável.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    # Inventário, não confiança: o certificado já foi registrado pela sonda TLS.
    ctx.verify_mode = ssl.CERT_NONE  # nosec B501
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Aceita as suítes que o servidor aceitar (inclusive troca de chave RSA): o pedido é
    # público por natureza, e um alvo legado também precisa ser identificado.
    ctx.set_ciphers("ALL:@SECLEVEL=1")
    ctx.set_alpn_protocols(["http/1.1"])
    server_hostname = request.sni if request.sni and not _is_ip(request.sni) else None
    raw = open_tcp((request.host, request.port), _remaining(deadline, clock))
    try:
        raw.settimeout(_remaining(deadline, clock))
        tls = ctx.wrap_socket(raw, server_hostname=server_hostname)
    except BaseException:
        raw.close()
        raise
    selected = tls.selected_alpn_protocol()
    if selected not in (None, "http/1.1"):
        tls.close()
        raise BannerUnavailable("o servidor não aceita HTTP/1.1 nesta porta")
    return tls


def read_head(stream: Stream, *, deadline: float, clock: Clock = time.monotonic) -> bytes:
    """Lê até o fim do cabeçalho, até o teto de bytes ou até o prazo total acabar.

    O prazo é do pedido inteiro, não de cada leitura: um servidor que pinga um
    byte por vez (slowloris) não segura a varredura.
    """
    data = b""
    while len(data) < MAX_HEAD_BYTES and b"\r\n\r\n" not in data:
        remaining = deadline - clock()
        if remaining <= 0:
            raise BannerUnavailable("o servidor não terminou de responder ao pedido HTTP a tempo")
        stream.settimeout(remaining)
        try:
            chunk = stream.recv(min(_RECV_CHUNK, MAX_HEAD_BYTES - len(data)))
        except TimeoutError as exc:
            raise BannerUnavailable("o servidor não respondeu ao pedido HTTP a tempo") from exc
        if not chunk:
            break  # o servidor fechou: o parser decide se o que veio basta
        data += chunk
    return data


def fetch_banner(
    request: BannerRequest,
    *,
    connector: Connector = default_connector,
    clock: Clock = time.monotonic,
) -> bytes:
    """Faz o único pedido ``HEAD /`` e devolve os bytes crus do cabeçalho de resposta."""
    if request.timeout <= 0:
        raise ValueError("timeout precisa ser positivo")
    budget = min(request.timeout, MAX_TIMEOUT_S)
    deadline = clock() + budget
    payload = build_head_request(host_header(request.host, request.sni, request.port))
    bounded = BannerRequest(request.host, request.port, request.sni, budget)
    try:
        stream = connector(bounded, deadline)
    except BannerUnavailable:
        raise
    except (OSError, ssl.SSLError) as exc:
        raise BannerUnavailable("não consegui abrir TLS para o pedido HTTP") from exc
    try:
        stream.settimeout(max(deadline - clock(), 0.001))
        stream.sendall(payload)
        return read_head(stream, deadline=deadline, clock=clock)
    except BannerUnavailable:
        raise
    except (OSError, ssl.SSLError) as exc:
        raise BannerUnavailable("a conexão caiu durante o pedido HTTP") from exc
    finally:
        with suppress(OSError):
            stream.close()
