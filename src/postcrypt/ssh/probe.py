"""Sonda SSH: lê o banner e a lista de algoritmos do servidor, sem autenticar.

Espelha ``tls/probe.py`` para o SSH, sem reaproveitar a observação do TLS.
Uma conexão por alvo, com um único prazo total (conexão e leituras somadas):

1. lê a linha de identificação que o servidor manda ao conectar;
2. manda a linha de identificação do Post-Crypt;
3. lê o KEXINIT do servidor (listas de troca de chave, chave do servidor,
   cifras, MACs, compressão) e fecha.

Nenhuma troca de chave é feita, nenhum usuário ou senha é enviado. Completar a
troca de chave para obter a chave pública do servidor é uma feature futura,
separada (decisão 0003).
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from postcrypt import __version__
from postcrypt.probe_errors import ProbeConnectionError
from postcrypt.ssh.messages import (
    MSG_DEBUG,
    MSG_IGNORE,
    MSG_KEXINIT,
    BannerReader,
    Identification,
    KexInit,
    SSHParseError,
    client_identification,
    parse_kexinit,
    take_packet,
)

MAX_SKIPPED_PACKETS = 8  # IGNORE/DEBUG que um servidor pode mandar antes do KEXINIT
_RECV_CHUNK = 4096

Clock = Callable[[], float]
Connect = Callable[[tuple[str, int], float], socket.socket]


def _connect(address: tuple[str, int], timeout: float) -> socket.socket:
    return socket.create_connection(address, timeout=timeout)


@dataclass
class SSHObservation:
    software: str | None = None  # ex.: "OpenSSH_9.6p1"
    comments: str | None = None  # ex.: "Ubuntu-3ubuntu13.20"
    protocol: str | None = None  # "2.0"
    kex: list[str] = field(default_factory=list[str])
    host_key: list[str] = field(default_factory=list[str])
    ciphers: list[str] = field(default_factory=list[str])  # união c2s + s2c, ordem do servidor
    macs: list[str] = field(default_factory=list[str])
    compression: list[str] = field(default_factory=list[str])
    strict_kex: bool = False  # kex-strict-s-v00@openssh.com (mitigação do Terrapin)
    not_ssh: bool = False  # a porta respondeu, mas não como SSH
    errors: list[str] = field(default_factory=list[str])

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _union(*lists: tuple[str, ...]) -> list[str]:
    seen: dict[str, None] = {}
    for names in lists:
        for name in names:
            seen.setdefault(name)
    return list(seen)


def observation_from(ident: Identification, kexinit: KexInit | None) -> SSHObservation:
    """Monta a observação a partir do que foi lido (lógica pura, sem rede)."""
    obs = SSHObservation(software=ident.software, comments=ident.comments, protocol=ident.protocol)
    if kexinit is None:
        return obs
    obs.kex = list(kexinit.kex)
    obs.host_key = list(kexinit.host_key)
    obs.ciphers = _union(kexinit.ciphers_c2s, kexinit.ciphers_s2c)
    obs.macs = _union(kexinit.macs_c2s, kexinit.macs_s2c)
    obs.compression = _union(kexinit.compression_c2s, kexinit.compression_s2c)
    obs.strict_kex = any(m.startswith("kex-strict-s-") for m in kexinit.kex_extensions)
    return obs


def _failed_read(ident: Identification | None, *, timed_out: bool) -> SSHObservation:
    """Observação de uma leitura interrompida, dizendo em que ponto e por quê."""
    motivo = "a tempo" if timed_out else "antes de a conexão cair"
    if ident is None:
        return SSHObservation(errors=[f"o serviço não mandou a identificação SSH {motivo}"])
    obs = observation_from(ident, None)
    obs.errors.append(f"o servidor não mandou a lista de algoritmos {motivo}")
    return obs


class SSHProbe:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 5.0,
        clock: Clock = time.monotonic,
        connect: Connect = _connect,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout precisa ser positivo")
        self.host = host
        self.port = port
        self.timeout = timeout
        self._clock = clock
        self._connect = connect

    def _recv(self, sock: socket.socket, deadline: float) -> bytes:
        """Uma leitura com o que resta do prazo; prazo esgotado conta como silêncio."""
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise TimeoutError("prazo esgotado")
        sock.settimeout(remaining)
        return sock.recv(_RECV_CHUNK)

    def _read_identification(self, sock: socket.socket, deadline: float) -> BannerReader:
        reader = BannerReader()
        while True:
            data = self._recv(sock, deadline)
            if not data:
                raise SSHParseError("a conexão fechou antes da identificação SSH")
            if reader.feed(data):
                return reader

    def _read_kexinit(self, sock: socket.socket, deadline: float, buffer: bytes) -> KexInit:
        skipped = 0
        while True:
            payload, buffer = take_packet(buffer)
            if payload is None:
                data = self._recv(sock, deadline)
                if not data:
                    raise SSHParseError("a conexão fechou antes da lista de algoritmos")
                buffer += data
                continue
            if payload and payload[0] == MSG_KEXINIT:
                return parse_kexinit(payload)
            if payload and payload[0] in (MSG_IGNORE, MSG_DEBUG) and skipped < MAX_SKIPPED_PACKETS:
                skipped += 1
                continue
            raise SSHParseError("o servidor não mandou a lista de algoritmos")

    def run(self) -> SSHObservation:
        deadline = self._clock() + self.timeout
        try:
            sock = self._connect((self.host, self.port), self.timeout)
        except OSError as exc:
            raise ProbeConnectionError(str(exc) or exc.__class__.__name__) from exc

        ident: Identification | None = None
        with sock:
            try:
                reader = self._read_identification(sock, deadline)
                ident = reader.identification
                if ident is None:  # pragma: no cover - feed só devolve True com identificação
                    raise SSHParseError("identificação SSH ausente")
                remaining = deadline - self._clock()
                if remaining <= 0:
                    raise TimeoutError("prazo esgotado")
                sock.settimeout(remaining)
                sock.sendall(client_identification(__version__))
                kexinit = self._read_kexinit(sock, deadline, reader.rest)
                return observation_from(ident, kexinit)
            except SSHParseError as exc:
                if ident is None:
                    return SSHObservation(not_ssh=True, errors=[str(exc)])
                obs = observation_from(ident, None)
                obs.errors.append(str(exc))
                return obs
            except OSError as exc:  # prazo esgotado ou conexão derrubada no meio da leitura
                return _failed_read(ident, timed_out=isinstance(exc, TimeoutError))
