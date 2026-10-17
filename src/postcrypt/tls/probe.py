"""Sonda TLS: descobre o que um serviço negocia sem completar o handshake.

Conexões por alvo, no caso comum (servidor clássico): 1 hello TLS 1.3 com
grupos clássicos, 1 com grupos pós-quânticos, 1 hello TLS 1.2, 1 só com
troca de chave RSA e, se preciso, 1 conexão para obter a cadeia. Só quando o
servidor aceita algum grupo pós-quântico a sonda testa cada um deles.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass, field

from postcrypt.certs import CertificateInfo, parse_certificate
from postcrypt.tls.constants import (
    CLASSICAL_GROUPS,
    PQC_GROUPS,
    RSA_KEY_TRANSPORT_SUITES,
    TLS12_SUITES,
    TLS13_SUITES,
    group_name,
    suite_info,
)
from postcrypt.tls.messages import (
    HS_CERTIFICATE,
    HS_SERVER_HELLO,
    HS_SERVER_HELLO_DONE,
    HandshakeReader,
    ServerResponse,
    TLSParseError,
    build_client_hello,
    parse_certificate_tls12,
    parse_server_hello,
)


class ProbeConnectionError(OSError):
    """Não foi possível conversar com o alvo (porta fechada, timeout, reset)."""


@dataclass
class TLSObservation:
    tls13: bool = False
    tls13_cipher_suite: str | None = None
    tls13_symmetric: str | None = None
    classical_group: str | None = None
    pqc_groups: list[str] = field(default_factory=list)
    tls12: bool = False
    tls12_cipher_suite: str | None = None
    tls12_key_exchange: str | None = None
    tls12_symmetric: str | None = None
    rsa_key_transport: bool = False
    not_tls: bool = False  # a porta respondeu, mas não como TLS
    certificates: list[CertificateInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["certificates"] = [c.to_dict() for c in self.certificates]
        return data


def exchange(
    host: str, port: int, hello: bytes, *, timeout: float, want_certificates: bool = False
) -> ServerResponse:
    """Envia um ClientHello e lê a resposta até ter o que precisa.

    Só levanta ``ProbeConnectionError`` quando nem a conexão TCP abre. Depois de
    conectado, silêncio, reset ou resposta que não é TLS viram um
    ``ServerResponse`` com ``kind`` ``no_response`` ou ``not_tls``.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise ProbeConnectionError(str(exc) or exc.__class__.__name__) from exc

    response: ServerResponse | None = None
    with sock:
        try:
            sock.sendall(hello)
            reader = HandshakeReader()
            while True:
                data = sock.recv(16384)
                if not data:
                    break
                reader.feed(data)
                if reader.alert is not None and response is None:
                    return ServerResponse(kind="alert", alert=reader.alert)
                for msg_type, body in reader.messages():
                    if msg_type == HS_SERVER_HELLO:
                        response = parse_server_hello(body)
                        done = (
                            not want_certificates
                            or response.kind == "hello_retry_request"
                            or response.version == 0x0304
                        )
                        if done:
                            return response
                    elif msg_type == HS_CERTIFICATE and response is not None:
                        response.certificates = parse_certificate_tls12(body)
                        return response
                    elif msg_type == HS_SERVER_HELLO_DONE and response is not None:
                        return response
        except TLSParseError:
            return ServerResponse(kind="not_tls")
        except OSError:  # timeout, reset no meio da leitura
            pass
    return response or ServerResponse(kind="no_response")


class TLSProbe:
    def __init__(self, host: str, port: int, *, sni: str | None = None, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.sni = sni
        self.timeout = timeout
        self._saw_not_tls = False

    def _exchange(self, hello: bytes, *, want_certificates: bool = False) -> ServerResponse:
        resp = exchange(
            self.host, self.port, hello, timeout=self.timeout, want_certificates=want_certificates
        )
        if resp.kind == "not_tls":
            self._saw_not_tls = True
        return resp

    # --- TLS 1.3 -------------------------------------------------------------

    def tls13_select(self, groups: tuple[int, ...] | list[int]) -> ServerResponse | None:
        """Grupo que o servidor escolhe entre ``groups`` em TLS 1.3, ou None."""
        hello = build_client_hello(
            cipher_suites=list(TLS13_SUITES), groups=groups, sni=self.sni, tls13=True
        )
        resp = self._exchange(hello)
        if resp.kind not in ("hello_retry_request", "server_hello"):
            return None
        if resp.version != 0x0304 or resp.selected_group is None:
            return None
        if resp.selected_group not in groups:
            return None
        return resp

    # --- TLS 1.2 -------------------------------------------------------------

    def tls12_hello(self, suites: tuple[int, ...] | list[int]) -> ServerResponse | None:
        hello = build_client_hello(
            cipher_suites=list(suites), groups=CLASSICAL_GROUPS, sni=self.sni, tls13=False
        )
        resp = self._exchange(hello, want_certificates=True)
        if resp.kind != "server_hello" or resp.version != 0x0303:
            return None
        return resp

    # --- Cadeia de certificados ----------------------------------------------

    def fetch_chain(self) -> list[bytes]:
        """Cadeia via biblioteca ssl, sem validar: aqui o objetivo é inventariar."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        # Inventário, não confiança: a cadeia é registrada mesmo se for inválida.
        ctx.verify_mode = ssl.CERT_NONE  # nosec B501
        server_hostname = self.sni if self.sni and not _is_ip(self.sni) else None
        with (
            socket.create_connection((self.host, self.port), timeout=self.timeout) as raw,
            ctx.wrap_socket(raw, server_hostname=server_hostname) as tls,
        ):
            if hasattr(tls, "get_unverified_chain"):  # Python 3.13+
                return [bytes(c) for c in tls.get_unverified_chain() or []]
            leaf = tls.getpeercert(binary_form=True)
            return [leaf] if leaf else []

    # --- Execução completa ---------------------------------------------------

    def run(self) -> TLSObservation:
        obs = TLSObservation()

        # 1) TLS 1.3 com grupos clássicos: descobre se há TLS 1.3 e a suíte.
        classical = self.tls13_select(CLASSICAL_GROUPS)
        if classical is not None:
            obs.tls13 = True
            obs.classical_group = group_name(classical.selected_group or 0)
            name, _, symmetric = suite_info(classical.cipher_suite or 0)
            obs.tls13_cipher_suite, obs.tls13_symmetric = name, symmetric

        # 2) TLS 1.3 com grupos pós-quânticos; só enumera se aceitar algum.
        pqc = self.tls13_select(PQC_GROUPS)
        if pqc is not None:
            obs.tls13 = True
            if obs.tls13_cipher_suite is None:
                name, _, symmetric = suite_info(pqc.cipher_suite or 0)
                obs.tls13_cipher_suite, obs.tls13_symmetric = name, symmetric
            for group in PQC_GROUPS:
                if self.tls13_select((group,)) is not None:
                    obs.pqc_groups.append(group_name(group))

        # 3) TLS 1.2: suíte preferida pelo servidor e cadeia em claro.
        chain: list[bytes] = []
        tls12 = self.tls12_hello(tuple(TLS12_SUITES))
        if tls12 is not None:
            obs.tls12 = True
            name, kx, symmetric = suite_info(tls12.cipher_suite or 0)
            obs.tls12_cipher_suite, obs.tls12_key_exchange, obs.tls12_symmetric = (
                name,
                kx,
                symmetric,
            )
            chain = tls12.certificates
            # 4) Aceita troca de chave RSA (sem sigilo futuro)?
            if kx == "RSA":
                obs.rsa_key_transport = True
            else:
                obs.rsa_key_transport = self.tls12_hello(RSA_KEY_TRANSPORT_SUITES) is not None

        # 5) Cadeia de certificados.
        if not chain and (obs.tls13 or obs.tls12):
            try:
                chain = self.fetch_chain()
            except (OSError, ssl.SSLError) as exc:
                obs.errors.append(f"cadeia de certificados indisponível: {exc}")
        obs.not_tls = self._saw_not_tls and not (obs.tls13 or obs.tls12)
        for position, der in enumerate(chain):
            try:
                obs.certificates.append(parse_certificate(der, position))
            except ValueError as exc:
                obs.errors.append(f"certificado {position} ilegível: {exc}")

        return obs


def _is_ip(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in value else socket.AF_INET, value)
    except OSError:
        return False
    return True
