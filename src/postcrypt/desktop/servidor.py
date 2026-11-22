"""Servidor do painel em segundo plano, só em 127.0.0.1, numa porta livre.

O socket é aberto aqui e entregue pronto ao uvicorn: a porta escolhida não fica livre
nem por um instante, então outro programa não consegue tomá-la no meio do caminho.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

import uvicorn

HOST = "127.0.0.1"  # nunca outra interface: o painel não pode ficar acessível pela rede
PRAZO_INICIO_S = 15.0
PRAZO_PARADA_S = 5.0
INTERVALO_S = 0.05

log = logging.getLogger(__name__)


class ErroServidor(RuntimeError):
    """O servidor do painel não subiu (ou caiu) dentro do prazo."""


class ServidorUvicorn(Protocol):
    started: bool
    should_exit: bool

    async def serve(self, sockets: list[socket.socket] | None = None) -> None: ...


FabricaServidor = Callable[[uvicorn.Config], ServidorUvicorn]
FabricaSocket = Callable[[], socket.socket]


def abrir_socket_local() -> socket.socket:
    """Socket TCP em 127.0.0.1, porta escolhida pelo sistema, já escutando."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((HOST, 0))
        sock.listen(64)
    except OSError:
        sock.close()
        raise
    return sock


class ServidorPainel:
    """Liga e desliga o servidor do painel numa thread própria."""

    def __init__(
        self,
        app: Any,
        *,
        fabrica_servidor: FabricaServidor = uvicorn.Server,
        fabrica_socket: FabricaSocket = abrir_socket_local,
        relogio: Callable[[], float] = time.monotonic,
        dormir: Callable[[float], None] = time.sleep,
    ) -> None:
        self._app = app
        self._fabrica_servidor = fabrica_servidor
        self._fabrica_socket = fabrica_socket
        self._relogio = relogio
        self._dormir = dormir
        self._servidor: ServidorUvicorn | None = None
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._falha: BaseException | None = None
        self._url: str | None = None

    @property
    def url(self) -> str:
        if self._url is None:
            raise ErroServidor("o servidor não foi iniciado")
        return self._url

    @staticmethod
    def _url_do_socket(sock: socket.socket) -> str:
        host, porta = sock.getsockname()[:2]
        if host != HOST:
            raise ErroServidor("o servidor escutaria fora de 127.0.0.1")
        return f"http://{HOST}:{porta}/"

    def iniciar(self, prazo_s: float = PRAZO_INICIO_S) -> str:
        """Sobe o servidor e só devolve a URL quando ele já aceita pedidos."""
        if self._thread is not None:
            raise ErroServidor("o servidor já foi iniciado")
        self._socket = self._fabrica_socket()
        try:
            url = self._url_do_socket(self._socket)
        except ErroServidor:
            self._fechar_socket()
            raise
        self._url = url
        config = uvicorn.Config(
            self._app,
            log_config=None,  # o executável não tem console; o log vai para o arquivo
            access_log=False,  # endereços pedidos não interessam ao log
            lifespan="on",
        )
        self._servidor = self._fabrica_servidor(config)
        self._thread = threading.Thread(target=self._rodar, name="painel", daemon=True)
        self._thread.start()
        self._esperar_inicio(prazo_s)
        log.info("painel no ar em %s", url)
        return url

    def _rodar(self) -> None:
        servidor, sock = self._servidor, self._socket
        if servidor is None or sock is None:
            return
        try:
            asyncio.run(servidor.serve(sockets=[sock]))
        except BaseException as exc:  # a falha é repassada a quem espera o início
            self._falha = exc

    def _esperar_inicio(self, prazo_s: float) -> None:
        servidor, thread = self._servidor, self._thread
        if servidor is None or thread is None:
            raise ErroServidor("o servidor não foi iniciado")
        limite = self._relogio() + prazo_s
        while not servidor.started:
            if not thread.is_alive():
                self._fechar_socket()
                motivo = repr(self._falha) if self._falha else "encerrou sem iniciar"
                raise ErroServidor(f"o servidor do painel parou ao iniciar: {motivo}")
            if self._relogio() >= limite:
                self.parar()
                raise ErroServidor(f"o servidor do painel não iniciou em {prazo_s:.0f} s")
            self._dormir(INTERVALO_S)

    def parar(self, prazo_s: float = PRAZO_PARADA_S) -> None:
        """Pede o encerramento e espera a thread; seguro de chamar mais de uma vez."""
        if self._servidor is not None:
            self._servidor.should_exit = True
        if self._thread is not None:
            self._thread.join(prazo_s)
            if self._thread.is_alive():
                log.warning("o servidor do painel não encerrou em %.0f s", prazo_s)
        self._fechar_socket()

    def _fechar_socket(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None
