import socket
import threading

import pytest

from postcrypt.desktop.servidor import HOST, ErroServidor, ServidorPainel, abrir_socket_local


class FalsoServidor:
    """Imita o uvicorn.Server: inicia, espera should_exit e termina."""

    def __init__(self, config, *, iniciar=True, falha=None):
        self.config = config
        self.started = False
        self.should_exit = False
        self.sockets = None
        self._iniciar = iniciar
        self._falha = falha
        self.parou = threading.Event()

    async def serve(self, sockets=None):
        import asyncio

        self.sockets = sockets
        if self._falha:
            raise self._falha
        if self._iniciar:
            self.started = True
        while not self.should_exit:
            await asyncio.sleep(0.01)
        self.parou.set()


def fabrica(**kwargs):
    criados = []

    def criar(config):
        s = FalsoServidor(config, **kwargs)
        criados.append(s)
        return s

    return criar, criados


def test_inicia_em_127_0_0_1_com_o_socket_ja_aberto():
    criar, criados = fabrica()
    srv = ServidorPainel(object(), fabrica_servidor=criar)
    url = srv.iniciar(prazo_s=5)
    try:
        assert url.startswith(f"http://{HOST}:") and url.endswith("/")
        assert criados[0].sockets and criados[0].sockets[0].getsockname()[0] == HOST
        config = criados[0].config
        assert config.log_config is None and config.access_log is False
        assert srv.url == url
    finally:
        srv.parar()
    assert criados[0].parou.is_set()


def test_parar_duas_vezes_e_seguro():
    criar, _ = fabrica()
    srv = ServidorPainel(object(), fabrica_servidor=criar)
    srv.iniciar(prazo_s=5)
    srv.parar()
    srv.parar()


def test_parar_sem_iniciar_nao_quebra():
    ServidorPainel(object()).parar()


def test_url_antes_de_iniciar_e_erro():
    with pytest.raises(ErroServidor):
        _ = ServidorPainel(object()).url


def test_iniciar_duas_vezes_e_recusado():
    criar, _ = fabrica()
    srv = ServidorPainel(object(), fabrica_servidor=criar)
    srv.iniciar(prazo_s=5)
    try:
        with pytest.raises(ErroServidor, match="já foi iniciado"):
            srv.iniciar()
    finally:
        srv.parar()


def test_servidor_que_morre_ao_iniciar_vira_erro_claro():
    criar, _ = fabrica(falha=RuntimeError("porta presa"))
    srv = ServidorPainel(object(), fabrica_servidor=criar)
    with pytest.raises(ErroServidor, match="porta presa"):
        srv.iniciar(prazo_s=5)


def test_servidor_que_nao_inicia_estoura_o_prazo_e_e_desligado():
    criar, criados = fabrica(iniciar=False)
    agora = [0.0]
    srv = ServidorPainel(
        object(),
        fabrica_servidor=criar,
        relogio=lambda: agora[0],
        dormir=lambda s: agora.__setitem__(0, agora[0] + s),
    )
    with pytest.raises(ErroServidor, match="não iniciou em 2 s"):
        srv.iniciar(prazo_s=2)
    assert criados[0].should_exit is True


def test_socket_fora_do_loopback_e_recusado_e_fechado():
    sock = socket.socket()
    sock.bind(("0.0.0.0", 0))  # noqa: S104 - o teste prova que isso é recusado
    srv = ServidorPainel(object(), fabrica_socket=lambda: sock)
    with pytest.raises(ErroServidor, match=r"fora de 127\.0\.0\.1"):
        srv.iniciar()
    assert sock.fileno() == -1


def test_socket_local_escuta_so_no_loopback():
    sock = abrir_socket_local()
    try:
        host, porta = sock.getsockname()[:2]
        assert host == "127.0.0.1" and porta > 0
    finally:
        sock.close()


def test_falha_ao_abrir_a_porta_fecha_o_socket(monkeypatch):
    criados = []
    original = socket.socket

    class SocketQueFalha(original):
        def bind(self, endereco):
            criados.append(self)
            raise OSError("porta indisponível")

    monkeypatch.setattr("postcrypt.desktop.servidor.socket.socket", SocketQueFalha)
    with pytest.raises(OSError, match="indisponível"):
        abrir_socket_local()
    assert criados[0].fileno() == -1
