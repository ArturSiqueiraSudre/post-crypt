"""Liga e desliga o laboratório em Python a partir do painel.

O laboratório (pasta ``lab``) não faz parte do pacote instalado: só existe no
clone do repositório. Quando a pasta não é encontrada, o painel simplesmente
não oferece o botão.
"""

from __future__ import annotations

import socket
import ssl

# Só executa os scripts fixos do próprio repositório, com o interpretador atual.
import subprocess  # nosec B404
import sys
import threading
import time
from pathlib import Path

PORTAS = (8441, 8442, 8443, 8444, 8445)
DURACAO_MAXIMA_S = 4 * 3600


def encontrar_raiz(inicio: Path | None = None) -> Path | None:
    """Procura a pasta do repositório que contém o laboratório."""
    candidatos: list[Path] = []
    base = (inicio or Path.cwd()).resolve()
    candidatos += [base, *base.parents]
    candidatos.append(Path(__file__).resolve().parents[3])  # instalação editável
    for pasta in candidatos:
        lab = pasta / "lab"
        if (lab / "servidores_python.py").is_file() and (lab / "escopo-lab.yaml").is_file():
            return pasta
    return None


def _porta_aberta(porta: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", porta), timeout=0.3):
            return True
    except OSError:
        return False


class Laboratorio:
    def __init__(self, raiz: Path | None) -> None:
        self.raiz = raiz
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()

    @property
    def disponivel(self) -> bool:
        return self.raiz is not None

    @property
    def escopo(self) -> Path | None:
        return self.raiz / "lab" / "escopo-lab.yaml" if self.raiz else None

    @property
    def ligado(self) -> bool:
        return all(_porta_aberta(p) for p in PORTAS)

    @property
    def aviso(self) -> str | None:
        if ssl.OPENSSL_VERSION_INFO < (3, 5):
            return (
                f"Este Python usa {ssl.OPENSSL_VERSION}, sem ML-KEM: o serviço híbrido "
                "do laboratório vai aparecer como clássico. Use o Python 3.13 do uv."
            )
        return None

    def ligar(self, espera_s: float = 20.0) -> None:
        if self.raiz is None:
            raise RuntimeError("a pasta lab não foi encontrada")
        with self._lock:
            if self.ligado:
                return
            lab = self.raiz / "lab"
            # Validades dos certificados são relativas a hoje: gera de novo a cada vez.
            # Argumentos fixos (interpretador atual + script do repositório), sem shell.
            subprocess.run(  # noqa: S603  # nosec B603
                [sys.executable, str(lab / "gerar_certificados.py")],
                cwd=self.raiz,
                check=True,
                capture_output=True,
                timeout=60,
            )
            self._proc = subprocess.Popen(  # noqa: S603  # nosec B603
                [
                    sys.executable,
                    str(lab / "servidores_python.py"),
                    "--duracao",
                    str(DURACAO_MAXIMA_S),
                ],
                cwd=self.raiz,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            limite = time.monotonic() + espera_s
            while time.monotonic() < limite:
                if self._proc.poll() is not None:
                    raise RuntimeError("os servidores do laboratório não subiram")
                if self.ligado:
                    return
                time.sleep(0.2)
            raise RuntimeError("o laboratório demorou demais para responder")

    def desligar(self) -> None:
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            self._proc = None
