"""OpenSSH de verdade (sshd), em primeiro plano, para os testes de integração SSH.

Só sobe quando há um ``sshd`` na máquina; sem ele, o teste é pulado. O
servidor não aceita login nenhum: senha, teclado e chave pública ficam
desligados, então ninguém entra, como a sonda, que nunca tenta.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess  # nosec B404 - executa só o sshd local com argumentos fixos
import sys
import time
from contextlib import suppress
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

CANDIDATES = ("/usr/sbin/sshd", "/usr/local/sbin/sshd")


def find_sshd() -> str | None:
    # O sshd do Windows exige permissões de arquivo e serviço próprios: lá os testes com
    # OpenSSH de verdade são pulados e rodam no CI (Linux) e no laboratório Docker.
    if sys.platform == "win32":
        return None
    found = shutil.which("sshd")
    if found:
        return found
    return next((c for c in CANDIDATES if Path(c).is_file()), None)


def _free_port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as s:
        return int(s.getsockname()[1])


class SSHDServer:
    """``with SSHDServer(tmp_path, extra=["KexAlgorithms curve25519-sha256"]) as srv: srv.port``."""

    def __init__(self, workdir: Path, *, extra: list[str] | None = None) -> None:
        sshd = find_sshd()
        if sshd is None:
            raise FileNotFoundError("sshd não encontrado")
        self.sshd = sshd
        self.port = _free_port()
        self.workdir = workdir
        self.extra = extra or []
        self._proc: subprocess.Popen[bytes] | None = None

    def _write_config(self) -> Path:
        key = ed25519.Ed25519PrivateKey.generate()
        host_key = self.workdir / f"host_ed25519_{self.port}"
        host_key.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            )
        )
        host_key.chmod(0o600)
        lines = [
            f"Port {self.port}",
            "ListenAddress 127.0.0.1",
            f"HostKey {host_key}",
            "PidFile none",
            "StrictModes no",
            "UsePAM no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PubkeyAuthentication no",
            *self.extra,
        ]
        config = self.workdir / f"sshd_{self.port}.conf"
        config.write_text("\n".join(lines) + "\n", encoding="ascii")
        return config

    def __enter__(self) -> SSHDServer:
        config = self._write_config()
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
            Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)  # diretório de privsep do sshd
        self._proc = subprocess.Popen(  # nosec B603
            [self.sshd, "-D", "-e", "-f", str(config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        limit = time.monotonic() + 10
        while time.monotonic() < limit:
            if self._proc.poll() is not None:
                err = self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else ""
                raise RuntimeError(f"sshd não subiu: {err.strip()[:300]}")
            with suppress(OSError), socket.create_connection(("127.0.0.1", self.port), timeout=0.3):
                return self
            time.sleep(0.1)
        self.__exit__()
        raise RuntimeError("sshd não abriu a porta a tempo")

    def __exit__(self, *exc: object) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def version(self) -> str:
        proc = subprocess.run(  # nosec B603
            [self.sshd, "-V"], capture_output=True, text=True, timeout=10, check=False
        )
        return (proc.stderr or proc.stdout).strip()
