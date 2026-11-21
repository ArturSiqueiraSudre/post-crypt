"""Laboratório sem Docker: os mesmos casos do nginx, servidos por Python.

Uso:
    python lab/gerar_certificados.py
    python lab/servidores_python.py            # Ctrl+C para parar
    postcrypt scan lab/escopo-lab.yaml

Usa as mesmas portas, certificados e gabarito do docker-compose. O caso
híbrido só aceita ML-KEM se este Python usar OpenSSL 3.5+ (os Pythons
instalados pelo uv usam); com OpenSSL antigo ele aparece como clássico.

Fingerprint (Estágio 2): os serviços de BANNERS respondem ao pedido HEAD com
um cabeçalho Server conhecido de antemão, que é o gabarito em
lab/gabarito-fingerprint.yaml. Os outros só fazem o handshake e fecham, como
um serviço TLS que não fala HTTP. No Docker, o nginx responde HTTP em todas
as portas com a versão real da imagem: lá só vale o gabarito de TLS e rede.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path

CERTS = Path(__file__).resolve().parent / "certs"

# serviço -> (porta, modo)
SERVICES = {
    "tls-hibrido": (8441, "hybrid"),
    "tls-classico": (8442, "classical"),
    "tls-legado": (8443, "tls12-rsa"),
    "tls-vencendo": (8444, "hybrid"),
    "tls-vencido": (8445, "hybrid"),
    "tls-desconhecido": (8446, "hybrid"),
}

# serviço -> cabeçalho Server devolvido ao HEAD / (gabarito do fingerprint)
BANNERS = {
    "tls-hibrido": "nginx/1.30.6",
    "tls-classico": "Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13",
    "tls-legado": "Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13",
    "tls-desconhecido": "Caddy/2.8.4",  # produto sem regra: registrado, nunca avaliado
}
MAX_REQUEST = 8192


def make_context(mode: str, name: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERTS / f"{name}.pem", CERTS / f"{name}.key")
    if mode == "classical":
        ctx.set_ecdh_curve("prime256v1")  # só P-256: nada de ML-KEM
    elif mode == "tls12-rsa":
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("AES256-GCM-SHA384")  # troca de chave RSA
    return ctx


def http_response(banner: str) -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\nServer: {banner}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def serve(name: str, port: int, ctx: ssl.SSLContext, stop: threading.Event) -> None:
    banner = BANNERS.get(name)
    with socket.create_server(("127.0.0.1", port)) as srv:
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            threading.Thread(target=_handle, args=(conn, ctx, banner), daemon=True).start()


def _answer_http(tls: ssl.SSLSocket, banner: str) -> None:
    request = b""
    while b"\r\n\r\n" not in request and len(request) < MAX_REQUEST:
        chunk = tls.recv(1024)
        if not chunk:
            return
        request += chunk
    tls.sendall(http_response(banner))


def _handle(conn: socket.socket, ctx: ssl.SSLContext, banner: str | None = None) -> None:
    conn.settimeout(3)
    with suppress(OSError, ssl.SSLError):
        with ctx.wrap_socket(conn, server_side=True) as tls, suppress(OSError, ssl.SSLError):
            if banner is None:
                tls.recv(1)  # serviço TLS que não fala HTTP
            else:
                _answer_http(tls, banner)
        return
    with suppress(OSError):
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--duracao", type=float, default=0, help="segundos até parar (0 = até Ctrl+C)"
    )
    args = parser.parse_args(argv)

    if not (CERTS / "ca.pem").exists():
        print("Certificados ausentes: rode antes 'python lab/gerar_certificados.py'.")
        return 2
    if ssl.OPENSSL_VERSION_INFO < (3, 5):
        print(
            f"Aviso: {ssl.OPENSSL_VERSION} não tem ML-KEM; "
            "o caso híbrido vai aparecer como clássico."
        )

    stop = threading.Event()
    threads = []
    for name, (port, mode) in SERVICES.items():
        t = threading.Thread(
            target=serve, args=(name, port, make_context(mode, name), stop), daemon=True
        )
        t.start()
        threads.append(t)
        extra = f", Server: {BANNERS[name]}" if name in BANNERS else ""
        print(f"{name:13} 127.0.0.1:{port}  ({mode}{extra})")
    print(f"Laboratório no ar com {ssl.OPENSSL_VERSION}. Porta 8449 fica fechada de propósito.")
    sys.stdout.flush()

    try:
        deadline = time.monotonic() + args.duracao if args.duracao else None
        while deadline is None or time.monotonic() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    stop.set()
    for t in threads:
        t.join(timeout=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
