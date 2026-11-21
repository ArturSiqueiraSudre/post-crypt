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

SSH (Estágio 3): SSH_SERVICES imita servidores SSH. Cada um manda a linha de
identificação e o KEXINIT de um OpenSSH real (listas copiadas da
configuração padrão), espera o cliente e fecha: nada de troca de chave nem
login, como a sonda. No Docker, os mesmos dois casos rodam num OpenSSH de
verdade (lab/ssh/).
"""

from __future__ import annotations

import argparse
import socket
import ssl
import struct
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

# serviço SSH -> (porta, identificação, listas do KEXINIT)
SSH_HIBRIDO_KEX = [
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "ext-info-s",
    "kex-strict-s-v00@openssh.com",
]
SSH_CLASSICO_KEX = [
    "curve25519-sha256",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group14-sha1",
    "kex-strict-s-v00@openssh.com",
]
SSH_SERVICES = {
    "ssh-hibrido": (
        8447,
        "SSH-2.0-OpenSSH_10.6",
        {
            "kex": SSH_HIBRIDO_KEX,
            "host_key": ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
            "ciphers": [
                "chacha20-poly1305@openssh.com",
                "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com",
                "aes128-ctr",
                "aes192-ctr",
                "aes256-ctr",
            ],
        },
    ),
    "ssh-classico": (
        8448,
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13",
        {
            "kex": SSH_CLASSICO_KEX,
            "host_key": ["ssh-rsa", "rsa-sha2-512", "ssh-ed25519"],
            "ciphers": ["aes128-ctr", "aes256-ctr", "aes128-cbc"],
        },
    ),
}
SSH_MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256"]


def kexinit_packet(lists: dict[str, list[str]]) -> bytes:
    """KEXINIT sem cifra (RFC 4253, 6 e 7.1), montado aqui, sem usar o código da sonda."""
    ciphers, macs = lists["ciphers"], SSH_MACS
    name_lists = [
        lists["kex"], lists["host_key"], ciphers, ciphers, macs, macs,
        ["none", "zlib@openssh.com"], ["none", "zlib@openssh.com"], [], [],
    ]  # fmt: skip
    payload = bytes([20]) + bytes(16)
    for names in name_lists:
        text = ",".join(names).encode("ascii")
        payload += struct.pack("!I", len(text)) + text
    payload += b"\x00" + struct.pack("!I", 0)
    padding = 8 - ((5 + len(payload)) % 8)
    padding += 8 if padding < 4 else 0
    return struct.pack("!IB", 1 + len(payload) + padding, padding) + payload + bytes(padding)


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


def serve_ssh(port: int, identification: str, packet: bytes, stop: threading.Event) -> None:
    with socket.create_server(("127.0.0.1", port)) as srv:
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            threading.Thread(
                target=_handle_ssh, args=(conn, identification, packet), daemon=True
            ).start()


def _handle_ssh(conn: socket.socket, identification: str, packet: bytes) -> None:
    conn.settimeout(3)
    with suppress(OSError), conn:
        conn.sendall(identification.encode("ascii") + b"\r\n")
        received = b""
        while b"\n" not in received and len(received) < 256:
            chunk = conn.recv(256)
            if not chunk:
                return
            received += chunk
        conn.sendall(packet)
        conn.recv(1)  # espera o cliente fechar: nada de troca de chave


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
    for name, (port, identification, lists) in SSH_SERVICES.items():
        t = threading.Thread(
            target=serve_ssh,
            args=(port, identification, kexinit_packet(lists), stop),
            daemon=True,
        )
        t.start()
        threads.append(t)
        print(f"{name:13} 127.0.0.1:{port}  (SSH, {identification})")
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
