"""Gera a PKI do laboratório em lab/certs/ (ignorada pelo git).

Uso: python lab/gerar_certificados.py

Cria uma CA própria e um certificado por serviço, com validades escolhidas
para exercitar o classificador: normal, vencendo em 10 dias e vencido.
As chaves privadas nunca entram no repositório.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent / "certs"

# nome -> (tipo de chave, dias desde a emissão, dias até vencer)
SERVICES = {
    "tls-hibrido": ("ec", -1, 365),
    "tls-classico": ("ec", -1, 365),
    "tls-legado": ("rsa", -1, 365),
    "tls-vencendo": ("ec", -355, 10),
    "tls-vencido": ("ec", -400, -5),
}


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Post-Crypt Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def main() -> None:
    OUT.mkdir(exist_ok=True)
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("Post-Crypt Lab CA"))
        .issuer_name(_name("Post-Crypt Lab CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=500))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA384())
    )
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (OUT / "ca.pem").write_bytes(ca_pem)

    for name, (key_type, start, end) in SERVICES.items():
        key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            if key_type == "rsa"
            else ec.generate_private_key(ec.SECP256R1())
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(f"{name}.lab"))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + dt.timedelta(days=start))
            .not_valid_after(now + dt.timedelta(days=end))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(f"{name}.lab"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (OUT / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM) + ca_pem)
        key_path = OUT / f"{name}.key"
        key_path.write_bytes(_pem_key(key))
        key_path.chmod(0o644)  # legível pelo nginx dentro do contêiner; chave só de laboratório
        print(f"{name}: válido de {start} a {end} dias")


if __name__ == "__main__":
    main()
