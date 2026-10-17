"""PKI de teste: uma CA e certificados de servidor com validades controladas."""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


@dataclass
class IssuedCert:
    cert_path: Path
    key_path: Path
    cert: x509.Certificate


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Post-Crypt Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _write_key(key, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


class TestPKI:
    __test__ = False  # não é uma classe de teste do pytest

    def __init__(self, directory: Path):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.now = dt.datetime.now(dt.UTC)
        self.ca_key = ec.generate_private_key(ec.SECP384R1())
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(_name("Post-Crypt Lab CA"))
            .issuer_name(_name("Post-Crypt Lab CA"))
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.now - dt.timedelta(days=1))
            .not_valid_after(self.now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.ca_key, hashes.SHA384())
        )
        (self.dir / "ca.pem").write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def issue(
        self,
        name: str,
        *,
        key_type: str = "ec",
        valid_from_days: int = -1,
        valid_to_days: int = 365,
    ) -> IssuedCert:
        key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            if key_type == "rsa"
            else ec.generate_private_key(ec.SECP256R1())
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(name))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.now + dt.timedelta(days=valid_from_days))
            .not_valid_after(self.now + dt.timedelta(days=valid_to_days))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(name), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        cert_path = self.dir / f"{name}.pem"
        key_path = self.dir / f"{name}.key"
        cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
            + self.ca_cert.public_bytes(serialization.Encoding.PEM)
        )
        _write_key(key, key_path)
        return IssuedCert(cert_path, key_path, cert)
