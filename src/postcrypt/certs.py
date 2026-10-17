"""Leitura de certificados X.509 para o inventário."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

# OIDs de chave pública que o inventário precisa reconhecer mesmo quando a
# biblioteca local não sabe carregar a chave (ex.: ML-DSA com OpenSSL antigo).
PUBLIC_KEY_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}


@dataclass
class CertificateInfo:
    position: int  # 0 = certificado do servidor (folha)
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    days_to_expiry: int
    public_key_algorithm: str  # RSA, EC, Ed25519, ML-DSA-65...
    public_key_bits: int | None
    public_key_detail: str  # RSA-2048, EC secp256r1...
    signature_algorithm: str
    self_signed: bool
    sha256_fingerprint: str
    subject_alt_names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _public_key(cert: x509.Certificate) -> tuple[str, int | None, str]:
    oid = cert.public_key_algorithm_oid.dotted_string
    family = PUBLIC_KEY_OIDS.get(oid, oid)
    try:
        key = cert.public_key()
    except Exception:  # algoritmo que a biblioteca local não carrega
        return family, None, family
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size, f"EC {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456, "Ed448"
    return family, None, family


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names: list[str] = [str(n) for n in ext.value.get_values_for_type(x509.DNSName)]
    names += [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
    return names


def parse_certificate(der: bytes, position: int, now: datetime | None = None) -> CertificateInfo:
    now = now or datetime.now(UTC)
    cert = x509.load_der_x509_certificate(der)
    algorithm, bits, detail = _public_key(cert)
    sig_oid = cert.signature_algorithm_oid
    not_after = cert.not_valid_after_utc
    return CertificateInfo(
        position=position,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=not_after.isoformat(),
        days_to_expiry=int((not_after - now).total_seconds() // 86400),
        public_key_algorithm=algorithm,
        public_key_bits=bits,
        public_key_detail=detail,
        signature_algorithm=getattr(sig_oid, "_name", sig_oid.dotted_string),
        self_signed=cert.subject == cert.issuer,
        sha256_fingerprint=hashlib.sha256(der).hexdigest(),
        subject_alt_names=_sans(cert),
    )
