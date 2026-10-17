"""Code points TLS usados pela sonda.

Fontes: registros IANA "TLS Supported Groups", "TLS Cipher Suites" e
"TLS SignatureScheme". Os grupos híbridos seguem draft-ietf-tls-ecdhe-mlkem e
os puros, draft-connolly-tls-mlkem-key-agreement.
"""

from __future__ import annotations

# --- Grupos de troca de chave (supported_groups / key_share) ---------------

GROUPS: dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
}

GROUP_IDS: dict[str, int] = {name: code for code, name in GROUPS.items()}

CLASSICAL_GROUPS: tuple[int, ...] = (
    0x001D,
    0x0017,
    0x0018,
    0x0019,
    0x001E,
    0x0100,
    0x0101,
    0x0102,
    0x0103,
    0x0104,
)

# Ordem de preferência ao enumerar: híbridos padronizados primeiro.
PQC_GROUPS: tuple[int, ...] = (
    0x11EC,
    0x11EB,
    0x11ED,
    0x0200,
    0x0201,
    0x0202,
    0x6399,
)

# --- Suítes de cifra ---------------------------------------------------------
# código -> (nome OpenSSL/IANA, troca de chave, cifra simétrica)

TLS13_SUITES: dict[int, tuple[str, str, str]] = {
    0x1301: ("TLS_AES_128_GCM_SHA256", "tls13", "AES_128_GCM"),
    0x1302: ("TLS_AES_256_GCM_SHA384", "tls13", "AES_256_GCM"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "tls13", "CHACHA20_POLY1305"),
    0x1304: ("TLS_AES_128_CCM_SHA256", "tls13", "AES_128_CCM"),
}

TLS12_SUITES: dict[int, tuple[str, str, str]] = {
    0xC02C: ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE", "AES_256_GCM"),
    0xC02B: ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE", "AES_128_GCM"),
    0xCCA9: ("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE", "CHACHA20_POLY1305"),
    0xC030: ("ECDHE-RSA-AES256-GCM-SHA384", "ECDHE", "AES_256_GCM"),
    0xC02F: ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", "AES_128_GCM"),
    0xCCA8: ("ECDHE-RSA-CHACHA20-POLY1305", "ECDHE", "CHACHA20_POLY1305"),
    0xC028: ("ECDHE-RSA-AES256-SHA384", "ECDHE", "AES_256_CBC"),
    0xC027: ("ECDHE-RSA-AES128-SHA256", "ECDHE", "AES_128_CBC"),
    0xC014: ("ECDHE-RSA-AES256-SHA", "ECDHE", "AES_256_CBC"),
    0xC013: ("ECDHE-RSA-AES128-SHA", "ECDHE", "AES_128_CBC"),
    0x009F: ("DHE-RSA-AES256-GCM-SHA384", "DHE", "AES_256_GCM"),
    0x009E: ("DHE-RSA-AES128-GCM-SHA256", "DHE", "AES_128_GCM"),
    0xCCAA: ("DHE-RSA-CHACHA20-POLY1305", "DHE", "CHACHA20_POLY1305"),
    0x009D: ("AES256-GCM-SHA384", "RSA", "AES_256_GCM"),
    0x009C: ("AES128-GCM-SHA256", "RSA", "AES_128_GCM"),
    0x003D: ("AES256-SHA256", "RSA", "AES_256_CBC"),
    0x003C: ("AES128-SHA256", "RSA", "AES_128_CBC"),
    0x0035: ("AES256-SHA", "RSA", "AES_256_CBC"),
    0x002F: ("AES128-SHA", "RSA", "AES_128_CBC"),
    0x000A: ("DES-CBC3-SHA", "RSA", "3DES_EDE_CBC"),
}

RSA_KEY_TRANSPORT_SUITES: tuple[int, ...] = tuple(
    code for code, (_, kx, _) in TLS12_SUITES.items() if kx == "RSA"
)

# --- Esquemas de assinatura oferecidos --------------------------------------

SIGNATURE_SCHEMES: tuple[int, ...] = (
    0x0905,  # mldsa65
    0x0904,  # mldsa44
    0x0906,  # mldsa87
    0x0403,  # ecdsa_secp256r1_sha256
    0x0503,  # ecdsa_secp384r1_sha384
    0x0603,  # ecdsa_secp521r1_sha512
    0x0807,  # ed25519
    0x0808,  # ed448
    0x0804,  # rsa_pss_rsae_sha256
    0x0805,  # rsa_pss_rsae_sha384
    0x0806,  # rsa_pss_rsae_sha512
    0x0809,  # rsa_pss_pss_sha256
    0x080A,  # rsa_pss_pss_sha384
    0x080B,  # rsa_pss_pss_sha512
    0x0401,  # rsa_pkcs1_sha256
    0x0501,  # rsa_pkcs1_sha384
    0x0601,  # rsa_pkcs1_sha512
    0x0203,  # ecdsa_sha1
    0x0201,  # rsa_pkcs1_sha1
)

# --- Versões e alertas -------------------------------------------------------

TLS_VERSIONS: dict[int, str] = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

ALERTS: dict[int, str] = {
    0: "close_notify",
    10: "unexpected_message",
    40: "handshake_failure",
    47: "illegal_parameter",
    50: "decode_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    120: "no_application_protocol",
}

# Valor especial de ServerHello.random que identifica um HelloRetryRequest
# (RFC 8446, seção 4.1.3): SHA-256("HelloRetryRequest").
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def group_name(code: int) -> str:
    return GROUPS.get(code, f"0x{code:04x}")


def suite_info(code: int) -> tuple[str, str, str]:
    if code in TLS13_SUITES:
        return TLS13_SUITES[code]
    if code in TLS12_SUITES:
        return TLS12_SUITES[code]
    return (f"0x{code:04x}", "unknown", "unknown")
