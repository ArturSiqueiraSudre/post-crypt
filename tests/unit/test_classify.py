"""Regras de classificação: troca de chave, cifra e autenticação separadas."""

from postcrypt.certs import CertificateInfo
from postcrypt.classify import HNDL, PQC, REVIEW, UNREACHABLE, classify, load_rules
from postcrypt.tls.probe import TLSObservation

RULES = load_rules()


def _cert(algorithm="EC", bits=256, detail="EC secp256r1", days=200, position=0):
    return CertificateInfo(
        position=position,
        subject="CN=svc",
        issuer="CN=ca",
        serial="1",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-05-01T00:00:00+00:00",
        days_to_expiry=days,
        public_key_algorithm=algorithm,
        public_key_bits=bits,
        public_key_detail=detail,
        signature_algorithm="ecdsa-with-SHA256",
        self_signed=False,
        sha256_fingerprint="00",
    )


def _ids(assessment):
    return {f.id for f in assessment.findings}


def test_hybrid_service_is_pqc_and_symmetric_is_separate():
    obs = TLSObservation(
        tls13=True,
        tls13_symmetric="AES_256_GCM",
        classical_group="x25519",
        pqc_groups=["X25519MLKEM768"],
        certificates=[_cert()],
    )
    a = classify(obs, RULES)
    assert a.status == PQC and a.status_label == "Híbrido PQC"
    assert a.symmetric["status"] == "ok"
    assert a.authentication["status"] == "quantum_vulnerable"
    assert "KX_CLASSICAL_ONLY" not in _ids(a)


def test_aes256_with_classical_exchange_is_still_hndl():
    """A objeção "já usamos AES-256" não muda o veredito."""
    obs = TLSObservation(
        tls13=True,
        tls13_symmetric="AES_256_GCM",
        classical_group="x25519",
        certificates=[_cert()],
    )
    a = classify(obs, RULES)
    assert a.status == HNDL
    assert a.symmetric["status"] == "ok"
    assert "KX_CLASSICAL_ONLY" in _ids(a)


def test_pure_mlkem_label():
    obs = TLSObservation(tls13=True, pqc_groups=["MLKEM1024"], certificates=[_cert()])
    assert classify(obs, RULES).status_label == "PQC puro"


def test_tls12_rsa_transport_and_expired_cert():
    obs = TLSObservation(
        tls12=True,
        tls12_key_exchange="RSA",
        tls12_symmetric="AES_256_GCM",
        rsa_key_transport=True,
        certificates=[_cert("RSA", 2048, "RSA-2048", days=-3)],
    )
    a = classify(obs, RULES)
    assert a.status == HNDL
    assert {"RSA_KEY_TRANSPORT", "NO_TLS13", "CERT_EXPIRED"} <= _ids(a)
    assert a.findings[0].id == "CERT_EXPIRED"  # mais grave primeiro
    assert "2030" in a.authentication["detail"]  # RSA-2048: depreciado após 2030


def test_expiring_certificate_threshold():
    obs = TLSObservation(tls13=True, classical_group="x25519", certificates=[_cert(days=30)])
    assert "CERT_EXPIRING" in _ids(classify(obs, RULES))
    obs.certificates = [_cert(days=31)]
    assert "CERT_EXPIRING" not in _ids(classify(obs, RULES))


def test_obsolete_kyber_draft_does_not_count_as_pqc():
    """Clientes atuais não negociam mais o rascunho Kyber: na prática, é clássico."""
    obs = TLSObservation(
        tls13=True,
        classical_group="x25519",
        pqc_groups=["X25519Kyber768Draft00"],
        certificates=[_cert()],
    )
    a = classify(obs, RULES)
    assert a.status == HNDL
    assert {"PQC_OBSOLETE_DRAFT", "KX_CLASSICAL_ONLY"} <= _ids(a)


def test_unreachable_is_a_visibility_gap_not_an_omission():
    a = classify(None, RULES, error="Connection refused")
    assert a.status == UNREACHABLE
    assert a.status_label == "Lacuna de visibilidade"
    assert "Connection refused" in a.findings[0].detail


def test_not_tls_needs_review():
    a = classify(TLSObservation(not_tls=True), RULES)
    assert a.status == REVIEW and "NOT_TLS" in _ids(a)


def test_mldsa_certificate_is_pqc():
    obs = TLSObservation(
        tls13=True,
        pqc_groups=["X25519MLKEM768"],
        certificates=[_cert("ML-DSA-65", None, "ML-DSA-65")],
    )
    assert classify(obs, RULES).authentication["status"] == "pqc"
