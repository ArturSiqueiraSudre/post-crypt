"""Classificador SSH: troca de chave, cifra e chave do servidor, a partir das regras."""

import copy

import pytest

from postcrypt.classify import HNDL, PQC, REVIEW, UNREACHABLE, load_rules
from postcrypt.classify_ssh import classify_ssh
from postcrypt.ssh.probe import SSHObservation

RULES = load_rules()


def obs(**kw):
    base = {
        "software": "OpenSSH_10.6",
        "protocol": "2.0",
        "kex": ["mlkem768x25519-sha256", "curve25519-sha256"],
        "host_key": ["ssh-ed25519"],
        "ciphers": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
    }
    return SSHObservation(**{**base, **kw})


def ids(assessment):
    return {f.id for f in assessment.findings}


# ---------- caminho feliz ----------


def test_servidor_moderno_e_pqc():
    a = classify_ssh(obs(), RULES)
    assert a.status == PQC and a.status_label == "Híbrido PQC"
    assert a.key_exchange["groups"] == ["mlkem768x25519-sha256"]
    assert a.key_exchange["classical_group"] == "curve25519-sha256"
    assert a.symmetric == {
        "status": "ok",
        "cipher": "chacha20-poly1305@openssh.com",
        "detail": "Cifra simétrica resistente a computador quântico.",
    }
    assert a.authentication["status"] == "quantum_vulnerable"
    assert ids(a) == {"SSH_HOST_KEY_QUANTUM_VULNERABLE"}


@pytest.mark.parametrize(
    "kex",
    ["sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512", "mlkem1024nistp384-sha384"],
)
def test_toda_troca_hibrida_conhecida_conta(kex):
    assert classify_ssh(obs(kex=[kex, "curve25519-sha256"]), RULES).status == PQC


def test_servidor_so_classico_e_hndl():
    a = classify_ssh(obs(kex=["curve25519-sha256", "ecdh-sha2-nistp256"]), RULES)
    assert a.status == HNDL and "KX_CLASSICAL_ONLY" in ids(a)
    assert a.key_exchange["classical_group"] == "curve25519-sha256"


def test_legado_gera_todos_os_achados_de_fraqueza():
    a = classify_ssh(
        obs(
            kex=["diffie-hellman-group1-sha1", "curve25519-sha256"],
            host_key=["ssh-rsa", "ssh-dss"],
            ciphers=["aes128-ctr", "3des-cbc", "arcfour"],
        ),
        RULES,
    )
    assert {"KX_CLASSICAL_ONLY", "SSH_WEAK_KEX", "SSH_WEAK_CIPHER", "SSH_WEAK_HOST_KEY"} <= ids(a)
    assert a.symmetric["status"] == "ok" and a.symmetric["cipher"] == "aes128-ctr"
    assert "3des-cbc" in a.symmetric["detail"]
    assert a.findings[0].severity == "high"  # ordenado do mais grave ao mais leve


def test_prazo_de_migracao_e_o_mais_curto_entre_as_chaves():
    a = classify_ssh(obs(host_key=["ssh-ed25519", "ssh-dss"]), RULES)
    assert "proibida após 2023" in a.authentication["detail"]
    so_moderna = classify_ssh(obs(host_key=["ssh-ed25519"]), RULES)
    assert "proibida após 2035" in so_moderna.authentication["detail"]


def test_so_troca_de_chave_fraca_tambem_e_classica():
    a = classify_ssh(obs(kex=["diffie-hellman-group1-sha1"]), RULES)
    assert a.status == HNDL
    assert {"KX_CLASSICAL_ONLY", "SSH_WEAK_KEX"} <= ids(a)
    assert a.key_exchange["classical_group"] == "diffie-hellman-group1-sha1"


def test_familia_sem_regra_de_chave_publica_conta_como_vulneravel():
    regras = copy.deepcopy(RULES)
    regras["ssh"]["host_keys"]["ssh-nova@exemplo"] = {"family": "FAMILIA-SEM-REGRA"}
    a = classify_ssh(obs(host_key=["ssh-nova@exemplo"]), regras)
    assert a.authentication["status"] == "quantum_vulnerable"
    assert "SSH_HOST_KEY_QUANTUM_VULNERABLE" in ids(a)


def test_certificado_ssh_conta_pela_chave_base():
    a = classify_ssh(obs(host_key=["ssh-ed25519-cert-v01@openssh.com"]), RULES)
    assert a.authentication["status"] == "quantum_vulnerable"


# ---------- limites e falhas ----------


def test_sem_conexao_e_lacuna_de_visibilidade():
    a = classify_ssh(None, RULES, error="recusado")
    assert a.status == UNREACHABLE and "recusado" in a.findings[0].detail


def test_porta_que_nao_e_ssh():
    a = classify_ssh(SSHObservation(not_ssh=True, errors=["x"]), RULES)
    assert a.status == REVIEW and "NOT_SSH" in ids(a)


def test_banner_sem_lista_de_algoritmos_e_revisar():
    a = classify_ssh(SSHObservation(software="OpenSSH_10.6", errors=["sem lista"]), RULES)
    assert a.status == REVIEW and "SSH_INCOMPLETE" in ids(a)


def test_so_cifras_fracas():
    a = classify_ssh(obs(ciphers=["aes128-cbc"]), RULES)
    assert a.symmetric["status"] == "weak" and "SSH_WEAK_CIPHER" in ids(a)


def test_algoritmos_sem_regra_nao_sao_dados_como_classicos():
    a = classify_ssh(
        obs(kex=["algo-novo@exemplo.com"], host_key=["chave-nova"], ciphers=["x"]), RULES
    )
    assert a.status == REVIEW
    assert a.key_exchange["status"] == "unknown" and "algo-novo" in a.key_exchange["detail"]
    assert a.authentication["status"] == "unknown" and a.symmetric["status"] == "unknown"


def test_regras_sem_secao_ssh_falham_fechado():
    regras = {k: v for k, v in RULES.items() if k != "ssh"}
    assert classify_ssh(obs(), regras).status == REVIEW


@pytest.mark.parametrize(
    "secao", ["texto", ["lista"], {"kex": "texto"}, {"kex": {"curve25519-sha256": 7}}]
)
def test_regras_ssh_malformadas_nao_quebram(secao):
    regras = {**RULES, "ssh": secao}
    assert classify_ssh(obs(kex=["curve25519-sha256"]), regras).status in (REVIEW, HNDL)


def test_chave_pos_quantica_cadastrada_nao_gera_achado():
    regras = copy.deepcopy(RULES)
    regras["ssh"]["host_keys"]["ssh-mldsa65@exemplo"] = {"family": "ML-DSA-65"}
    a = classify_ssh(obs(host_key=["ssh-mldsa65@exemplo"]), regras)
    assert a.authentication["status"] == "pqc" and not ids(a)


# ---------- entradas maliciosas ----------


def test_nome_hostil_aparece_so_como_texto_no_detalhe():
    a = classify_ssh(obs(kex=["<img src=x>"]), RULES)
    assert a.status == REVIEW and "<img src=x>" in a.key_exchange["detail"]


def test_lista_enorme_nao_estoura_o_texto_do_achado():
    a = classify_ssh(
        obs(kex=[f"curve25519-sha256-{i}" for i in range(100)] + ["curve25519-sha256"]), RULES
    )
    assert a.status == HNDL
    assert len(next(f for f in a.findings if f.id == "KX_CLASSICAL_ONLY").detail) < 400
