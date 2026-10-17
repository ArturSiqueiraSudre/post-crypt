"""Classificação de cada serviço a partir das regras em YAML.

Três perguntas são respondidas separadamente, porque a confusão entre elas é a
objeção mais comum em campo ("já usamos AES-256"):

- troca de chave: o tráfego de hoje pode ser decifrado no futuro (HNDL)?
- cifra simétrica: o conteúdo cifrado aguenta um adversário quântico?
- autenticação: a assinatura do certificado precisa migrar, e até quando?
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from postcrypt.certs import CertificateInfo
from postcrypt.tls.probe import TLSObservation

# Status geral do serviço
PQC = "pqc"
HNDL = "hndl_vulnerable"
REVIEW = "review"
UNREACHABLE = "unreachable"

STATUS_LABELS = {
    PQC: "Híbrido PQC",
    HNDL: "Vulnerável a HNDL",
    REVIEW: "Revisar",
    UNREACHABLE: "Lacuna de visibilidade",
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Assessment:
    status: str
    status_label: str
    key_exchange: dict
    symmetric: dict
    authentication: dict
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


def load_rules(path: str | Path | None = None) -> dict:
    if path is None:
        text = resources.files("postcrypt.rules").joinpath("default.yaml").read_text("utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    rules = yaml.safe_load(text)
    if not isinstance(rules, dict) or rules.get("version") != 1:
        raise ValueError("arquivo de regras inválido ou de versão desconhecida")
    return rules


def _key_exchange(obs: TLSObservation, rules: dict, findings: list[Finding]) -> dict:
    classes = rules["key_exchange_groups"]
    pqc = [g for g in obs.pqc_groups if classes.get(g) in ("hybrid", "pure")]
    hybrid = [g for g in pqc if classes.get(g) == "hybrid"]
    obsolete = [g for g in obs.pqc_groups if classes.get(g) == "obsolete"]

    if obsolete:
        findings.append(
            Finding(
                "PQC_OBSOLETE_DRAFT",
                "medium",
                "Grupo pós-quântico pré-padrão ainda habilitado",
                f"{', '.join(obsolete)} é anterior ao FIPS 203; troque por X25519MLKEM768.",
            )
        )

    if pqc:
        kind = "híbrido" if hybrid else "ML-KEM puro"
        return {
            "status": "pqc",
            "groups": pqc,
            "classical_group": obs.classical_group,
            "detail": f"Aceita troca de chave pós-quântica ({kind}): {', '.join(pqc)}.",
        }

    if obs.tls13 or obs.tls12:
        used = obs.classical_group or obs.tls12_key_exchange or "desconhecido"
        findings.append(
            Finding(
                "KX_CLASSICAL_ONLY",
                "high",
                "Troca de chave só clássica",
                f"Negocia {used}. Tráfego gravado hoje pode ser decifrado por um "
                "computador quântico no futuro (Harvest Now, Decrypt Later).",
            )
        )
        if not obs.tls13:
            findings.append(
                Finding(
                    "NO_TLS13",
                    "medium",
                    "Sem TLS 1.3",
                    "Os grupos híbridos pós-quânticos só existem em TLS 1.3; "
                    "habilitar TLS 1.3 é pré-requisito da migração.",
                )
            )
        return {
            "status": "classical",
            "groups": [],
            "classical_group": obs.classical_group or obs.tls12_key_exchange,
            "detail": f"Só troca de chave clássica ({used}).",
        }

    return {"status": "unknown", "groups": [], "classical_group": None, "detail": "Não observado."}


def _symmetric(obs: TLSObservation, rules: dict, findings: list[Finding]) -> dict:
    table = rules["symmetric"]
    cipher = obs.tls13_symmetric or obs.tls12_symmetric
    if cipher is None:
        return {"status": "unknown", "cipher": None, "detail": "Não observado."}
    rule = table.get(cipher, {"status": "unknown"})
    note = rule.get("note")
    if rule["status"] == "weak":
        findings.append(Finding("SYMMETRIC_WEAK", "medium", f"Cifra fraca: {cipher}", note or ""))
    detail = (
        "Cifra simétrica resistente a computador quântico."
        if rule["status"] == "ok"
        else f"Cifra {cipher} precisa ser substituída."
    )
    if note:
        detail = f"{detail} {note}"
    return {"status": rule["status"], "cipher": cipher, "detail": detail}


def _authentication(certs: list[CertificateInfo], rules: dict, findings: list[Finding]) -> dict:
    if not certs:
        findings.append(
            Finding(
                "CERT_UNAVAILABLE",
                "medium",
                "Certificado não observado",
                "Não foi possível ler a cadeia; o registro de certificados fica incompleto.",
            )
        )
        return {"status": "unknown", "certificate": None, "detail": "Cadeia não observada."}

    warn_days = int(rules["certificates"]["expiry_warning_days"])
    for cert in certs:
        where = "do servidor" if cert.position == 0 else f"da cadeia (posição {cert.position})"
        if cert.days_to_expiry < 0:
            findings.append(
                Finding(
                    "CERT_EXPIRED",
                    "critical",
                    f"Certificado {where} vencido",
                    f"{cert.subject} venceu em {cert.not_after[:10]}.",
                )
            )
        elif cert.days_to_expiry <= warn_days:
            findings.append(
                Finding(
                    "CERT_EXPIRING",
                    "high",
                    f"Certificado {where} vence em {cert.days_to_expiry} dias",
                    f"{cert.subject} vence em {cert.not_after[:10]}; renove antes do prazo.",
                )
            )

    leaf = certs[0]
    rule = rules["public_keys"].get(leaf.public_key_algorithm)
    if rule is None:
        return {
            "status": "unknown",
            "certificate": leaf.public_key_detail,
            "detail": f"Algoritmo {leaf.public_key_algorithm} sem regra cadastrada.",
        }
    if not rule.get("quantum_vulnerable", True):
        return {
            "status": "pqc",
            "certificate": leaf.public_key_detail,
            "detail": f"Certificado com assinatura pós-quântica ({leaf.public_key_detail}).",
        }

    deadline = rule.get("disallowed_after")
    threshold = rule.get("deprecated_after_if_bits_below")
    if threshold and leaf.public_key_bits and leaf.public_key_bits < threshold["bits"]:
        when = f"depreciado após {threshold['year']} e proibido após {deadline}"
    else:
        when = f"proibido após {deadline}"
    findings.append(
        Finding(
            "CERT_KEY_QUANTUM_VULNERABLE",
            "low",
            f"Certificado {leaf.public_key_detail} precisa migrar",
            f"Pelo NIST IR 8547 (rascunho), {leaf.public_key_detail} será {when}. "
            "Não expõe tráfego já gravado: o risco é de falsificação futura.",
        )
    )
    return {
        "status": "quantum_vulnerable",
        "certificate": leaf.public_key_detail,
        "detail": f"Assinatura clássica ({leaf.public_key_detail}): {when}.",
    }


def classify(obs: TLSObservation | None, rules: dict, *, error: str | None = None) -> Assessment:
    """Gera a avaliação de um alvo. ``obs`` é None quando a conexão nem abriu."""
    if obs is None:
        finding = Finding(
            "UNREACHABLE",
            "medium",
            "Alvo sem resposta",
            f"Não foi possível conectar ({error or 'motivo desconhecido'}). "
            "O ativo continua no inventário como lacuna de visibilidade.",
        )
        unknown = {"status": "unknown", "detail": "Não observado."}
        return Assessment(
            UNREACHABLE, STATUS_LABELS[UNREACHABLE], unknown, unknown, unknown, [finding]
        )

    findings: list[Finding] = []
    if obs.not_tls:
        findings.append(
            Finding(
                "NOT_TLS",
                "medium",
                "A porta não respondeu como TLS",
                "Confira se o protocolo do alvo no arquivo de escopo está certo.",
            )
        )
    kx = _key_exchange(obs, rules, findings)
    sym = _symmetric(obs, rules, findings)
    auth = (
        _authentication(obs.certificates, rules, findings)
        if obs.tls13 or obs.tls12
        else {"status": "unknown", "certificate": None, "detail": "Não observado."}
    )
    if obs.rsa_key_transport:
        findings.append(
            Finding(
                "RSA_KEY_TRANSPORT",
                "high",
                "Aceita troca de chave RSA (sem sigilo futuro)",
                "Em TLS 1.2 com troca de chave RSA, quem obtiver a chave privada do "
                "certificado decifra todo o tráfego gravado, mesmo sem computador quântico.",
            )
        )

    if kx["status"] == "pqc":
        status = PQC
    elif kx["status"] == "classical":
        status = HNDL
    else:
        status = REVIEW
    label = STATUS_LABELS[status]
    if status == PQC and not any(
        rules["key_exchange_groups"].get(g) == "hybrid" for g in kx["groups"]
    ):
        label = "PQC puro"

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return Assessment(status, label, kx, sym, auth, findings)
