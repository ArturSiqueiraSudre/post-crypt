"""Classificação de um serviço SSH a partir das regras em YAML.

Separado do classificador TLS (``classify.py``), mas responde às mesmas três
perguntas, com o mesmo formato de ``Assessment``, para que a tabela, o JSON,
o painel e a correlação de rede tratem TLS e SSH do mesmo jeito:

- troca de chave: o servidor aceita algum algoritmo pós-quântico híbrido? Um
  cliente moderno (OpenSSH 9.0+) escolhe o híbrido quando o servidor aceita;
- cifra simétrica: o servidor ainda aceita cifras fracas?
- autenticação: de que tipo são as chaves do servidor e até quando valem?

A sonda vê o que o servidor aceita, não o que foi negociado com um cliente
específico. Por isso os achados falam em "aceita", não em "usa".
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from postcrypt.classify import (
    HNDL,
    PQC,
    REVIEW,
    SEVERITY_ORDER,
    STATUS_LABELS,
    UNREACHABLE,
    Assessment,
    Finding,
)
from postcrypt.ssh.probe import SSHObservation

Rules = Mapping[str, object]
CERT_SUFFIX = "-cert-v01@openssh.com"


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in cast("Mapping[object, object]", value).items()}


def _ssh_section(rules: Rules, name: str) -> dict[str, object]:
    return _mapping(_mapping(rules.get("ssh")).get(name))


def _kex(obs: SSHObservation, rules: Rules, findings: list[Finding]) -> dict[str, object]:
    classes = _ssh_section(rules, "kex")
    pqc = [k for k in obs.kex if classes.get(k) in ("hybrid", "pure")]
    weak = [k for k in obs.kex if classes.get(k) == "weak"]
    classical = [k for k in obs.kex if classes.get(k) in ("classical", "weak")]
    unknown = [k for k in obs.kex if k not in classes]

    if weak:
        findings.append(
            Finding(
                "SSH_WEAK_KEX",
                "medium",
                "Aceita troca de chave fraca",
                f"{', '.join(weak)} já é fraco hoje, mesmo sem computador quântico. "
                "Remova da configuração do servidor (KexAlgorithms).",
            )
        )
    if pqc:
        return {
            "status": "pqc",
            "groups": pqc,
            "classical_group": classical[0] if classical else None,
            "detail": f"Aceita troca de chave pós-quântica híbrida: {', '.join(pqc)}.",
        }
    if classical:
        findings.append(
            Finding(
                "KX_CLASSICAL_ONLY",
                "high",
                "Troca de chave só clássica",
                f"O servidor só aceita {', '.join(classical[:3])}"
                + (" e outros clássicos" if len(classical) > 3 else "")
                + ". Sessões gravadas hoje podem ser decifradas por um computador quântico "
                "no futuro (Harvest Now, Decrypt Later). O OpenSSH 9.0 ou mais novo já "
                "oferece troca híbrida.",
            )
        )
        return {
            "status": "classical",
            "groups": [],
            "classical_group": classical[0],
            "detail": f"Só troca de chave clássica ({classical[0]}).",
        }
    if unknown:
        return {
            "status": "unknown",
            "groups": [],
            "classical_group": None,
            "detail": f"Algoritmos sem regra cadastrada: {', '.join(unknown[:5])}.",
        }
    return {"status": "unknown", "groups": [], "classical_group": None, "detail": "Não observado."}


def _symmetric(obs: SSHObservation, rules: Rules, findings: list[Finding]) -> dict[str, object]:
    table = _ssh_section(rules, "ciphers")
    if not obs.ciphers:
        return {"status": "unknown", "cipher": None, "detail": "Não observado."}
    rules_by_name = {c: _mapping(table.get(c)) for c in obs.ciphers}
    weak = [c for c, r in rules_by_name.items() if r.get("status") == "weak"]
    ok = [c for c, r in rules_by_name.items() if r.get("status") == "ok"]
    if weak:
        notes = sorted(
            {str(rules_by_name[c].get("note")) for c in weak if rules_by_name[c].get("note")}
        )
        findings.append(
            Finding(
                "SSH_WEAK_CIPHER",
                "medium",
                "Aceita cifra fraca",
                f"{', '.join(weak)}. {' '.join(notes)} "
                "Remova da configuração do servidor (Ciphers).",
            )
        )
    if not ok:
        return {
            "status": "weak" if weak else "unknown",
            "cipher": obs.ciphers[0],
            "detail": "Nenhuma cifra forte aceita." if weak else "Cifras sem regra cadastrada.",
        }
    # Um cliente atual escolhe uma cifra forte quando o servidor aceita: o status vem
    # dela. As fracas que ainda são aceitas viram o achado SSH_WEAK_CIPHER, acima.
    best = ok[0]
    note = rules_by_name[best].get("note")
    detail = "Cifra simétrica resistente a computador quântico."
    if weak:
        detail = f"{detail} Ainda aceita cifras fracas: {', '.join(weak)}."
    if isinstance(note, str):
        detail = f"{detail} {note}"
    return {"status": "ok", "cipher": best, "detail": detail}


def _host_key_rule(name: str, rules: Rules) -> dict[str, object]:
    base = name.removesuffix(CERT_SUFFIX)
    return _mapping(_ssh_section(rules, "host_keys").get(base))


def _authentication(
    obs: SSHObservation, rules: Rules, findings: list[Finding]
) -> dict[str, object]:
    if not obs.host_key:
        return {
            "status": "unknown",
            "certificate": None,
            "detail": "Chave do servidor não observada.",
        }
    public_keys = _mapping(rules.get("public_keys"))
    families: dict[str, str] = {}
    weak: list[str] = []
    for name in obs.host_key:
        rule = _host_key_rule(name, rules)
        family = rule.get("family")
        if isinstance(family, str):
            families.setdefault(family, name)
        reason = rule.get("weak")
        if isinstance(reason, str):
            weak.append(f"{name} ({reason})")
    summary = ", ".join(obs.host_key)
    if weak:
        findings.append(
            Finding(
                "SSH_WEAK_HOST_KEY",
                "medium",
                "Aceita assinatura de servidor fraca",
                f"{'; '.join(weak)}. Remova da configuração do servidor (HostKeyAlgorithms).",
            )
        )
    if not families:
        return {
            "status": "unknown",
            "certificate": summary,
            "detail": "Tipos de chave do servidor sem regra cadastrada.",
        }
    vulnerable = [
        f
        for f in families
        if _mapping(public_keys.get(f)).get("quantum_vulnerable", True) is not False
    ]
    if not vulnerable:
        return {
            "status": "pqc",
            "certificate": summary,
            "detail": "Chave do servidor com assinatura pós-quântica.",
        }
    deadlines = sorted(
        {
            int(d)
            for f in vulnerable
            if isinstance(d := _mapping(public_keys.get(f)).get("disallowed_after"), int)
        }
    )
    # O prazo que vale é o mais curto: com RSA e DSA juntos, a migração já está atrasada.
    when = f"proibida após {deadlines[0]}" if deadlines else "vulnerável a computador quântico"
    findings.append(
        Finding(
            "SSH_HOST_KEY_QUANTUM_VULNERABLE",
            "low",
            "Chave do servidor precisa migrar",
            f"O servidor se autentica com {', '.join(vulnerable)}: pelo NIST IR 8547 "
            f"(rascunho), {when}. Não expõe sessões já gravadas: o risco é de "
            "falsificação futura do servidor.",
        )
    )
    return {
        "status": "quantum_vulnerable",
        "certificate": summary,
        "detail": f"Assinatura clássica ({', '.join(vulnerable)}): {when}.",
    }


def classify_ssh(
    obs: SSHObservation | None, rules: Rules, *, error: str | None = None
) -> Assessment:
    """Avaliação de um alvo SSH. ``obs`` é None quando a conexão nem abriu."""
    unknown: dict[str, object] = {"status": "unknown", "detail": "Não observado."}
    if obs is None:
        finding = Finding(
            "UNREACHABLE",
            "medium",
            "Alvo sem resposta",
            f"Não foi possível conectar ({error or 'motivo desconhecido'}). "
            "O ativo continua no inventário como lacuna de visibilidade.",
        )
        return Assessment(
            UNREACHABLE, STATUS_LABELS[UNREACHABLE], unknown, unknown, unknown, [finding]
        )

    findings: list[Finding] = []
    if obs.not_ssh:
        findings.append(
            Finding(
                "NOT_SSH",
                "medium",
                "A porta não respondeu como SSH",
                "Confira se o protocolo do alvo no arquivo de escopo está certo.",
            )
        )
    elif obs.errors and not obs.kex:
        findings.append(
            Finding(
                "SSH_INCOMPLETE",
                "medium",
                "O servidor SSH não mandou a lista de algoritmos",
                f"{obs.errors[0].capitalize()}. Sem a lista não dá para avaliar a troca de chave.",
            )
        )
    kx = _kex(obs, rules, findings)
    sym = _symmetric(obs, rules, findings)
    auth = _authentication(obs, rules, findings)

    status = {"pqc": PQC, "classical": HNDL}.get(str(kx["status"]), REVIEW)
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return Assessment(status, STATUS_LABELS[status], kx, sym, auth, findings)
