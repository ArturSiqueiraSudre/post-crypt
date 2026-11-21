"""Correlação de rede: o que só aparece ao comparar os alvos entre si.

O classificador avalia um alvo por vez. Este módulo lê a varredura inteira e
responde cinco perguntas que nenhum alvo isolado responde:

- uma mesma autoridade certificadora, de assinatura clássica, sustenta vários
  alvos (ponto único de falha)?
- o mesmo certificado está em mais de um alvo?
- que proporção dos ativos próprios está exposta a Harvest Now, Decrypt Later?
- quanto do escopo ficou sem visibilidade (sem resposta ou de terceiros)?
- a mesma versão de software, já sem suporte do fabricante, roda em vários
  alvos (fingerprint do Estágio 2)?

É lógica pura: não abre conexão, não lê disco e não coleta nada novo. Só usa
o que a varredura já observou e as mesmas regras em YAML do classificador.
A prioridade de cada achado é severidade × raio de impacto (quantos alvos ele
afeta), para que o que atinge muitos serviços de uma vez suba na lista.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING

from postcrypt.certs import CertificateInfo
from postcrypt.classify import HNDL, PQC, SEVERITY_ORDER, UNREACHABLE
from postcrypt.fingerprint import HEADER_LABELS, UNSUPPORTED, ProductVersion

if TYPE_CHECKING:
    from postcrypt.scanner import ScanResult, TargetResult

SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Usados quando o arquivo de regras (por exemplo um --rules antigo) não traz
# a seção "network".
DEFAULT_THRESHOLDS = {
    "hndl_exposure": {"high": 0.5, "medium": 0.25},
    "visibility_gap": {"high": 0.5, "medium": 0.25},
}
DEFAULT_SIGNATURE_FAMILIES = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "ml-dsa-44": "ML-DSA-44",
    "ml-dsa-65": "ML-DSA-65",
    "ml-dsa-87": "ML-DSA-87",
    "rsa": "RSA",
    "ecdsa": "EC",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
}

ACTIONS = {
    "NET_SHARED_CLASSICAL_CA": (
        "Inclua essa autoridade certificadora no plano de migração e combine com quem a "
        "opera a emissão com assinatura pós-quântica (ML-DSA). Enquanto isso, mantenha a "
        "lista dos serviços que dependem dela."
    ),
    "NET_SHARED_CA_UNCLASSIFIED": (
        "Cadastre o algoritmo dessa autoridade certificadora no arquivo de regras para que "
        "ela possa ser avaliada."
    ),
    "NET_DUPLICATE_LEAF": (
        "Confirme com os responsáveis se o reaproveitamento é intencional. Se não for, "
        "emita um certificado com chave própria para cada serviço."
    ),
    "NET_HNDL_EXPOSURE": (
        "Comece pelos serviços que carregam dados que precisam ficar sigilosos por muitos "
        "anos: habilite TLS 1.3 com o grupo híbrido X25519MLKEM768."
    ),
    "NET_VISIBILITY_GAP": (
        "Confira endereço e porta dos serviços que não responderam e peça ao fornecedor a "
        "postura criptográfica dos serviços dele."
    ),
    "NET_OUTDATED_VERSION": (
        "Atualize esse software para uma versão com suporte em todos os serviços listados, "
        "começando pelos que carregam dados sensíveis. Se ele vier de uma distribuição "
        "(Ubuntu, Debian, RHEL), confirme com quem mantém o sistema se as correções chegam "
        "sem mudar o número da versão."
    ),
}


@dataclass(frozen=True)
class NetworkFinding:
    id: str
    severity: str
    title: str
    detail: str
    action: str
    assets: tuple[str, ...]  # "host:porta" de cada alvo afetado
    blast_radius: int
    priority: int
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["assets"] = list(self.assets)
        return data


@dataclass(frozen=True)
class NetworkAssessment:
    total_targets: int
    findings: tuple[NetworkFinding, ...] = ()

    def to_dict(self) -> dict:
        return {
            "total_targets": self.total_targets,
            "findings": [f.to_dict() for f in self.findings],
        }


def asset_id(result: TargetResult) -> str:
    return f"{result.target.host}:{result.target.port}"


def _finding(
    finding_id: str, severity: str, title: str, detail: str, assets: list[str], evidence: dict
) -> NetworkFinding:
    return NetworkFinding(
        id=finding_id,
        severity=severity,
        title=title,
        detail=detail,
        action=ACTIONS[finding_id],
        assets=tuple(assets),
        blast_radius=len(assets),
        priority=SEVERITY_WEIGHT[severity] * len(assets),
        evidence=evidence,
    )


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _certificates(result: TargetResult) -> list[CertificateInfo]:
    return list(result.observation.certificates) if result.observation else []


def _leaf(result: TargetResult) -> CertificateInfo | None:
    return next((c for c in _certificates(result) if c.position == 0), None)


def _common_name(distinguished_name: str) -> str:
    for part in distinguished_name.split(","):
        key, _, value = part.strip().partition("=")
        if key.upper() == "CN" and value:
            return value
    return distinguished_name


def _signature_family(signature_algorithm: str, rules: dict) -> str | None:
    """Família de chave (RSA, EC...) de quem assinou, pelo nome do algoritmo."""
    families = rules.get("signature_families")
    if not isinstance(families, dict):
        families = DEFAULT_SIGNATURE_FAMILIES
    name = signature_algorithm.lower()
    for fragment, family in families.items():
        if str(fragment).lower() in name:
            return str(family)
    return None


def _quantum_vulnerable(family: str | None, rules: dict) -> bool | None:
    """True/False pela regra da família; None quando não há regra cadastrada."""
    public_keys = rules.get("public_keys")
    rule = public_keys.get(family) if isinstance(public_keys, dict) and family else None
    if not isinstance(rule, dict):
        return None
    return bool(rule.get("quantum_vulnerable", True))


def _ratio_severity(ratio: float, thresholds: dict, fallback: str = "low") -> str:
    for severity in SEVERITY_ORDER:
        limit = thresholds.get(severity)
        if isinstance(limit, int | float) and not isinstance(limit, bool) and ratio >= limit:
            return severity
    return fallback


def _thresholds(rules: dict, name: str) -> dict:
    section = rules.get("network")
    values = section.get(name) if isinstance(section, dict) else None
    return values if isinstance(values, dict) else DEFAULT_THRESHOLDS[name]


def _shared_ca(results: list[TargetResult], rules: dict) -> list[NetworkFinding]:
    """Alvos cujo certificado foi emitido pela mesma autoridade certificadora."""
    by_issuer: dict[str, list[TargetResult]] = {}
    for result in results:
        leaf = _leaf(result)
        if leaf is None or leaf.self_signed or not leaf.issuer:
            continue  # sem cadeia observada ou autoassinado: não há CA a relacionar
        by_issuer.setdefault(leaf.issuer, []).append(result)

    findings: list[NetworkFinding] = []
    for issuer, members in by_issuer.items():
        if len(members) < 2:
            continue
        # Preferência: o próprio certificado da CA, se algum alvo o enviou na
        # cadeia. Sem ele, a família sai do algoritmo com que a folha foi assinada.
        ca_cert = next(
            (
                c
                for m in members
                for c in _certificates(m)
                if c.position > 0 and c.subject == issuer
            ),
            None,
        )
        if ca_cert is not None:
            family: str | None = ca_cert.public_key_algorithm
            key_detail = ca_cert.public_key_detail
        else:
            signature = _leaf(members[0]).signature_algorithm  # type: ignore[union-attr]
            family = _signature_family(signature, rules)
            key_detail = f"assinatura {signature}"
        vulnerable = _quantum_vulnerable(family, rules)
        if vulnerable is False:
            continue  # CA já pós-quântica: compartilhar não é achado
        assets = [asset_id(m) for m in members]
        name = _common_name(issuer)
        evidence = {
            "ca_subject": issuer,
            "ca_key": key_detail,
            "ca_observed": ca_cert is not None,
        }
        count = _plural(len(members), "serviço", "serviços")
        if vulnerable is None:
            findings.append(
                _finding(
                    "NET_SHARED_CA_UNCLASSIFIED",
                    "info",
                    f"Autoridade certificadora de {count} não pôde ser avaliada",
                    f"{name} ({key_detail}) assina os certificados de {count}, mas o algoritmo "
                    "dela não tem regra cadastrada. Sem a regra, não dá para dizer se é um "
                    "ponto único de falha.",
                    assets,
                    evidence,
                )
            )
            continue
        findings.append(
            _finding(
                "NET_SHARED_CLASSICAL_CA",
                "medium",
                f"A mesma autoridade certificadora assina {count}",
                f"{name} ({key_detail}) assina os certificados de {count}. É um ponto único "
                "de falha: quando essa assinatura puder ser forjada, todos precisam ser "
                "reemitidos de uma vez.",
                assets,
                evidence,
            )
        )
    return findings


def _duplicate_leaf(results: list[TargetResult]) -> list[NetworkFinding]:
    """O mesmo certificado de servidor apresentado por mais de um alvo."""
    by_fingerprint: dict[str, list[TargetResult]] = {}
    for result in results:
        leaf = _leaf(result)
        if leaf is not None and leaf.sha256_fingerprint:
            by_fingerprint.setdefault(leaf.sha256_fingerprint, []).append(result)

    findings: list[NetworkFinding] = []
    for fingerprint, members in by_fingerprint.items():
        if len(members) < 2:
            continue
        leaf = _leaf(members[0])
        subject = leaf.subject if leaf else ""
        third_party = any(m.target.owner == "third_party" for m in members)
        count = _plural(len(members), "serviço", "serviços")
        findings.append(
            _finding(
                "NET_DUPLICATE_LEAF",
                "low",
                f"O mesmo certificado está em {count}",
                f"O certificado de {_common_name(subject)} aparece em {count}"
                + (", ao menos um deles de fornecedor" if third_party else "")
                + ". Confirme se o reaproveitamento é intencional: a mesma chave privada "
                "está em mais de um lugar.",
                [asset_id(m) for m in members],
                {"sha256_fingerprint": fingerprint, "subject": subject},
            )
        )
    return findings


def _hndl_exposure(results: list[TargetResult], rules: dict) -> list[NetworkFinding]:
    """Proporção dos ativos próprios avaliados que só fazem troca de chave clássica."""
    assessed = [
        r for r in results if r.target.owner == "self" and r.assessment.status in (PQC, HNDL)
    ]
    vulnerable = [r for r in assessed if r.assessment.status == HNDL]
    if not vulnerable:
        return []
    ratio = len(vulnerable) / len(assessed)
    percent = round(ratio * 100)
    return [
        _finding(
            "NET_HNDL_EXPOSURE",
            _ratio_severity(ratio, _thresholds(rules, "hndl_exposure")),
            f"{len(vulnerable)} de {_plural(len(assessed), 'serviço', 'serviços')} da empresa "
            f"{'pode' if len(vulnerable) == 1 else 'podem'} ter o tráfego aberto no futuro",
            f"{percent}% dos serviços da empresa que puderam ser avaliados só aceitam troca "
            "de chave clássica. O que trafega por eles hoje pode ser gravado e aberto no "
            "futuro (Harvest Now, Decrypt Later).",
            [asset_id(r) for r in vulnerable],
            {"vulnerable": len(vulnerable), "assessed": len(assessed), "ratio": round(ratio, 2)},
        )
    ]


def _visibility_gap(results: list[TargetResult], rules: dict) -> list[NetworkFinding]:
    """Alvos sem resposta ou de terceiros: partes do escopo que a empresa não enxerga."""
    unreachable = [r for r in results if r.assessment.status == UNREACHABLE]
    third_party = [r for r in results if r.target.owner == "third_party"]
    gaps = list({asset_id(r): r for r in [*unreachable, *third_party]}.values())
    if not gaps:
        return []
    ratio = len(gaps) / len(results)
    parts = []
    if unreachable:
        parts.append(_plural(len(unreachable), "serviço não respondeu", "serviços não responderam"))
    if third_party:
        parts.append(_plural(len(third_party), "é de fornecedor", "são de fornecedor"))
    return [
        _finding(
            "NET_VISIBILITY_GAP",
            _ratio_severity(ratio, _thresholds(rules, "visibility_gap")),
            f"{len(gaps)} de {_plural(len(results), 'serviço', 'serviços')} "
            f"{'ficou' if len(gaps) == 1 else 'ficaram'} sem visibilidade",
            f"{' e '.join(parts)}. Para {round(ratio * 100)}% da lista, a postura "
            "criptográfica depende de alguém de fora ou não pôde ser observada.",
            [asset_id(r) for r in gaps],
            {
                "unreachable": len(unreachable),
                "third_party": len(third_party),
                "total": len(results),
                "ratio": round(ratio, 2),
            },
        )
    ]


def _unsupported_products(result: TargetResult) -> list[ProductVersion]:
    fp = result.fingerprint
    if fp is None:
        return []
    return [p for p in fp.products if p.support == UNSUPPORTED and p.version]


def _outdated_version(results: list[TargetResult]) -> list[NetworkFinding]:
    """A mesma versão sem suporte, declarada pelo próprio servidor, em mais de um alvo."""
    groups: dict[tuple[str, str], list[tuple[TargetResult, ProductVersion]]] = {}
    for result in results:
        seen: set[tuple[str, str]] = set()
        for product in _unsupported_products(result):
            key = (product.key or product.name.lower(), str(product.version))
            if key not in seen:  # Server e X-Powered-By repetindo o mesmo produto contam uma vez
                seen.add(key)
                groups.setdefault(key, []).append((result, product))

    findings: list[NetworkFinding] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        product = members[0][1]
        label = f"{product.name} {product.version}"
        count = _plural(len(members), "serviço", "serviços")
        sources = sorted({HEADER_LABELS.get(p.source, p.source) for _, p in members})
        supported = f" (com suporte: {product.supported})" if product.supported else ""
        findings.append(
            _finding(
                "NET_OUTDATED_VERSION",
                "medium",
                f"{label}, sem suporte do fabricante, em {count}",
                f"{count.capitalize()} rodam {label}, versão "
                f"que o fabricante não corrige mais{supported}. Uma falha nova nessa versão "
                "atinge todos de uma vez. A versão vem do cabeçalho "
                f"{' e '.join(sources)}, declarado pelo próprio servidor.",
                [asset_id(r) for r, _ in members],
                {
                    "product": product.name,
                    "version": product.version,
                    "supported": product.supported,
                    "source": sources,
                },
            )
        )
    return findings


def analyze_network(scan: ScanResult, rules: dict) -> NetworkAssessment:
    """Relaciona os alvos de uma varredura. Com menos de dois alvos não há o que relacionar."""
    results = list(scan.results)
    if len(results) < 2:
        return NetworkAssessment(total_targets=len(results))
    findings = [
        *_shared_ca(results, rules),
        *_duplicate_leaf(results),
        *_hndl_exposure(results, rules),
        *_visibility_gap(results, rules),
        *_outdated_version(results),
    ]
    findings.sort(key=lambda f: (-f.priority, SEVERITY_ORDER.index(f.severity), f.id, f.assets))
    return NetworkAssessment(total_targets=len(results), findings=tuple(findings))
