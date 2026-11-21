"""Fingerprint de versão de serviço: o que está rodando do outro lado.

Lógica pura. Recebe o que já foi observado (o cabeçalho HTTP do único pedido
autorizado e a forma do ServerHello que a sonda TLS já recebeu) e as regras
em YAML. Não abre conexão nem lê disco.

Não julga a postura criptográfica, que é papel do ``classify.py``: só
identifica produto e versão e diz se o fabricante ainda corrige aquela
versão. Sem sinal suficiente, o resultado é "não observado", nunca um chute.

Dois sinais, de confiança diferente:

- cabeçalhos ``Server`` e ``X-Powered-By`` (o servidor declara o que é);
- assinatura da pilha TLS no estilo JA4S (versão, suíte e ordem das
  extensões do ServerHello). É heurística, com falsos positivos conhecidos:
  só vira nome de pilha quando a assinatura está cadastrada nas regras, e
  nunca gera achado sozinha.

As regras vêm de YAML e podem ser substituídas pelo usuário (``--rules``):
tudo o que é lido delas passa por ``_mapping``/``_strings`` e falha fechado.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from postcrypt.http_banner.parse import HTTPResponseHead
    from postcrypt.tls.probe import ServerHelloShape

Rules = Mapping[str, object]

# Situação do fingerprint de um alvo
OBSERVED = "observed"
NOT_OBSERVED = "not_observed"
NOT_AUTHORIZED = "not_authorized"
UNAVAILABLE = "unavailable"

# Suporte do fabricante à versão encontrada
SUPPORTED = "supported"
UNSUPPORTED = "unsupported"
UNKNOWN = "unknown"

SOURCE_HEADERS = ("server", "x-powered-by")  # ordem em que os produtos são listados
HEADER_LABELS = {"server": "Server", "x-powered-by": "X-Powered-By"}
MAX_PRODUCTS_PER_HEADER = 8
MAX_DISTRO_CHARS = 40
MAX_STACK_CHARS = 80

_TCHAR = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_PRODUCT_START = re.compile(r"[A-Za-z0-9]")
_VERSION = re.compile(r"(\d{1,6})((?:\.\d{1,6}){0,4})")
_SPEC_BRANCH = re.compile(r"\d{1,6}(?:\.\d{1,6}){0,4}")
_SPEC_MINIMUM = re.compile(r">=\s*(\d{1,6}(?:\.\d{1,6}){0,4})")
_TLS_VERSIONS = {0x0303: "12", 0x0304: "13"}

NOTE_HIDDEN_VERSION = (
    "O servidor esconde o número da versão, então não dá para dizer se ainda tem suporte."
)
NOTE_NO_RULE = "Produto sem regra cadastrada: a versão foi registrada, mas não avaliada."
NOTE_DISTRO = (
    "Pacotes de distribuição ({distro}) às vezes recebem correções sem mudar o número da "
    "versão: confirme com quem mantém o sistema."
)


@dataclass(frozen=True)
class ProductToken:
    """Um ``produto/versão`` como aparece no cabeçalho, ainda sem interpretação."""

    name: str
    version: str | None
    comment: str | None
    source: str  # nome do cabeçalho, minúsculo


@dataclass(frozen=True)
class ProductVersion:
    key: str | None  # entrada em rules.fingerprint.products; None = sem regra
    name: str
    version: str | None
    source: str
    support: str
    supported: str | None = None  # versões com suporte, em texto, para o relatório
    note: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "key": self.key,
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "support": self.support,
            "supported": self.supported,
            "note": self.note,
        }


@dataclass(frozen=True)
class TLSStack:
    signature: str
    stack: str | None  # nome da pilha só quando a assinatura está nas regras
    basis: str  # "server_hello" ou "hello_retry_request"

    def to_dict(self) -> dict[str, str | None]:
        return {"signature": self.signature, "stack": self.stack, "basis": self.basis}


@dataclass(frozen=True)
class HTTPEvidence:
    requested: bool
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict[str, str])
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "requested": self.requested,
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "error": self.error,
        }


@dataclass(frozen=True)
class ServiceFingerprint:
    status: str
    detail: str
    http: HTTPEvidence
    products: tuple[ProductVersion, ...] = ()
    tls_stack: TLSStack | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "detail": self.detail,
            "http": self.http.to_dict(),
            "products": [p.to_dict() for p in self.products],
            "tls_stack": self.tls_stack.to_dict() if self.tls_stack else None,
        }


# ---------- leitura defensiva das regras ----------


def _mapping(value: object) -> dict[str, object]:
    """Mapa de texto -> valor; qualquer outra coisa vira mapa vazio."""
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in cast("Mapping[object, object]", value).items()}


def _strings(value: object) -> list[str]:
    """Lista de textos; itens que não são texto são descartados."""
    if not isinstance(value, list):
        return []
    return [v for v in cast("list[object]", value) if isinstance(v, str)]


def _section(rules: Rules, name: str) -> dict[str, object]:
    return _mapping(_mapping(rules.get("fingerprint")).get(name))


# ---------- cabeçalhos: produto/versão ----------


def _read_token(value: str, pos: int) -> tuple[str, int]:
    start = pos
    while pos < len(value) and value[pos] in _TCHAR:
        pos += 1
    return value[start:pos], pos


def _read_comment(value: str, pos: int) -> tuple[str, int]:
    """Comentário entre parênteses, com aninhamento, a partir do '('.

    A leitura é linear no tamanho do valor (já limitado pelo parser HTTP), então
    o aninhamento não precisa de teto. Sem fechamento, o resto é descartado.
    """
    depth, start = 0, pos + 1
    while pos < len(value):
        char = value[pos]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return value[start:pos], pos + 1
        pos += 1
    return value[start:pos], len(value)


def parse_product_tokens(value: str, source: str) -> list[ProductToken]:
    """Lê ``produto/versão (comentário)`` na gramática de ``Server`` da RFC 9110."""
    tokens: list[ProductToken] = []
    pending: tuple[str, str | None] | None = None
    pos = 0
    while pos < len(value) and len(tokens) < MAX_PRODUCTS_PER_HEADER:
        char = value[pos]
        if char in " \t":
            pos += 1
        elif char == "(":
            comment, pos = _read_comment(value, pos)
            if pending is not None:
                tokens.append(ProductToken(pending[0], pending[1], comment.strip() or None, source))
                pending = None
        elif char in _TCHAR:
            if pending is not None:
                tokens.append(ProductToken(pending[0], pending[1], None, source))
            name, pos = _read_token(value, pos)
            version = None
            if pos < len(value) and value[pos] == "/":
                version, pos = _read_token(value, pos + 1)
            # Nome de produto começa com letra ou dígito: "'" ou "--" sozinhos são ruído.
            pending = (name, version or None) if _PRODUCT_START.match(name) else None
        else:
            pos += 1  # caractere fora da gramática: ignorado, nunca interpretado
    if pending is not None and len(tokens) < MAX_PRODUCTS_PER_HEADER:
        tokens.append(ProductToken(pending[0], pending[1], None, source))
    return tokens


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """Parte numérica inicial de uma versão: '1.18.0-ubuntu' -> (1, 18, 0)."""
    if not text:
        return None
    match = _VERSION.match(text)
    if match is None:
        return None
    parts = [match.group(1), *[p for p in match.group(2).split(".") if p]]
    return tuple(int(p) for p in parts)


def _padded(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    size = max(len(a), len(b))
    return a + (0,) * (size - len(a)), b + (0,) * (size - len(b))


def _matches(version: tuple[int, ...], spec: str) -> bool | None:
    """True/False quando a regra é legível; None quando está fora do formato."""
    spec = spec.strip()
    minimum = _SPEC_MINIMUM.fullmatch(spec)
    if minimum:
        have, need = _padded(version, parse_version(minimum.group(1)) or ())
        return have >= need
    if _SPEC_BRANCH.fullmatch(spec):
        branch = parse_version(spec) or ()
        return version[: len(branch)] == branch
    return None


def evaluate_support(version: tuple[int, ...] | None, specs: object) -> str:
    """Compara a versão com a lista ``supported`` da regra. Regra ilegível nunca aprova."""
    if version is None:
        return UNKNOWN
    verdicts = [_matches(version, s) for s in _strings(specs)]
    readable = [v for v in verdicts if v is not None]
    if not readable:
        return UNKNOWN
    return SUPPORTED if any(readable) else UNSUPPORTED


def _find_rule(name: str, rules: Rules) -> tuple[str, dict[str, object]] | None:
    wanted = name.lower()
    for key, value in _section(rules, "products").items():
        rule = _mapping(value)
        if wanted in {n.lower() for n in _strings(rule.get("tokens"))}:
            return key, rule
    return None


def _describe_specs(specs: object) -> str | None:
    parts: list[str] = []
    for spec in _strings(specs):
        minimum = _SPEC_MINIMUM.fullmatch(spec.strip())
        if minimum:
            parts.append(f"{minimum.group(1)} ou mais nova")
        elif _SPEC_BRANCH.fullmatch(spec.strip()):
            parts.append(f"{spec.strip()}.x")
    return " ou ".join(parts) or None


def distribution(comment: str | None, rules: Rules) -> str | None:
    """Nome da distribuição citada no comentário, se estiver na lista das regras.

    "(Ubuntu)" e "(Red Hat Enterprise Linux)" contam; "(Win64)" não, porque não é
    pacote de distribuição e não recebe correção sem mudar a versão.
    """
    if not comment:
        return None
    section = _mapping(rules.get("fingerprint"))
    lowered = comment.lower()
    for name in _strings(section.get("distributions")):
        if name.strip() and name.strip().lower() in lowered:
            return name.strip()[:MAX_DISTRO_CHARS]
    return None


def _note(
    support: str, version: str | None, distro: str | None, rule: Mapping[str, object] | None
) -> str | None:
    if rule is None:
        return NOTE_NO_RULE
    if version is None:
        return NOTE_HIDDEN_VERSION
    if support != UNSUPPORTED:
        return None
    notes: list[str] = []
    extra = rule.get("note")
    if isinstance(extra, str) and extra.strip():
        notes.append(extra.strip())
    if distro:
        notes.append(NOTE_DISTRO.format(distro=distro))
    return " ".join(notes) or None


def identify_product(
    token: ProductToken, rules: Rules, distro: str | None = None
) -> ProductVersion:
    """``distro`` vale para todos os produtos do cabeçalho (ex.: Apache e OpenSSL do Ubuntu)."""
    found = _find_rule(token.name, rules)
    if found is None:
        return ProductVersion(
            None,
            token.name,
            token.version,
            token.source,
            UNKNOWN,
            note=_note(UNKNOWN, None, None, None),
        )
    key, rule = found
    specs = rule.get("supported")
    support = evaluate_support(parse_version(token.version), specs)
    label = rule.get("label")
    return ProductVersion(
        key=key,
        name=label if isinstance(label, str) and label else token.name,
        version=token.version,
        source=token.source,
        support=support,
        supported=_describe_specs(specs),
        note=_note(support, token.version, distro, rule),
    )


def identify_products(head: HTTPResponseHead, rules: Rules) -> tuple[ProductVersion, ...]:
    """Produtos declarados nos cabeçalhos de software, sem repetição."""
    seen: set[tuple[str, str | None]] = set()
    products: list[ProductVersion] = []
    for header in SOURCE_HEADERS:
        value = head.headers.get(header)
        if not value:
            continue
        tokens = parse_product_tokens(value, header)
        # "Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13": o comentário fala do pacote inteiro.
        distro = next((d for t in tokens if (d := distribution(t.comment, rules))), None)
        for token in tokens:
            product = identify_product(token, rules, distro)
            identity = (product.key or product.name.lower(), product.version)
            if identity not in seen:
                seen.add(identity)
                products.append(product)
    return tuple(products)


# ---------- pilha TLS: assinatura estilo JA4S ----------


def tls_stack_signature(shape: ServerHelloShape) -> str:
    """Assinatura no layout do JA4S, por exemplo ``t120300_c02f_1a2b3c4d5e6f``.

    Partes: protocolo (``t``), versão TLS (``12``/``13``), número de extensões,
    ALPN (``00``: o ClientHello da sonda não oferece ALPN), suíte escolhida e
    os 12 primeiros dígitos do SHA-256 da lista ordenada como chegou. Para
    HelloRetryRequest o prefixo é ``h`` em vez de ``t``.
    """
    prefix = "h" if shape.kind == "hello_retry_request" else "t"
    version = _TLS_VERSIONS.get(shape.version, "00")
    count = min(len(shape.extensions), 99)
    joined = ",".join(f"{e:04x}" for e in shape.extensions).encode("ascii")
    digest = hashlib.sha256(joined).hexdigest()[:12]
    return f"{prefix}{version}{count:02d}00_{shape.cipher_suite & 0xFFFF:04x}_{digest}"


def identify_tls_stack(shape: ServerHelloShape, rules: Rules) -> TLSStack:
    signature = tls_stack_signature(shape)
    label = _section(rules, "tls_stacks").get(signature)
    stack = label.strip()[:MAX_STACK_CHARS] if isinstance(label, str) and label.strip() else None
    return TLSStack(signature=signature, stack=stack, basis=shape.kind)


# ---------- decisão por alvo ----------


def _summary(products: tuple[ProductVersion, ...]) -> str:
    named = ", ".join(f"{p.name} {p.version}" if p.version else p.name for p in products)
    unsupported = [p for p in products if p.support == UNSUPPORTED]
    text = f"O servidor se identificou como {named}."
    if unsupported:
        names = ", ".join(f"{p.name} {p.version}" for p in unsupported)
        text += f" Sem suporte do fabricante: {names}."
    return text


def _stack_sentence(stack: TLSStack | None) -> str:
    """Só menciona a pilha quando a assinatura está nas regras; sem isso, nada a dizer."""
    if stack is None or not stack.stack:
        return ""
    return f" Pilha TLS provável, por assinatura: {stack.stack} (estimativa)."


def fingerprint_target(
    *,
    authorized: bool,
    tls_reachable: bool,
    server_hello: ServerHelloShape | None,
    head: HTTPResponseHead | None,
    http_error: str | None,
    rules: Rules,
) -> ServiceFingerprint:
    """Junta os sinais de um alvo. ``head`` só existe quando o pedido HTTP foi feito e lido."""
    if not tls_reachable:
        return ServiceFingerprint(
            UNAVAILABLE,
            "Sem conexão TLS com o serviço: não há o que identificar.",
            HTTPEvidence(requested=False),
        )
    stack = identify_tls_stack(server_hello, rules) if server_hello else None
    if not authorized:
        return ServiceFingerprint(
            NOT_AUTHORIZED,
            "A identificação por HTTP não foi autorizada para este serviço "
            "(http_fingerprint no escopo)." + _stack_sentence(stack),
            HTTPEvidence(requested=False),
            tls_stack=stack,
        )
    if head is None:
        reason = http_error or "o pedido HTTP não teve resposta"
        return ServiceFingerprint(
            NOT_OBSERVED,
            f"Versão não observada: {reason}." + _stack_sentence(stack),
            HTTPEvidence(requested=True, error=reason),
            tls_stack=stack,
        )
    evidence = HTTPEvidence(True, head.status_code, dict(head.headers))
    products = identify_products(head, rules)
    if not products:
        return ServiceFingerprint(
            NOT_OBSERVED,
            "Versão não observada: o servidor respondeu ao HTTP sem dizer qual software usa."
            + _stack_sentence(stack),
            evidence,
            tls_stack=stack,
        )
    return ServiceFingerprint(
        OBSERVED, _summary(products) + _stack_sentence(stack), evidence, products, stack
    )
