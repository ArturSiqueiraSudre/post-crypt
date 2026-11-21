"""Arquivo de escopo: a lista fechada do que a ferramenta pode contatar.

O Post-Crypt nunca descobre alvos sozinho. Cada serviço precisa estar listado
com host e porta explícitos, e o arquivo precisa dizer quem autorizou a
varredura e quando. Faixas de IP e curingas são recusados de propósito.

``protocol`` é ``tls`` (padrão) ou ``ssh`` (decisão 0003). Num alvo SSH não há
nome no certificado (``sni``) nem pedido HTTP (``http_fingerprint``).

``http_fingerprint`` é uma autorização à parte, alvo a alvo (decisão 0002):
só com ``true`` a ferramenta manda o único pedido HTTP mínimo que identifica
a versão do software. Sem o campo, o alvo é varrido só no TLS, como antes.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

import yaml

PROTOCOLS = ("tls", "ssh")
OWNERS = ("self", "third_party")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.?)+$")


class ScopeError(ValueError):
    """Arquivo de escopo inválido."""


@dataclass(frozen=True)
class Authorization:
    by: str
    date: str
    reference: str | None = None


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    protocol: str = "tls"
    label: str | None = None
    owner: str = "self"
    sni: str | None = None
    http_fingerprint: bool = False  # opt-in: 1 pedido HEAD / no mesmo host:porta

    @property
    def name(self) -> str:
        return self.label or f"{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Scope:
    authorization: Authorization
    targets: tuple[Target, ...]


def _validate_host(host: str, where: str) -> str:
    host = host.strip()
    if any(ch in host for ch in "/*?"):
        raise ScopeError(f"{where}: '{host}' parece faixa ou curinga; liste cada host")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOSTNAME.match(host):
        raise ScopeError(f"{where}: host inválido '{host}'")
    return host


def _parse_target(raw: object, index: int) -> Target:
    where = f"targets[{index}]"
    if not isinstance(raw, dict):
        raise ScopeError(f"{where}: esperado um mapa com host e port")
    unknown = set(raw) - {"host", "port", "protocol", "label", "owner", "sni", "http_fingerprint"}
    if unknown:
        raise ScopeError(f"{where}: campos desconhecidos {sorted(unknown)}")
    if "host" not in raw or "port" not in raw:
        raise ScopeError(f"{where}: host e port são obrigatórios")
    host = _validate_host(str(raw["host"]), where)
    port = raw["port"]
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ScopeError(f"{where}: porta inválida '{port}'")
    protocol = str(raw.get("protocol", "tls")).lower()
    if protocol not in PROTOCOLS:
        raise ScopeError(f"{where}: protocolo '{protocol}' não suportado ainda")
    owner = str(raw.get("owner", "self"))
    if owner not in OWNERS:
        raise ScopeError(f"{where}: owner deve ser 'self' ou 'third_party'")
    sni = raw.get("sni")
    http_fingerprint: object = cast("dict[str, object]", raw).get("http_fingerprint", False)
    if protocol == "ssh":
        # Campos que só fazem sentido em TLS são recusados, não ignorados em silêncio.
        if sni is not None:
            raise ScopeError(f"{where}: sni só vale para protocol: tls")
        if http_fingerprint is not False:
            raise ScopeError(f"{where}: http_fingerprint só vale para protocol: tls")
    elif sni is None:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            sni = host
    if not isinstance(http_fingerprint, bool):
        # Só booleano de verdade: "sim", 1 ou "true" entre aspas não autorizam nada.
        raise ScopeError(f"{where}: http_fingerprint deve ser true ou false, sem aspas")
    label = raw.get("label")
    return Target(
        host=host,
        port=port,
        protocol=protocol,
        label=str(label) if label is not None else None,
        owner=owner,
        sni=str(sni) if sni is not None else None,
        http_fingerprint=http_fingerprint,
    )


def parse_scope(data: object) -> Scope:
    if not isinstance(data, dict):
        raise ScopeError("o arquivo de escopo deve ser um mapa YAML")
    auth = data.get("authorization")
    if not isinstance(auth, dict) or not auth.get("by") or not auth.get("date"):
        raise ScopeError(
            "authorization.by e authorization.date são obrigatórios: "
            "registre quem autorizou a varredura e quando"
        )
    date = auth["date"]
    if isinstance(date, dt.date):
        date = date.isoformat()
    else:
        try:
            date = dt.date.fromisoformat(str(date)).isoformat()
        except ValueError as exc:
            raise ScopeError("authorization.date deve estar no formato AAAA-MM-DD") from exc
    authorization = Authorization(
        by=str(auth["by"]),
        date=date,
        reference=str(auth["reference"]) if auth.get("reference") else None,
    )

    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ScopeError("targets deve listar ao menos um serviço")
    targets = tuple(_parse_target(t, i) for i, t in enumerate(raw_targets))
    seen: set[tuple[str, int]] = set()
    for t in targets:
        if (t.host, t.port) in seen:
            raise ScopeError(f"alvo repetido: {t.host}:{t.port}")
        seen.add((t.host, t.port))
    return Scope(authorization=authorization, targets=targets)


def load_scope(path: str | Path) -> Scope:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ScopeError(f"não consegui ler {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ScopeError(f"YAML inválido em {path}: {exc}") from exc
    return parse_scope(data)
