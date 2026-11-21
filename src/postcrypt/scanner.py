"""Orquestra a varredura: só contata os alvos do escopo, em paralelo.

Por alvo, conforme o ``protocol`` do escopo:

- TLS: sonda TLS, classificação e fingerprint de versão. O pedido HTTP do
  fingerprint só sai quando o alvo tem ``http_fingerprint: true`` e respondeu
  como TLS; quem faz o pedido é um adaptador injetável (``fetch_banner``).
- SSH: sonda SSH (banner + lista de algoritmos), classificação SSH e
  fingerprint pelo banner que a sonda já leu (decisão 0003).
"""

from __future__ import annotations

import platform
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime

from postcrypt import __version__
from postcrypt.classify import Assessment, classify
from postcrypt.classify_ssh import classify_ssh
from postcrypt.fingerprint import (
    Rules,
    ServiceFingerprint,
    fingerprint_ssh_banner,
    fingerprint_target,
)
from postcrypt.http_banner.parse import HTTPHeadError, HTTPResponseHead, parse_response_head
from postcrypt.http_banner.probe import BannerRequest, BannerUnavailable, fetch_banner
from postcrypt.scope import Scope, Target
from postcrypt.ssh.probe import SSHObservation, SSHProbe
from postcrypt.tls.probe import ProbeConnectionError, TLSObservation, TLSProbe

BannerFetcher = Callable[[BannerRequest], bytes]
SSHProber = Callable[[str, int, float], SSHObservation]


def probe_ssh(host: str, port: int, timeout: float) -> SSHObservation:
    return SSHProbe(host, port, timeout=timeout).run()


@dataclass
class TargetResult:
    target: Target
    reachable: bool
    duration_ms: int
    observation: TLSObservation | None
    assessment: Assessment
    error: str | None = None
    fingerprint: ServiceFingerprint | None = None
    ssh: SSHObservation | None = None  # só em alvos com protocol: ssh

    def to_dict(self) -> dict:
        return {
            "target": self.target.to_dict(),
            "reachable": self.reachable,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "tls": self.observation.to_dict() if self.observation else None,
            "ssh": self.ssh.to_dict() if self.ssh else None,
            "assessment": self.assessment.to_dict(),
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
        }


@dataclass
class ScanResult:
    scan_id: str
    started_at: str
    finished_at: str
    scope: Scope
    results: list[TargetResult] = field(default_factory=list)
    rules_version: str = ""

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.results:
            out[r.assessment.status] = out.get(r.assessment.status, 0) + 1
        return out

    def to_dict(self) -> dict:
        auth = self.scope.authorization
        return {
            "tool": {"name": "post-crypt", "version": __version__},
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "host": {"python": platform.python_version(), "system": platform.system()},
            "authorization": {"by": auth.by, "date": auth.date, "reference": auth.reference},
            "rules_version": self.rules_version,
            "summary": self.counts(),
            "results": [r.to_dict() for r in self.results],
        }


def _read_banner(
    target: Target, timeout: float, fetch: BannerFetcher
) -> tuple[HTTPResponseHead | None, str | None]:
    """O único pedido HTTP do alvo, já lido. Falha vira motivo em texto, nunca exceção."""
    request = BannerRequest(target.host, target.port, target.sni, timeout)
    try:
        return parse_response_head(fetch(request)), None
    except (BannerUnavailable, HTTPHeadError) as exc:
        return None, str(exc)  # mensagens nossas: nada do servidor vai para o relatório


def observe_fingerprint(
    target: Target,
    obs: TLSObservation | None,
    rules: Rules,
    timeout: float,
    fetch: BannerFetcher = fetch_banner,
) -> ServiceFingerprint:
    tls_reachable = obs is not None and (obs.tls13 or obs.tls12)
    head, error = None, None
    if target.http_fingerprint and tls_reachable:
        head, error = _read_banner(target, timeout, fetch)
    return fingerprint_target(
        authorized=target.http_fingerprint,
        tls_reachable=tls_reachable,
        server_hello=obs.server_hello if obs else None,
        head=head,
        http_error=error,
        rules=rules,
    )


def scan_ssh_target(
    target: Target, rules: Rules, timeout: float, *, probe: SSHProber = probe_ssh
) -> TargetResult:
    start = time.monotonic()
    try:
        obs = probe(target.host, target.port, timeout)
    except ProbeConnectionError as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return TargetResult(
            target,
            False,
            elapsed,
            None,
            classify_ssh(None, rules, error=str(exc)),
            str(exc),
            fingerprint_ssh_banner(reachable=False, software=None, comments=None, rules=rules),
        )
    elapsed = int((time.monotonic() - start) * 1000)
    fingerprint = fingerprint_ssh_banner(
        reachable=not obs.not_ssh, software=obs.software, comments=obs.comments, rules=rules
    )
    return TargetResult(
        target, True, elapsed, None, classify_ssh(obs, rules), fingerprint=fingerprint, ssh=obs
    )


def scan_target(
    target: Target,
    rules: dict,
    timeout: float,
    *,
    fetch: BannerFetcher = fetch_banner,
    ssh_probe: SSHProber = probe_ssh,
) -> TargetResult:
    if target.protocol == "ssh":
        return scan_ssh_target(target, rules, timeout, probe=ssh_probe)
    start = time.monotonic()
    probe = TLSProbe(target.host, target.port, sni=target.sni, timeout=timeout)
    try:
        obs = probe.run()
    except ProbeConnectionError as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return TargetResult(
            target,
            False,
            elapsed,
            None,
            classify(None, rules, error=str(exc)),
            str(exc),
            observe_fingerprint(target, None, rules, timeout, fetch),
        )
    fingerprint = observe_fingerprint(target, obs, rules, timeout, fetch)
    elapsed = int((time.monotonic() - start) * 1000)
    return TargetResult(target, True, elapsed, obs, classify(obs, rules), fingerprint=fingerprint)


def run_scan(
    scope: Scope,
    rules: dict,
    *,
    timeout: float = 5.0,
    workers: int = 8,
    on_result: Callable[[TargetResult], None] | None = None,
    fetch: BannerFetcher = fetch_banner,
    ssh_probe: SSHProber = probe_ssh,
) -> ScanResult:
    started = datetime.now(UTC)
    ordered: dict[int, TargetResult] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(scan_target, t, rules, timeout, fetch=fetch, ssh_probe=ssh_probe): i
            for i, t in enumerate(scope.targets)
        }
        for future, index in futures.items():
            result = future.result()
            ordered[index] = result
            if on_result:
                on_result(result)
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        started_at=started.isoformat(),
        finished_at=datetime.now(UTC).isoformat(),
        scope=scope,
        results=[ordered[i] for i in sorted(ordered)],
        rules_version=str(rules.get("updated", "")),
    )
