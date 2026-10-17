"""Orquestra a varredura: só contata os alvos do escopo, em paralelo."""

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
from postcrypt.scope import Scope, Target
from postcrypt.tls.probe import ProbeConnectionError, TLSObservation, TLSProbe


@dataclass
class TargetResult:
    target: Target
    reachable: bool
    duration_ms: int
    observation: TLSObservation | None
    assessment: Assessment
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target.to_dict(),
            "reachable": self.reachable,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "tls": self.observation.to_dict() if self.observation else None,
            "assessment": self.assessment.to_dict(),
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


def scan_target(target: Target, rules: dict, timeout: float) -> TargetResult:
    start = time.monotonic()
    probe = TLSProbe(target.host, target.port, sni=target.sni, timeout=timeout)
    try:
        obs = probe.run()
    except ProbeConnectionError as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return TargetResult(
            target, False, elapsed, None, classify(None, rules, error=str(exc)), str(exc)
        )
    elapsed = int((time.monotonic() - start) * 1000)
    return TargetResult(target, True, elapsed, obs, classify(obs, rules))


def run_scan(
    scope: Scope,
    rules: dict,
    *,
    timeout: float = 5.0,
    workers: int = 8,
    on_result: Callable[[TargetResult], None] | None = None,
) -> ScanResult:
    started = datetime.now(UTC)
    ordered: dict[int, TargetResult] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(scan_target, t, rules, timeout): i for i, t in enumerate(scope.targets)
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
