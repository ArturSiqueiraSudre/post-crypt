"""Saídas da varredura: tabela no terminal e JSON."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from postcrypt.classify import HNDL, PQC, REVIEW, STATUS_LABELS, UNREACHABLE
from postcrypt.scanner import ScanResult, TargetResult

STATUS_STYLE = {PQC: "green", HNDL: "red", REVIEW: "yellow", UNREACHABLE: "magenta"}


def _kx_cell(r: TargetResult) -> str:
    kx = r.assessment.key_exchange
    if kx.get("groups"):
        return ", ".join(kx["groups"])
    return kx.get("classical_group") or "—"


def _sym_cell(r: TargetResult) -> str:
    sym = r.assessment.symmetric
    return sym.get("cipher") or "—"


def _cert_cell(r: TargetResult) -> tuple[str, str]:
    obs = r.observation
    if not obs or not obs.certificates:
        return "—", "—"
    leaf = obs.certificates[0]
    days = leaf.days_to_expiry
    expiry = "vencido" if days < 0 else f"{days} d"
    return leaf.public_key_detail, expiry


def render_table(scan: ScanResult, console: Console) -> None:
    table = Table(title="Post-Crypt — prontidão pós-quântica", title_justify="left")
    table.add_column("Alvo")
    table.add_column("Status")
    table.add_column("Troca de chave")
    table.add_column("Cifra simétrica")
    table.add_column("Certificado")
    table.add_column("Vence em", justify="right")
    for r in scan.results:
        status = r.assessment.status
        cert, expiry = _cert_cell(r)
        table.add_row(
            f"{r.target.name}\n[dim]{r.target.host}:{r.target.port}[/dim]",
            f"[{STATUS_STYLE[status]}]{r.assessment.status_label}[/]",
            _kx_cell(r),
            _sym_cell(r),
            cert,
            expiry,
        )
    console.print(table)

    counts = scan.counts()
    parts = [
        f"{STATUS_LABELS[s]}: {counts[s]}" for s in (PQC, HNDL, REVIEW, UNREACHABLE) if s in counts
    ]
    console.print(" · ".join(parts))

    for r in scan.results:
        serious = [f for f in r.assessment.findings if f.severity in ("critical", "high")]
        for f in serious:
            console.print(f"[bold]{r.target.name}[/bold] — {f.title}: {f.detail}")


def write_json(scan: ScanResult, path: str | Path) -> str:
    text = json.dumps(scan.to_dict(), ensure_ascii=False, indent=2)
    if str(path) != "-":
        Path(path).write_text(text + "\n", encoding="utf-8")
    return text
