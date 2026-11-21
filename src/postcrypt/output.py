"""Saídas da varredura: tabela no terminal e JSON.

Nomes de alvo, de certificado e mensagens de erro vêm de fora (arquivo de
escopo e servidores varridos). No terminal eles passam por ``escape`` para
não serem lidos como marcação do rich, e perdem caracteres de controle para
não carregarem sequências de terminal.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from postcrypt.classify import HNDL, PQC, REVIEW, STATUS_LABELS, UNREACHABLE
from postcrypt.fingerprint import NOT_AUTHORIZED, UNSUPPORTED
from postcrypt.network import NetworkAssessment, asset_id
from postcrypt.scanner import ScanResult, TargetResult

STATUS_STYLE = {PQC: "green", HNDL: "red", REVIEW: "yellow", UNREACHABLE: "magenta"}
SEVERITY_LABELS = {
    "critical": "crítica",
    "high": "alta",
    "medium": "média",
    "low": "baixa",
    "info": "informativa",
}
MAX_ASSETS_LISTED = 6  # no terminal; o JSON traz a lista inteira


def _plain(text: str) -> str:
    """Texto de fora, pronto para o terminal: sem caracteres de controle nem marcação."""
    return escape("".join(ch for ch in str(text) if ch.isprintable()))


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


def _software_cell(r: TargetResult) -> str:
    """Produtos declarados pelo servidor, marcando os que estão sem suporte."""
    fp = r.fingerprint
    if fp is None or not fp.products:
        return "não autorizado" if fp is not None and fp.status == NOT_AUTHORIZED else "—"
    parts: list[str] = []
    for p in fp.products:
        text = f"{p.name} {p.version}" if p.version else p.name
        parts.append(f"{text} (sem suporte)" if p.support == UNSUPPORTED else text)
    return "\n".join(parts)


def render_table(scan: ScanResult, console: Console) -> None:
    table = Table(title="Post-Crypt — prontidão pós-quântica", title_justify="left")
    table.add_column("Alvo")
    table.add_column("Status")
    table.add_column("Troca de chave")
    table.add_column("Cifra simétrica")
    table.add_column("Certificado")
    table.add_column("Vence em", justify="right")
    table.add_column("Software")
    for r in scan.results:
        status = r.assessment.status
        cert, expiry = _cert_cell(r)
        table.add_row(
            f"{_plain(r.target.name)}\n[dim]{_plain(r.target.host)}:{r.target.port}[/dim]",
            f"[{STATUS_STYLE[status]}]{_plain(r.assessment.status_label)}[/]",
            _plain(_kx_cell(r)),
            _plain(_sym_cell(r)),
            _plain(cert),
            _plain(expiry),
            "\n".join(_plain(line) for line in _software_cell(r).split("\n")),
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
            console.print(
                f"[bold]{_plain(r.target.name)}[/bold] — {_plain(f.title)}: {_plain(f.detail)}"
            )


def render_network(scan: ScanResult, network: NetworkAssessment, console: Console) -> None:
    """Seção de rede no terminal: achados que relacionam mais de um alvo."""
    if network.total_targets < 2:
        return  # com um alvo só não há o que relacionar
    console.print()
    console.print("[bold]Rede[/bold] — prioridade = severidade × alvos afetados")
    if not network.findings:
        console.print("Nenhuma relação entre os alvos gerou achado.")
        return
    names = {asset_id(r): r.target.name for r in scan.results}
    table = Table(show_header=True)
    table.add_column("Prioridade", justify="right")
    table.add_column("Severidade")
    table.add_column("Achado")
    table.add_column("Alvos")
    for f in network.findings:
        listed = [names.get(a, a) for a in f.assets[:MAX_ASSETS_LISTED]]
        extra = len(f.assets) - len(listed)
        assets = ", ".join(listed) + (f" e mais {extra}" if extra > 0 else "")
        table.add_row(
            str(f.priority),
            SEVERITY_LABELS.get(f.severity, f.severity),
            f"{_plain(f.title)}\n[dim]{_plain(f.detail)}[/dim]",
            _plain(assets),
        )
    console.print(table)


def scan_report(scan: ScanResult, network: NetworkAssessment) -> dict:
    """Resultado exportado: a varredura mais a chave ``network``."""
    return {**scan.to_dict(), "network": network.to_dict()}


def write_json(scan: ScanResult, network: NetworkAssessment, path: str | Path) -> str:
    text = json.dumps(scan_report(scan, network), ensure_ascii=False, indent=2)
    if str(path) != "-":
        Path(path).write_text(text + "\n", encoding="utf-8")
    return text
