"""Confere o JSON de uma varredura do laboratório contra os gabaritos.

Uso: python lab/verificar_gabarito.py resultado.json
Sai com código 1 se algum serviço divergir de lab/gabarito.yaml (critério de
aceite CA2) ou se algum achado de rede divergir de lab/gabarito-rede.yaml.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

GABARITO = Path(__file__).resolve().parent / "gabarito.yaml"
GABARITO_REDE = Path(__file__).resolve().parent / "gabarito-rede.yaml"


def check(result: dict, expected: dict) -> list[str]:
    errors: list[str] = []
    by_label = {r["target"]["label"]: r for r in result["results"]}
    for label, exp in expected.items():
        got = by_label.get(label)
        if got is None:
            errors.append(f"{label}: ausente do resultado")
            continue
        status = got["assessment"]["status"]
        if status != exp["status"]:
            errors.append(f"{label}: status {status}, esperado {exp['status']}")
        ids = {f["id"] for f in got["assessment"]["findings"]}
        missing = set(exp.get("findings", [])) - ids
        if missing:
            errors.append(f"{label}: faltam achados {sorted(missing)}")
    return errors


def check_network(result: dict, expected: dict) -> list[str]:
    """Cada achado de rede esperado precisa existir e apontar exatamente os serviços dados."""
    errors: list[str] = []
    network = result.get("network")
    if not isinstance(network, dict):
        return ["rede: o resultado não traz a chave 'network'"]
    labels = {
        f"{r['target']['host']}:{r['target']['port']}": r["target"]["label"]
        for r in result["results"]
    }
    found: dict[str, list[set]] = {}
    for finding in network.get("findings", []):
        assets = {labels.get(a, a) for a in finding.get("assets", [])}
        found.setdefault(finding["id"], []).append(assets)
        if finding.get("blast_radius") != len(finding.get("assets", [])):
            errors.append(f"rede {finding['id']}: raio de impacto difere do número de serviços")
    for finding_id, services in expected.items():
        if finding_id not in found:
            errors.append(f"rede {finding_id}: achado ausente")
        elif set(services) not in found[finding_id]:
            got = [sorted(a) for a in found[finding_id]]
            errors.append(f"rede {finding_id}: serviços {got}, esperado {sorted(services)}")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    result = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    expected = yaml.safe_load(GABARITO.read_text(encoding="utf-8"))
    errors = check(result, expected)
    for e in errors:
        print(f"DIVERGE  {e}")
    divergent = {e.split(":")[0] for e in errors}
    print(f"{len(expected) - len(divergent)}/{len(expected)} serviços conferem")

    expected_network = yaml.safe_load(GABARITO_REDE.read_text(encoding="utf-8"))
    network_errors = check_network(result, expected_network)
    for e in network_errors:
        print(f"DIVERGE  {e}")
    failed = {e.split(":")[0].removeprefix("rede ") for e in network_errors}
    ok = len(set(expected_network) - failed)
    print(f"{ok}/{len(expected_network)} achados de rede conferem")
    return 1 if errors or network_errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
