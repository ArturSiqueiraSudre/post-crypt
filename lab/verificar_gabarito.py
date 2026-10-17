"""Confere o JSON de uma varredura do laboratório contra lab/gabarito.yaml.

Uso: python lab/verificar_gabarito.py resultado.json
Sai com código 1 se algum serviço divergir do esperado (critério de aceite CA2).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

GABARITO = Path(__file__).resolve().parent / "gabarito.yaml"


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
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
