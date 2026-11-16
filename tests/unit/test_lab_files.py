"""O laboratório, o escopo do laboratório e o gabarito precisam concordar."""

import importlib.util
from pathlib import Path

import yaml

from postcrypt.scope import load_scope

LAB = Path(__file__).resolve().parents[2] / "lab"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, LAB / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_lab_scope_matches_gabarito():
    scope = load_scope(LAB / "escopo-lab.yaml")
    gabarito = yaml.safe_load((LAB / "gabarito.yaml").read_text(encoding="utf-8"))
    assert {t.label for t in scope.targets} == set(gabarito)


def test_every_tls_service_has_a_certificate_and_nginx_block():
    certs = _load("gerar_certificados").SERVICES
    nginx = (LAB / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    for name in certs:
        assert f"/etc/nginx/certs/{name}.pem" in nginx


def test_gabarito_checker_flags_divergence():
    check = _load("verificar_gabarito").check
    result = {
        "results": [
            {
                "target": {"label": "a"},
                "assessment": {"status": "pqc", "findings": [{"id": "CERT_EXPIRING"}]},
            }
        ]
    }
    assert check(result, {"a": {"status": "pqc", "findings": ["CERT_EXPIRING"]}}) == []
    assert check(result, {"a": {"status": "hndl_vulnerable"}})
    assert check(result, {"b": {"status": "pqc"}}) == ["b: ausente do resultado"]


def test_network_gabarito_only_names_lab_services():
    scope = load_scope(LAB / "escopo-lab.yaml")
    rede = yaml.safe_load((LAB / "gabarito-rede.yaml").read_text(encoding="utf-8"))
    labels = {t.label for t in scope.targets}
    assert rede and all(set(services) <= labels for services in rede.values())


def _network_result(assets, blast_radius=None):
    return {
        "results": [
            {"target": {"host": "127.0.0.1", "port": 1, "label": "a"}},
            {"target": {"host": "127.0.0.1", "port": 2, "label": "b"}},
        ],
        "network": {
            "findings": [
                {
                    "id": "NET_X",
                    "assets": assets,
                    "blast_radius": len(assets) if blast_radius is None else blast_radius,
                }
            ]
        },
    }


def test_network_gabarito_checker_flags_divergence():
    check = _load("verificar_gabarito").check_network
    ok = _network_result(["127.0.0.1:1", "127.0.0.1:2"])
    assert check(ok, {"NET_X": ["a", "b"]}) == []
    assert check(ok, {"NET_X": ["a"]})  # serviços errados
    assert check(ok, {"NET_Y": ["a"]}) == ["rede NET_Y: achado ausente"]
    assert check(_network_result(["127.0.0.1:1"], blast_radius=7), {})  # raio inconsistente
    assert check({"results": []}, {"NET_X": ["a"]}) == [
        "rede: o resultado não traz a chave 'network'"
    ]
    assert check({"results": [], "network": "<script>"}, {}) != []  # formato hostil não passa


def test_python_lab_matches_lab_scope():
    """Laboratório sem Docker: mesmas portas e nomes do escopo do laboratório."""
    services = _load("servidores_python").SERVICES
    scope = load_scope(LAB / "escopo-lab.yaml")
    tls_targets = {t.label: t.port for t in scope.targets if t.label != "desligado"}
    assert {name: port for name, (port, _mode) in services.items()} == tls_targets
