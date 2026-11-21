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


# ---------- Estágio 2: gabarito do fingerprint ----------


def test_gabarito_de_fingerprint_cobre_o_escopo_do_laboratorio():
    scope = load_scope(LAB / "escopo-lab.yaml")
    fp = yaml.safe_load((LAB / "gabarito-fingerprint.yaml").read_text(encoding="utf-8"))
    assert set(fp) == {t.label for t in scope.targets}


def test_banners_so_em_servicos_autorizados_e_casam_com_o_gabarito():
    banners = _load("servidores_python").BANNERS
    scope = {t.label: t for t in load_scope(LAB / "escopo-lab.yaml").targets}
    fp = yaml.safe_load((LAB / "gabarito-fingerprint.yaml").read_text(encoding="utf-8"))
    for name in banners:
        assert scope[name].http_fingerprint, name
        assert fp[name]["status"] == "observed"
    observados = {label for label, exp in fp.items() if exp["status"] == "observed"}
    assert observados == set(banners)


def test_resposta_http_do_laboratorio_passa_no_parser():
    from postcrypt.http_banner.parse import parse_response_head

    lab = _load("servidores_python")
    for banner in lab.BANNERS.values():
        assert parse_response_head(lab.http_response(banner)).headers["server"] == banner


def _fp_result(status="observed", products=None):
    return {
        "results": [
            {
                "target": {"label": "a"},
                "fingerprint": {"status": status, "products": products or []},
            }
        ]
    }


def test_conferencia_de_fingerprint_aponta_divergencia():
    check = _load("verificar_gabarito").check_fingerprint
    nginx = [{"name": "nginx", "version": "1.30.6", "support": "supported"}]
    esperado = {"a": {"status": "observed", "products": {"nginx": ["1.30.6", "supported"]}}}
    assert check(_fp_result(products=nginx), esperado) == []
    assert check(_fp_result(status="not_observed", products=nginx), esperado)
    assert check(_fp_result(products=[]), esperado) == [
        "fingerprint a: não identificou nginx 1.30.6"
    ]
    errado = [{**nginx[0], "support": "unsupported"}]
    assert "esperado supported" in check(_fp_result(products=errado), esperado)[0]
    assert check({"results": [{"target": {"label": "a"}}]}, esperado) == [
        "fingerprint a: ausente do resultado"
    ]
    hostil = {
        "results": [
            {"target": {"label": "a"}, "fingerprint": {"status": "observed", "products": "<x>"}}
        ]
    }
    assert check(hostil, esperado)  # formato hostil não passa


def test_docker_pula_o_gabarito_de_fingerprint(tmp_path, capsys):
    verificar = _load("verificar_gabarito")
    assert verificar.main(["verificar"]) == 2
    vazio = tmp_path / "r.json"
    vazio.write_text('{"results": [], "network": {"findings": []}}', encoding="utf-8")
    verificar.main(["verificar", str(vazio), "--sem-fingerprint"])
    assert "fingerprints conferem" not in capsys.readouterr().out
