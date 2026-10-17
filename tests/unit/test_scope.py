"""O arquivo de escopo é a garantia de que só alvos autorizados são contatados."""

from pathlib import Path

import pytest

from postcrypt.scope import ScopeError, load_scope, parse_scope

AUTH = {"by": "Maria (CISO)", "date": "2026-10-17", "reference": "Termo 01/2026"}


def test_valid_scope_defaults():
    scope = parse_scope(
        {
            "authorization": AUTH,
            "targets": [
                {"host": "vpn.example.com", "port": 443},
                {"host": "10.0.0.5", "port": 8443, "owner": "third_party", "label": "core"},
            ],
        }
    )
    first, second = scope.targets
    assert first.sni == "vpn.example.com" and first.protocol == "tls" and first.owner == "self"
    assert second.sni is None and second.name == "core"
    assert scope.authorization.reference == "Termo 01/2026"


@pytest.mark.parametrize("host", ["10.0.0.0/24", "*.example.com", "host?"])
def test_ranges_and_wildcards_are_refused(host):
    with pytest.raises(ScopeError, match="faixa ou curinga"):
        parse_scope({"authorization": AUTH, "targets": [{"host": host, "port": 443}]})


def test_authorization_is_mandatory():
    with pytest.raises(ScopeError, match="authorization"):
        parse_scope({"targets": [{"host": "a.example", "port": 443}]})


@pytest.mark.parametrize(
    "target, message",
    [
        ({"host": "a.example", "port": 70000}, "porta"),
        ({"host": "a.example"}, "obrigatórios"),
        ({"host": "a.example", "port": 22, "protocol": "ssh"}, "não suportado"),
        ({"host": "a.example", "port": 443, "owner": "vendor"}, "owner"),
        ({"host": "a.example", "port": 443, "extra": 1}, "desconhecidos"),
    ],
)
def test_invalid_targets(target, message):
    with pytest.raises(ScopeError, match=message):
        parse_scope({"authorization": AUTH, "targets": [target]})


def test_duplicate_targets_refused():
    with pytest.raises(ScopeError, match="repetido"):
        parse_scope(
            {
                "authorization": AUTH,
                "targets": [{"host": "a.example", "port": 443}, {"host": "a.example", "port": 443}],
            }
        )


def test_example_scope_is_valid():
    path = Path(__file__).resolve().parents[2] / "examples" / "escopo-exemplo.yaml"
    scope = load_scope(path)
    assert [t.owner for t in scope.targets] == ["self", "third_party"]
