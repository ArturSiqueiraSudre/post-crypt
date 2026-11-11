"""Painel web local: API, regras de escopo e proteções da página."""

import re
import time
from html.parser import HTMLParser
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from postcrypt.classify import HNDL, UNREACHABLE
from postcrypt.painel import create_app
from postcrypt.painel.app import ESTATICOS
from postcrypt.painel.laboratorio import Laboratorio
from postcrypt.scope import ScopeError, parse_scope
from tests.support.pki import TestPKI
from tests.support.tls_server import TLSServer, closed_port

pytestmark = pytest.mark.integration
TOKEN = "token-de-teste"  # noqa: S105
RAIZ = Path(__file__).resolve().parents[2]


@pytest.fixture
def client():
    app = create_app(token=TOKEN, laboratorio=Laboratorio(None))
    with TestClient(app, base_url="http://127.0.0.1:8765") as c:
        c.headers["X-Post-Crypt-Token"] = TOKEN
        yield c


def escopo(*alvos, by="Ana Lima (TI)", date="2026-11-10"):
    return {"authorization": {"by": by, "date": date, "reference": ""}, "targets": list(alvos)}


def esperar(client, vid, limite_s=20):
    fim = time.monotonic() + limite_s
    while time.monotonic() < fim:
        estado = client.get(f"/api/varreduras/{vid}").json()
        if estado["estado"] != "rodando":
            return estado
        time.sleep(0.1)
    raise AssertionError("a varredura não terminou")


# ---------- funcionamento ----------


def test_pagina_entrega_token_e_cabecalhos_de_seguranca(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert f'content="{TOKEN}"' in resp.text
    csp = resp.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_info_sem_laboratorio(client):
    info = client.get("/api/info").json()
    assert info["laboratorio"]["disponivel"] is False
    assert client.post("/api/laboratorio/ligar", json={}).status_code == 404


def test_formulario_normaliza_campos_vazios_e_porta_em_texto(client):
    alvo = {"host": " vpn.exemplo.com.br ", "port": "443", "label": "", "sni": "", "owner": "self"}
    resp = client.post("/api/escopo/validar", json=escopo(alvo))
    assert resp.status_code == 200, resp.text
    t = resp.json()["targets"][0]
    assert (t["host"], t["port"], t["label"], t["sni"]) == (
        "vpn.exemplo.com.br",
        443,
        None,
        "vpn.exemplo.com.br",
    )


def test_importar_e_salvar_escopo_ida_e_volta(client):
    texto = (RAIZ / "examples" / "escopo-exemplo.yaml").read_text(encoding="utf-8")
    importado = client.post("/api/escopo/importar", json={"texto": texto}).json()
    assert len(importado["targets"]) == 2
    salvo = client.post("/api/escopo/yaml", json=importado).json()["texto"]
    assert parse_scope(yaml.safe_load(salvo)) == parse_scope(yaml.safe_load(texto))


def test_importar_yaml_quebrado(client):
    resp = client.post("/api/escopo/importar", json={"texto": "targets: [\n"})
    assert resp.status_code == 422
    assert "YAML" in resp.json()["erro"]


def test_varredura_pelo_painel_classifica_os_alvos(client, tmp_path):
    cert = TestPKI(tmp_path).issue("painel.lab")
    fechada = closed_port()
    with TLSServer("classical", cert.cert_path, cert.key_path) as srv:
        pedido = {
            "escopo": escopo(
                {"host": "127.0.0.1", "port": srv.port, "label": "clássico", "sni": "painel.lab"},
                {"host": "127.0.0.1", "port": fechada, "label": "fora do ar"},
            ),
            "timeout": 2,
        }
        inicio = client.post("/api/varreduras", json=pedido)
        assert inicio.status_code == 202, inicio.text
        estado = esperar(client, inicio.json()["id"])
    assert estado["estado"] == "concluida"
    assert estado["feitos"] == estado["total"] == 2
    resultado = estado["resultado"]
    assert resultado["authorization"]["by"] == "Ana Lima (TI)"
    assert [r["assessment"]["status"] for r in resultado["results"]] == [HNDL, UNREACHABLE]


# ---------- segurança ----------


def test_api_recusa_pedido_sem_token(client):
    resp = client.get("/api/info", headers={"X-Post-Crypt-Token": "outro"})
    assert resp.status_code == 403


def test_api_recusa_host_estranho_dns_rebinding(client):
    resp = client.get("/api/info", headers={"Host": "atacante.example:8765"})
    assert resp.status_code == 400


@pytest.mark.parametrize(
    ("alvo", "trecho"),
    [
        ({"host": "10.0.0.0/24", "port": 443}, "faixa ou curinga"),
        ({"host": "*.exemplo.com", "port": 443}, "faixa ou curinga"),
        ({"host": "exemplo.com", "port": 70000}, "porta inválida"),
        ({"host": "exemplo.com", "port": 443, "extra": "x"}, "campos desconhecidos"),
    ],
)
def test_varredura_com_escopo_invalido_nao_comeca(client, alvo, trecho):
    resp = client.post("/api/varreduras", json={"escopo": escopo(alvo)})
    assert resp.status_code == 422
    assert trecho in resp.json()["erro"]


def test_varredura_sem_autorizacao_nao_comeca(client):
    resp = client.post(
        "/api/varreduras", json={"escopo": escopo({"host": "exemplo.com", "port": 443}, by="")}
    )
    assert resp.status_code == 422
    assert "authorization" in resp.json()["erro"]


def test_pagina_nunca_monta_html_com_dados_da_varredura():
    """Nomes de certificado vêm do servidor varrido; só podem entrar como texto."""
    js = (ESTATICOS / "painel.js").read_text(encoding="utf-8")
    codigo = re.sub(r"//.*", "", js)  # o comentário do topo cita innerHTML de propósito
    for proibido in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert proibido not in codigo, proibido


def test_laboratorio_do_repositorio_e_encontrado():
    from postcrypt.painel.laboratorio import encontrar_raiz

    assert encontrar_raiz(RAIZ / "tests") == RAIZ


# ---------- guia do arquivo de escopo ----------


class _LeitorDoGuia(HTMLParser):
    """Lê o index.html: atributos de cada elemento e o texto dos exemplos em <code>."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elementos: list[tuple[str, dict[str, str | None]]] = []
        self.modelo = ""
        self.recusados: dict[str, str] = {}
        self._destino: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapa = dict(attrs)
        self.elementos.append((tag, mapa))
        if tag != "code":
            return
        if mapa.get("id") == "guia-modelo":
            self._destino = "modelo"
        elif mapa.get("data-recusado"):
            self._destino = str(mapa["data-recusado"])
            self.recusados[self._destino] = ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "code":
            self._destino = None

    def handle_data(self, data: str) -> None:
        if self._destino == "modelo":
            self.modelo += data
        elif self._destino is not None:
            self.recusados[self._destino] += data

    def por_id(self, ident: str) -> dict[str, str | None]:
        achados = [a for _tag, a in self.elementos if a.get("id") == ident]
        assert len(achados) == 1, f"esperado exatamente um #{ident}, achei {len(achados)}"
        return achados[0]


@pytest.fixture(scope="module")
def guia() -> _LeitorDoGuia:
    leitor = _LeitorDoGuia()
    leitor.feed((ESTATICOS / "index.html").read_text(encoding="utf-8"))
    leitor.close()
    return leitor


def test_guia_e_uma_aba_separada_e_comeca_fechada(guia):
    abas = [a for _tag, a in guia.elementos if a.get("role") == "tab"]
    assert [a["data-aba"] for a in abas] == ["varredura", "guia"]
    assert [a["aria-selected"] for a in abas] == ["true", "false"]
    for aba in abas:
        painel = guia.por_id(str(aba["aria-controls"]))
        assert painel["role"] == "tabpanel"
        assert painel["aria-labelledby"] == aba["id"]
    assert "hidden" in guia.por_id("painel-guia")
    assert "hidden" not in guia.por_id("painel-varredura")


def test_pagina_com_guia_e_servida_com_os_arquivos_estaticos(client):
    pagina = client.get("/")
    assert pagina.status_code == 200
    assert 'id="painel-guia"' in pagina.text and 'id="guia-modelo"' in pagina.text
    for arquivo in ("painel.js", "painel.css"):
        assert client.get(f"/static/{arquivo}").status_code == 200


def test_modelo_do_guia_e_um_escopo_valido(guia):
    """O cliente copia este modelo: ele precisa passar na validação de verdade."""
    scope = parse_scope(yaml.safe_load(guia.modelo))
    assert scope.authorization.by and scope.authorization.reference
    assert len(scope.targets) == 3
    assert {t.owner for t in scope.targets} == {"self", "third_party"}
    fornecedor = next(t for t in scope.targets if t.owner == "third_party")
    assert fornecedor.sni and fornecedor.sni != fornecedor.host


def test_modelo_do_guia_abre_pelo_painel(client, guia):
    resp = client.post("/api/escopo/importar", json={"texto": guia.modelo})
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["targets"]) == 3


@pytest.mark.parametrize(
    ("caso", "trecho"),
    [
        ("faixa", "faixa ou curinga"),
        ("curinga", "faixa ou curinga"),
        ("url", "faixa ou curinga"),
        ("sem-porta", "obrigatórios"),
        ("porta", "porta inválida"),
        ("campo", "campos desconhecidos"),
    ],
)
def test_exemplos_recusados_do_guia_sao_mesmo_recusados(guia, caso, trecho):
    """O guia não pode prometer uma recusa que a validação não faz."""
    alvos = yaml.safe_load(guia.recusados[caso])
    autorizacao = {"by": "Ana Lima (TI)", "date": "2026-11-10"}
    with pytest.raises(ScopeError, match=trecho):
        parse_scope({"authorization": autorizacao, "targets": alvos})


def test_guia_nao_tem_exemplo_recusado_sem_teste(guia):
    assert set(guia.recusados) == {"faixa", "curinga", "url", "sem-porta", "porta", "campo"}


def test_curinga_sem_aspas_nao_vira_alvo(client):
    """Asterisco solto é erro de YAML: o arquivo é recusado antes de qualquer conexão."""
    texto = (
        "authorization: {by: Ana, date: 2026-11-10}\n"
        "targets:\n  - host: *.exemplo.com\n    port: 443\n"
    )
    resp = client.post("/api/escopo/importar", json={"texto": texto})
    assert resp.status_code == 422
    assert "YAML" in resp.json()["erro"]


def test_pagina_nao_usa_script_nem_estilo_embutido(guia):
    """A CSP só aceita script e estilo dos arquivos do painel; o guia não pode furar isso."""
    for tag, attrs in guia.elementos:
        assert tag != "style"
        assert "style" not in attrs, f"<{tag}> com style embutido"
        assert not [a for a in attrs if a.startswith("on")], f"<{tag}> com manipulador embutido"
        if tag == "script":
            assert attrs.get("src") == "/static/painel.js"
        for atributo in ("href", "src"):
            valor = attrs.get(atributo)
            if valor is not None:
                assert valor.startswith(("#", "/")), f"{atributo} aponta para fora: {valor}"
