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
        self.no_formulario: set[str] = set()
        self._destino: str | None = None
        self._dentro_do_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapa = dict(attrs)
        self.elementos.append((tag, mapa))
        if tag == "form":
            self._dentro_do_form = True
        elif self._dentro_do_form:
            self.no_formulario.update(str(mapa[k]) for k in ("id", "name") if mapa.get(k))
        if tag != "code":
            return
        if mapa.get("id") == "guia-modelo":
            self._destino = "modelo"
        elif mapa.get("data-recusado"):
            self._destino = str(mapa["data-recusado"])
            self.recusados[self._destino] = ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._dentro_do_form = False
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


VISTAS = ["autorizacao", "servicos", "revisar", "resultado", "guia"]


def test_barra_lateral_lista_as_etapas_e_o_guia(guia):
    itens = [a for _tag, a in guia.elementos if "data-vista" in a]
    assert [a["data-vista"] for a in itens] == VISTAS
    assert [a["id"] for a in itens] == [f"nav-{v}" for v in VISTAS]
    for nome in VISTAS:
        guia.por_id(f"vista-{nome}")  # cada item do menu tem a sua vista


def test_so_a_primeira_etapa_comeca_visivel(guia):
    visiveis = [v for v in VISTAS if "hidden" not in guia.por_id(f"vista-{v}")]
    assert visiveis == ["autorizacao"]
    assert guia.por_id("nav-autorizacao")["aria-current"] == "step"


def test_resultado_comeca_bloqueado_no_menu(guia):
    """Sem varredura não há resultado: o item nasce desabilitado no próprio HTML."""
    assert "disabled" in guia.por_id("nav-resultado")
    for nome in ("autorizacao", "servicos", "revisar", "guia"):
        assert "disabled" not in guia.por_id(f"nav-{nome}")


def test_etapas_do_escopo_ficam_no_mesmo_formulario(guia):
    """As etapas trocam de tela, mas o escopo é um formulário só, enviado inteiro."""
    assert {"vista-autorizacao", "vista-servicos", "vista-revisar"} <= guia.no_formulario
    assert {"by", "date", "reference", "timeout", "workers"} <= guia.no_formulario
    assert not {"vista-resultado", "vista-guia"} & guia.no_formulario
    varrer = guia.por_id("varrer")
    assert (varrer["type"], varrer["form"]) == ("submit", "form-escopo")
    for botao in ("voltar", "continuar", "nova-varredura"):
        assert guia.por_id(botao)["type"] == "button"


def test_links_internos_apontam_para_vistas_que_existem(guia):
    destinos = [str(a["data-ir-para"]) for _tag, a in guia.elementos if "data-ir-para" in a]
    assert destinos and set(destinos) <= set(VISTAS)
    for _tag, a in guia.elementos:
        href = a.get("href")
        if href and href.startswith("#"):
            alvo = href[1:]
            assert alvo in VISTAS or guia.por_id(alvo)


def test_pagina_com_guia_e_servida_com_os_arquivos_estaticos(client):
    pagina = client.get("/")
    assert pagina.status_code == 200
    assert 'id="vista-guia"' in pagina.text and 'id="guia-modelo"' in pagina.text
    assert "{{" not in pagina.text
    for arquivo in ("painel.js", "painel.css"):
        assert client.get(f"/static/{arquivo}").status_code == 200


def test_vista_vinda_da_url_passa_por_lista_fechada():
    """O nome depois do # é entrada externa: só vale se estiver na lista de vistas."""
    js = (ESTATICOS / "painel.js").read_text(encoding="utf-8")
    assert "Object.hasOwn(VISTAS, alvo)" in js
    assert "Object.hasOwn(VISTAS, nome)" in js
    for nome in VISTAS:
        assert re.search(rf"^  {nome}: \{{ titulo:", js, flags=re.M), nome


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


# ---------- identidade visual ----------

MARCA = {"marinho": "#0B1530", "ciano": "#1590B3", "ciano-vivo": "#3CC3DE", "fundo": "#F5F7FA"}
PALETA_ANTIGA = ("#0F766E", "#0B5F58", "#5EEAD4", "#2DD4BF", "#111418")
CONTRASTE_MINIMO = 4.5  # WCAG 2.1 AA para texto normal

# (texto, fundo): pares que aparecem de fato na tela.
PARES_DE_TEXTO = [
    ("tinta", "fundo"),
    ("tinta", "superficie"),
    ("texto", "fundo"),
    ("texto", "superficie"),
    ("suave", "fundo"),
    ("suave", "superficie"),
    ("ciano-forte", "fundo"),
    ("ciano-forte", "superficie"),
    ("ciano-forte", "ciano-claro"),
    ("principal-texto", "principal"),
    ("laranja", "superficie"),
    ("laranja", "laranja-claro"),
    ("ambar", "ambar-claro"),
    ("lacuna", "lacuna-claro"),
    ("superficie", "laranja"),
    ("lateral-texto", "marinho"),
    ("lateral-suave", "marinho"),
    ("ciano-vivo", "marinho"),
    ("codigo-texto", "codigo-fundo"),
]


def _tokens(bloco: str) -> dict[str, str]:
    achados = re.findall(r"--([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})\b", bloco)
    return {nome: cor.upper() for nome, cor in achados}


@pytest.fixture(scope="module")
def paletas() -> dict[str, dict[str, str]]:
    css = (ESTATICOS / "painel.css").read_text(encoding="utf-8")
    corte = css.index("@media (prefers-color-scheme: dark)")
    claro = _tokens(css[:corte])
    escuro = {**claro, **_tokens(css[corte : css.index("*, *::before")])}
    return {"claro": claro, "escuro": escuro}


def _luminancia(cor: str) -> float:
    canais = [int(cor[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = (c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in canais)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contraste(a: str, b: str) -> float:
    claro, escuro = sorted((_luminancia(a), _luminancia(b)), reverse=True)
    return (claro + 0.05) / (escuro + 0.05)


def test_contraste_bate_com_valores_conhecidos():
    assert _contraste("#000000", "#FFFFFF") == pytest.approx(21.0)
    assert _contraste("#FFFFFF", "#FFFFFF") == pytest.approx(1.0)
    assert _contraste("#1590B3", "#FFFFFF") < CONTRASTE_MINIMO  # por isso existe --ciano-forte


def test_painel_usa_a_paleta_da_marca(paletas):
    for nome, cor in MARCA.items():
        assert paletas["claro"][nome] == cor
    assert paletas["claro"]["tinta"] == MARCA["marinho"]
    assert paletas["escuro"]["ciano"] == MARCA["ciano-vivo"]
    assert paletas["escuro"]["fundo"] == MARCA["marinho"]


def test_paleta_antiga_saiu_do_painel():
    for arquivo in ("painel.css", "icone.svg", "index.html"):
        texto = (ESTATICOS / arquivo).read_text(encoding="utf-8").upper()
        for cor in PALETA_ANTIGA:
            assert cor not in texto, f"{cor} ainda em {arquivo}"


def test_toda_variavel_de_cor_usada_esta_definida():
    css = (ESTATICOS / "painel.css").read_text(encoding="utf-8")
    definidas = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
    usadas = set(re.findall(r"var\((--[a-z0-9-]+)", css))
    assert usadas <= definidas, sorted(usadas - definidas)


@pytest.mark.parametrize("modo", ["claro", "escuro"])
@pytest.mark.parametrize(("texto", "fundo"), PARES_DE_TEXTO)
def test_texto_tem_contraste_minimo(paletas, modo, texto, fundo):
    cores = paletas[modo]
    razao = _contraste(cores[texto], cores[fundo])
    assert razao >= CONTRASTE_MINIMO, f"{texto} sobre {fundo} ({modo}): {razao:.2f}"


DESENHO = {"svg", "rect", "g", "path"}
# Credencial de conteúdo (C2PA): bloco de metadados que não é desenhado nem executado.
PROVENIENCIA = {"metadata", "c2pa:manifest"}
MANIFESTO = re.compile(r"<c2pa:manifest>[A-Za-z0-9+/=\s]+</c2pa:manifest>")


def problemas_do_svg(svg: str) -> list[str]:
    """Lista o que impede um SVG de ser aceito como desenho puro (vazia = aceito)."""
    problemas: list[str] = []
    if len(svg) >= 50_000:
        problemas.append("arquivo grande demais")
    if "<!ENTITY" in svg.upper() or "<!DOCTYPE" in svg.upper():
        problemas.append("declaração de entidade ou DOCTYPE")
    leitor = _LeitorDoGuia()
    leitor.feed(svg)
    for tag, attrs in leitor.elementos:
        if tag not in DESENHO | PROVENIENCIA:
            problemas.append(f"elemento <{tag}>")
        for nome in attrs:
            if nome.startswith("on") or nome in ("href", "xlink:href", "style", "src"):
                problemas.append(f"atributo {nome} em <{tag}>")
    blocos = re.findall(r"<metadata\b[^>]*>(.*?)</metadata>", svg, flags=re.S)
    if len(blocos) > 1 or svg.count("<metadata") != len(blocos):
        problemas.append("metadados repetidos ou malformados")
    for bloco in blocos:
        if not MANIFESTO.fullmatch(bloco.strip()):
            problemas.append("metadados com algo além do manifesto em base64")
    return problemas


def test_icone_e_um_svg_estatico_da_marca():
    """O ícone vem de um pacote externo: só entra se for desenho puro, sem nada ativo."""
    svg = (ESTATICOS / "icone.svg").read_text(encoding="utf-8")
    assert MARCA["marinho"] in svg and MARCA["ciano-vivo"] in svg
    assert problemas_do_svg(svg) == []


def test_svg_de_desenho_com_credencial_de_conteudo_e_aceito():
    puro = '<svg xmlns="http://www.w3.org/2000/svg"><g><path d="M0,0 L1,1"/></g></svg>'
    assert problemas_do_svg(puro) == []
    credencial = "<metadata><c2pa:manifest>AAAWgmp1bWI=\n</c2pa:manifest></metadata>"
    assert problemas_do_svg(puro.replace("</svg>", credencial + "</svg>")) == []


@pytest.mark.parametrize(
    "trecho",
    [
        "<script>alert(1)</script>",
        '<g onload="alert(1)"/>',
        '<a href="https://atacante.example"><path d="M0,0"/></a>',
        '<image href="https://atacante.example/x.png"/>',
        '<use xlink:href="https://atacante.example/x.svg#a"/>',
        "<foreignObject><iframe/></foreignObject>",
        '<path style="background:url(https://atacante.example)" d="M0,0"/>',
        "<metadata><script>alert(1)</script></metadata>",
        "<metadata><c2pa:manifest>AAAA</c2pa:manifest><x>fora do manifesto</x></metadata>",
        "<metadata><c2pa:manifest>javascript:alert(1)</c2pa:manifest></metadata>",
        "<metadata><c2pa:manifest>AAAA</c2pa:manifest></metadata><metadata>AAAA</metadata>",
        "<metadata><c2pa:manifest>AAAA</c2pa:manifest>",
    ],
)
def test_svg_com_conteudo_ativo_e_recusado(trecho):
    svg = f'<svg xmlns="http://www.w3.org/2000/svg">{trecho}</svg>'
    assert problemas_do_svg(svg) != []


def test_svg_com_entidade_ou_grande_demais_e_recusado():
    bomba = '<!DOCTYPE svg [<!ENTITY a "aaaa">]><svg xmlns="http://www.w3.org/2000/svg"/>'
    assert problemas_do_svg(bomba) != []
    enorme = '<svg xmlns="http://www.w3.org/2000/svg">' + '<path d="M0,0"/>' * 4000 + "</svg>"
    assert problemas_do_svg(enorme) != []


def test_icone_e_servido_como_svg(client):
    resp = client.get("/static/icone.svg")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/svg+xml")
    assert resp.headers["x-content-type-options"] == "nosniff"
