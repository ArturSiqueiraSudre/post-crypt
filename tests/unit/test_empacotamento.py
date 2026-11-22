"""O instalador depende de arquivos que nenhum outro teste lê: aqui eles são conferidos."""

import re
import tomllib
from pathlib import Path

import yaml

from postcrypt import __version__

RAIZ = Path(__file__).resolve().parents[2]
PASTA = RAIZ / "packaging" / "windows"
ISS = (PASTA / "post-crypt.iss").read_text(encoding="utf-8")
SPEC = (PASTA / "post-crypt.spec").read_text(encoding="utf-8")
SCRIPT = RAIZ / "scripts" / "gerar-instalador.ps1"
APP_ID = "{{B50B4263-B4F1-4959-9715-4B8BF87F17B0}"


def diretivas(texto: str) -> dict[str, str]:
    return dict(re.findall(r"^(\w+)=(.*)$", texto, re.M))


def test_versao_do_pacote_e_a_do_pyproject():
    pyproject = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))
    versao = pyproject["project"]["version"]
    assert versao == __version__
    assert re.fullmatch(r"\d+\.\d+\.\d+", versao), "o script e o instalador esperam x.y.z"


def test_app_id_nunca_muda():
    # Trocar o AppId faz o Windows tratar a versão nova como outro programa.
    assert diretivas(ISS)["AppId"] == APP_ID


def test_instala_por_usuario_sem_administrador_por_padrao():
    d = diretivas(ISS)
    assert d["PrivilegesRequired"] == "lowest"
    assert d["PrivilegesRequiredOverridesAllowed"] == "dialog"
    assert d["DefaultDirName"] == r"{autopf}\{#AppName}"


def test_assistente_oferece_pasta_atalho_e_abrir_ao_terminar():
    d = diretivas(ISS)
    assert d.get("DisableDirPage", "no") == "no"  # a pessoa escolhe a pasta
    assert 'Name: "desktopicon"' in ISS
    assert re.search(r"\{autodesktop\}.*Tasks: desktopicon", ISS)
    assert re.search(r"\{group\}\\\{#AppName\}", ISS)
    assert re.search(r"\[Run\][^\[]*postinstall[^\[]*runasoriginaluser", ISS)
    assert "BrazilianPortuguese.isl" in ISS


def test_arquivos_citados_pelo_instalador_existem():
    d = diretivas(ISS)
    for chave in ("SetupIconFile", "WizardImageFile", "WizardSmallImageFile"):
        assert (PASTA / d[chave]).is_file(), chave
    assert (PASTA / "post-crypt.ico").read_bytes()[:4] == b"\x00\x00\x01\x00"  # formato ICO
    for bmp in ("assistente.bmp", "assistente-pequeno.bmp"):
        assert (PASTA / bmp).read_bytes()[:2] == b"BM"


def test_executavel_e_de_janela_sem_upx_e_com_os_dados_do_pacote():
    assert "console=False" in SPEC
    assert "upx=True" not in SPEC
    assert 'collect_data_files("postcrypt"' in SPEC
    assert (PASTA / "iniciar.py").is_file()
    assert "postcrypt.desktop.app import main" in (PASTA / "iniciar.py").read_text("utf-8")


def test_dados_que_o_executavel_precisa_estao_no_pacote():
    pacote = RAIZ / "src" / "postcrypt"
    assert (pacote / "rules" / "default.yaml").is_file()
    for nome in ("index.html", "painel.css", "painel.js"):
        assert (pacote / "painel" / "static" / nome).is_file()


def test_script_de_build_abre_no_windows_powershell_5():
    bruto = SCRIPT.read_bytes()
    assert bruto.startswith(b"\xef\xbb\xbf"), "sem BOM, o PowerShell 5.1 estraga os acentos"
    texto = bruto.decode("utf-8-sig")
    assert "\r\n" in texto and "\n" not in texto.replace("\r\n", "")
    regex = re.search(r"-Pattern '([^']+)'", texto).group(1)
    pyproject = (RAIZ / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(regex, pyproject, re.M), "o script não acharia a versão no pyproject"
    assert "--autoteste" in texto and "/DAppVersion=" in texto


def test_workflow_so_publica_tag_que_bate_com_a_versao():
    fluxo = yaml.safe_load((RAIZ / ".github" / "workflows" / "instalador.yml").read_text("utf-8"))
    passos = fluxo["jobs"]["instalador"]["steps"]
    assert any("A tag confere" in p.get("name", "") for p in passos)
    assert fluxo["permissions"] == {"contents": "read"}
    assert fluxo["jobs"]["publicar"]["permissions"] == {"contents": "write"}
    assert fluxo["jobs"]["publicar"]["if"].startswith("startsWith(github.ref, 'refs/tags/v')")
