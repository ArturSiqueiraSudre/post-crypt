from pathlib import Path

import pytest

from postcrypt import __version__
from postcrypt.desktop import app
from postcrypt.desktop.autoteste import FalhaAutoteste
from postcrypt.desktop.servidor import ErroServidor

URL = "http://127.0.0.1:51234/"


class FalsoServidor:
    def __init__(self, _app, *, falha=None):
        self.falha = falha
        self.paradas = 0

    def iniciar(self):
        if self.falha:
            raise self.falha
        return URL

    def parar(self):
        self.paradas += 1


class Registro:
    def __init__(self):
        self.eventos = []


def montar(tmp_path, *, janela_ok=True, navegador_ok=True, falha=None, autoteste=None):
    r = Registro()
    servidores = []

    def criar_servidor(a):
        s = FalsoServidor(a, falha=falha)
        servidores.append(s)
        return s

    def rodar_autoteste(url, versao):
        r.eventos.append(("autoteste", url, versao))
        if autoteste:
            raise autoteste
        return {"versao": versao, "regras": "2026-11-20"}

    deps = app.Dependencias(
        criar_app=lambda: "app",
        criar_servidor=criar_servidor,
        abrir_janela=lambda url, icone=None: r.eventos.append(("janela", url)) or janela_ok,
        abrir_navegador=lambda url: r.eventos.append(("navegador", url)) or navegador_ok,
        aguardar_no_navegador=lambda t, m: r.eventos.append(("aguardar", t)),
        mostrar_erro=lambda t, m: r.eventos.append(("erro", m)),
        rodar_autoteste=rodar_autoteste,
        pasta_de_dados=lambda: tmp_path,
        icone=lambda: None,
    )
    return deps, r, servidores


def test_abre_a_janela_e_desliga_o_servidor_ao_fechar(tmp_path):
    deps, r, servidores = montar(tmp_path)
    assert app.main([], deps) == 0
    assert r.eventos == [("janela", URL)]
    assert servidores[0].paradas == 1
    assert (tmp_path / "logs" / "post-crypt.log").is_file()


def test_sem_janela_cai_no_navegador_e_espera_a_pessoa(tmp_path):
    deps, r, servidores = montar(tmp_path, janela_ok=False)
    assert app.main([], deps) == 0
    assert r.eventos == [("janela", URL), ("navegador", URL), ("aguardar", "Post-Crypt")]
    assert servidores[0].paradas == 1


def test_opcao_navegador_nem_tenta_a_janela(tmp_path):
    deps, r, _ = montar(tmp_path)
    assert app.main(["--navegador"], deps) == 0
    assert r.eventos == [("navegador", URL), ("aguardar", "Post-Crypt")]


def test_sem_janela_e_sem_navegador_mostra_erro_e_sai_com_1(tmp_path):
    deps, r, servidores = montar(tmp_path, janela_ok=False, navegador_ok=False)
    assert app.main([], deps) == 1
    assert r.eventos[-1][0] == "erro" and "post-crypt.log" in r.eventos[-1][1]
    assert servidores[0].paradas == 1


def test_servidor_que_nao_sobe_mostra_erro_sem_abrir_janela(tmp_path):
    deps, r, _ = montar(tmp_path, falha=ErroServidor("não iniciou em 15 s"))
    assert app.main([], deps) == 1
    assert [e[0] for e in r.eventos] == ["erro"]
    assert "não iniciou em 15 s" in r.eventos[0][1]


def test_autoteste_ok_sai_com_0_sem_janela(tmp_path, capsys):
    deps, r, servidores = montar(tmp_path)
    assert app.main(["--autoteste"], deps) == 0
    assert r.eventos == [("autoteste", URL, __version__)]
    assert "autoteste ok" in capsys.readouterr().out
    assert servidores[0].paradas == 1


def test_autoteste_que_falha_sai_com_2_sem_caixa_de_mensagem(tmp_path, capsys):
    deps, r, _ = montar(tmp_path, autoteste=FalhaAutoteste("a API respondeu a um pedido sem token"))
    assert app.main(["--autoteste"], deps) == 2
    assert "erro" not in [e[0] for e in r.eventos]
    assert "sem token" in capsys.readouterr().err


def test_autoteste_com_servidor_quebrado_sai_com_1_sem_caixa(tmp_path):
    deps, r, _ = montar(tmp_path, falha=ErroServidor("x"))
    assert app.main(["--autoteste"], deps) == 1
    assert r.eventos == []


def test_sem_onde_gravar_o_log_o_programa_segue(tmp_path):
    deps, _r, _ = montar(tmp_path)
    bloqueio = tmp_path / "arquivo"
    bloqueio.write_text("x")
    deps.pasta_de_dados = lambda: bloqueio
    assert app.main([], deps) == 0


@pytest.mark.parametrize(
    "argv", [["--autoteste", "--navegador"], ["--porta", "80"], ["--host=0.0.0.0"], ["; rm -rf /"]]
)
def test_argumentos_desconhecidos_ou_conflitantes_sao_recusados(argv, tmp_path):
    deps, r, servidores = montar(tmp_path)
    with pytest.raises(SystemExit) as saida:
        app.main(argv, deps)
    assert saida.value.code == 2
    assert servidores == [] and r.eventos == []


def test_painel_do_aplicativo_nao_oferece_o_laboratorio():
    from fastapi.testclient import TestClient

    painel = app.criar_app_do_painel()
    cliente = TestClient(painel, base_url="http://127.0.0.1")
    pagina = cliente.get("/").text
    token = pagina.split('name="pc-token" content="', 1)[1].split('"', 1)[0]
    info = cliente.get("/api/info", headers={"X-Post-Crypt-Token": token}).json()
    assert info["laboratorio"]["disponivel"] is False


def test_icone_ausente_devolve_none(monkeypatch, tmp_path):
    monkeypatch.setattr(app.sys, "_MEIPASS", str(tmp_path), raising=False)
    assert app.caminho_do_icone() is None
    (tmp_path / "post-crypt.ico").write_bytes(b"\x00")
    assert app.caminho_do_icone() == str(Path(tmp_path) / "post-crypt.ico")
