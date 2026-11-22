import io
import logging
from pathlib import Path

import pytest

from postcrypt.desktop import registro


class Sistema:
    def __init__(self, stdout=None, stderr=None):
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture(autouse=True)
def _limpar_log():
    yield
    raiz = logging.getLogger()
    for h in [h for h in raiz.handlers if getattr(h, "_postcrypt", False)]:
        raiz.removeHandler(h)
        h.close()


def test_windows_usa_localappdata(tmp_path):
    pasta = registro.pasta_de_dados({"LOCALAPPDATA": str(tmp_path)}, "win32", Path("/casa"))
    assert pasta == tmp_path / "Post-Crypt"


def test_linux_usa_xdg_state(tmp_path):
    pasta = registro.pasta_de_dados({"XDG_STATE_HOME": str(tmp_path)}, "linux", Path("/casa"))
    assert pasta == tmp_path / "post-crypt"


@pytest.mark.parametrize("valor", ["", "relativa", "..\\..\\Windows", "./x"])
def test_variavel_vazia_ou_relativa_cai_na_pasta_do_usuario(valor):
    casa = Path("/casa").resolve()
    assert registro.pasta_de_dados({"LOCALAPPDATA": valor}, "win32", casa) == (
        casa / "AppData" / "Local" / "Post-Crypt"
    )
    assert registro.pasta_de_dados({"XDG_STATE_HOME": valor}, "linux", casa) == (
        casa / ".local" / "state" / "post-crypt"
    )


def test_registro_grava_em_arquivo_rotativo(tmp_path):
    arquivo = registro.configurar_registro(tmp_path)
    logging.getLogger("teste").info("evento de teste")
    for h in logging.getLogger().handlers:
        h.flush()
    assert arquivo == tmp_path / "logs" / "post-crypt.log"
    assert "evento de teste" in arquivo.read_text(encoding="utf-8")
    manipulador = next(h for h in logging.getLogger().handlers if getattr(h, "_postcrypt", False))
    assert manipulador.maxBytes == registro.TAMANHO_MAXIMO_LOG
    assert manipulador.backupCount == registro.ARQUIVOS_GUARDADOS


def test_configurar_duas_vezes_nao_duplica_o_manipulador(tmp_path):
    registro.configurar_registro(tmp_path)
    registro.configurar_registro(tmp_path)
    nossos = [h for h in logging.getLogger().handlers if getattr(h, "_postcrypt", False)]
    assert len(nossos) == 1


def test_pasta_sem_permissao_levanta_oserror(tmp_path):
    bloqueio = tmp_path / "arquivo"
    bloqueio.write_text("x")
    with pytest.raises(OSError):
        registro.configurar_registro(bloqueio)  # "logs" não pode nascer dentro de um arquivo


def test_saidas_ausentes_viram_devnull():
    sistema = Sistema()
    registro.garantir_saidas_padrao(sistema)
    assert sistema.stdout is not None and sistema.stderr is not None
    print("não quebra", file=sistema.stdout)
    sistema.stdout.close()
    sistema.stderr.close()


def test_saidas_existentes_ficam_como_estao():
    saida, erro = io.StringIO(), io.StringIO()
    sistema = Sistema(saida, erro)
    registro.garantir_saidas_padrao(sistema)
    assert sistema.stdout is saida and sistema.stderr is erro
