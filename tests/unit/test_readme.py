"""O README precisa continuar verdadeiro: exemplo de escopo válido e links que existem."""

import re
from pathlib import Path

import pytest

from postcrypt.scope import load_scope

RAIZ = Path(__file__).resolve().parents[2]
README = (RAIZ / "README.md").read_text(encoding="utf-8")


def test_exemplo_de_escopo_do_readme_passa_na_validacao(tmp_path):
    blocos = re.findall(r"```yaml\n(.*?)```", README, re.S)
    assert blocos, "o README perdeu o exemplo de escopo"
    arquivo = tmp_path / "escopo.yaml"
    arquivo.write_text(blocos[0], encoding="utf-8")
    escopo = load_scope(arquivo)
    assert {t.protocol for t in escopo.targets} == {"tls", "ssh"}


LINKS = sorted(set(re.findall(r"\]\(((?!https?://|#)[^)\s]+)\)", README)))


@pytest.mark.parametrize("link", LINKS)
def test_links_relativos_do_readme_existem(link):
    alvo = (RAIZ / link).resolve()
    assert alvo.is_relative_to(RAIZ), link
    assert alvo.exists(), link


def test_readme_conta_os_servicos_do_laboratorio():
    servicos = (RAIZ / "lab" / "escopo-lab.yaml").read_text(encoding="utf-8").count("- { host:")
    assert servicos == 9
    assert "nove serviços" in README
