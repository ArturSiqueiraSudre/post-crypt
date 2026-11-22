"""Ponto de entrada do aplicativo de computador: só orquestra os outros módulos.

Fluxo: prepara o log, sobe o painel em 127.0.0.1, abre a janela (ou o navegador) e,
quando a pessoa fecha, desliga o servidor. Erros viram uma mensagem clara, nunca uma
janela em branco.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from postcrypt import __version__
from postcrypt.desktop import autoteste, avisos, janela, registro
from postcrypt.desktop.servidor import ErroServidor, ServidorPainel

TITULO = "Post-Crypt"
MENSAGEM_NAVEGADOR = (
    "O Post-Crypt abriu no seu navegador.\n\n"
    "Deixe esta mensagem aberta enquanto usa o painel. Clique em OK para encerrar o Post-Crypt."
)
MENSAGEM_FALHA = (
    "O Post-Crypt não conseguiu abrir.\n\n{motivo}\n\n"
    "Os detalhes ficam no arquivo de registro:\n{log}"
)

log = logging.getLogger(__name__)


def criar_app_do_painel() -> Any:
    """O mesmo painel da linha de comando, sem o laboratório de teste.

    O laboratório roda ``sys.executable`` com um script do repositório; no programa
    instalado, ``sys.executable`` é o próprio Post-Crypt.exe e não há repositório.
    """
    from postcrypt.painel import app as painel
    from postcrypt.painel.laboratorio import Laboratorio

    # create_app recebe regras como dict sem tipo; aqui só o laboratório importa.
    criar: Callable[..., Any] = painel.create_app  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    return criar(laboratorio=Laboratorio(None))


def caminho_do_icone() -> str | None:
    """Ícone da janela: ao lado do executável, quando empacotado."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    icone = base / "post-crypt.ico"
    return str(icone) if icone.is_file() else None


@dataclass
class Dependencias:
    """Tudo o que toca o sistema, injetável para testes."""

    criar_app: Callable[[], Any] = criar_app_do_painel
    criar_servidor: Callable[[Any], ServidorPainel] = ServidorPainel
    abrir_janela: Callable[..., bool] = janela.abrir_janela
    abrir_navegador: Callable[[str], bool] = janela.abrir_no_navegador
    aguardar_no_navegador: Callable[[str, str], None] = avisos.mostrar_informacao
    mostrar_erro: Callable[[str, str], None] = avisos.mostrar_erro
    rodar_autoteste: Callable[[str, str], dict[str, str]] = autoteste.executar
    pasta_de_dados: Callable[[], Path] = field(
        default=lambda: registro.pasta_de_dados(os.environ, sys.platform, Path.home())
    )
    icone: Callable[[], str | None] = caminho_do_icone


def ler_argumentos(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="Post-Crypt", description="Painel do Post-Crypt.")
    modo = parser.add_mutually_exclusive_group()
    modo.add_argument(
        "--navegador", action="store_true", help="abre no navegador em vez da janela própria"
    )
    modo.add_argument(
        "--autoteste", action="store_true", help="confere se o programa responde e encerra"
    )
    parser.add_argument("--version", action="version", version=f"post-crypt {__version__}")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, deps: Dependencias | None = None) -> int:
    deps = deps or Dependencias()
    registro.garantir_saidas_padrao(sys)
    args = ler_argumentos(argv)
    arquivo_log = _preparar_registro(deps)
    log.info("Post-Crypt %s iniciando (%s)", __version__, _modo(args))

    servidor: ServidorPainel | None = None
    try:
        servidor = deps.criar_servidor(deps.criar_app())
        url = servidor.iniciar()
        if args.autoteste:
            return _autoteste(url, deps)
        _mostrar_painel(url, forcar_navegador=args.navegador, deps=deps)
        return 0
    except (ErroServidor, OSError) as exc:
        log.exception("falha ao abrir o painel")
        if not args.autoteste:
            deps.mostrar_erro(TITULO, MENSAGEM_FALHA.format(motivo=exc, log=arquivo_log))
        return 1
    finally:
        if servidor is not None:
            servidor.parar()
        log.info("Post-Crypt encerrado")


def _modo(args: argparse.Namespace) -> str:
    if args.autoteste:
        return "autoteste"
    return "navegador" if args.navegador else "janela"


def _preparar_registro(deps: Dependencias) -> Path | str:
    try:
        return registro.configurar_registro(deps.pasta_de_dados())
    except OSError:
        # Sem onde gravar o log, o programa ainda funciona; só perde o registro.
        return "(registro indisponível)"


def _autoteste(url: str, deps: Dependencias) -> int:
    try:
        resumo = deps.rodar_autoteste(url, __version__)
    except autoteste.FalhaAutoteste as exc:
        log.error("autoteste falhou: %s", exc)
        print(f"autoteste falhou: {exc}", file=sys.stderr)
        return 2
    log.info("autoteste ok: versão %s, regras de %s", resumo["versao"], resumo["regras"])
    print(f"autoteste ok: versão {resumo['versao']}, regras de {resumo['regras']}")
    return 0


def _mostrar_painel(url: str, *, forcar_navegador: bool, deps: Dependencias) -> None:
    if not forcar_navegador and deps.abrir_janela(url, icone=deps.icone()):
        return
    if not deps.abrir_navegador(url):
        raise ErroServidor(f"nenhum navegador abriu o endereço {url}")
    deps.aguardar_no_navegador(TITULO, MENSAGEM_NAVEGADOR)


if __name__ == "__main__":
    sys.exit(main())
