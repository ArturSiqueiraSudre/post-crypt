"""Interface de linha de comando: ``postcrypt``."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from postcrypt import __version__
from postcrypt.classify import HNDL, load_rules
from postcrypt.output import render_table, write_json
from postcrypt.scanner import run_scan
from postcrypt.scope import ScopeError, load_scope

app = typer.Typer(
    help="Post-Crypt: varredura local de prontidão pós-quântica.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)


@app.command()
def scan(
    scope_file: Annotated[Path, typer.Argument(help="Arquivo YAML com os alvos autorizados.")],
    json_out: Annotated[
        str | None,
        typer.Option("--json", help="Grava o resultado em JSON neste caminho ('-' = terminal)."),
    ] = None,
    rules_file: Annotated[
        Path | None, typer.Option("--rules", help="Regras alternativas em YAML.")
    ] = None,
    timeout: Annotated[float, typer.Option(help="Timeout por conexão, em segundos.")] = 5.0,
    workers: Annotated[int, typer.Option(help="Alvos varridos em paralelo.")] = 8,
    fail_on_vulnerable: Annotated[
        bool,
        typer.Option(
            "--fail-on-vulnerable",
            help="Sai com código 1 se algum alvo for vulnerável a HNDL (útil em pipelines).",
        ),
    ] = False,
) -> None:
    """Varre os serviços TLS listados no arquivo de escopo."""
    try:
        scope = load_scope(scope_file)
        rules = load_rules(rules_file)
    except (ScopeError, ValueError, OSError) as exc:
        err.print(f"[red]Erro:[/red] {exc}")
        raise typer.Exit(2) from exc

    quiet = json_out == "-"
    if not quiet:
        auth = scope.authorization
        console.print(
            f"Varredura autorizada por [bold]{auth.by}[/bold] em {auth.date}"
            + (f" ({auth.reference})" if auth.reference else "")
            + f" · {len(scope.targets)} alvo(s)"
        )

    result = run_scan(scope, rules, timeout=timeout, workers=workers)

    if json_out:
        text = write_json(result, json_out)
        if quiet:
            typer.echo(text)
        else:
            console.print(f"JSON gravado em {json_out}")
    if not quiet:
        render_table(result, console)

    if fail_on_vulnerable and result.counts().get(HNDL):
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Mostra a versão instalada."""
    typer.echo(f"post-crypt {__version__}")


if __name__ == "__main__":
    app()
