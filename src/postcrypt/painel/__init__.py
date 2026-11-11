"""Painel web local: a varredura sem terminal, para quem não é especialista.

O painel só escuta em 127.0.0.1, só aceita pedidos da própria página (token
gerado a cada execução) e passa pelo mesmo arquivo de escopo da linha de
comando. Nada é gravado em disco: o resultado só sai quando a pessoa baixa.
"""

from postcrypt.painel.app import create_app

__all__ = ["create_app"]
