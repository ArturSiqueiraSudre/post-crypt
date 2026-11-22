"""Aplicativo de computador do Post-Crypt: o mesmo painel, numa janela própria.

Cada módulo tem uma responsabilidade:

- ``registro``: pasta de dados do usuário e log em arquivo (o programa não tem console);
- ``servidor``: sobe o servidor do painel em 127.0.0.1, numa porta livre, em segundo plano;
- ``janela``: mostra o painel numa janela própria ou, na falta dela, no navegador;
- ``avisos``: caixa de mensagem do sistema para erros que a pessoa precisa ver;
- ``autoteste``: confere, sem janela, se o programa empacotado responde;
- ``app``: só orquestra os módulos acima.
"""
