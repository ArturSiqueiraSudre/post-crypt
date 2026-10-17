# Como contribuir

## Fluxo

1. Crie uma branch a partir de `main`: `feat/sonda-ssh`, `fix/timeout-tls`, `docs/readme`.
2. Faça commits pequenos no formato `tipo(escopo): descrição`. Tipos: `feat`, `fix`, `test`, `docs`, `ci`, `chore`, `refactor`.
3. Abra um pull request. O CI precisa passar: ruff, pytest, bandit, pip-audit e o gabarito do laboratório.
4. Outra pessoa do grupo revisa antes do merge.

Referencie o item do YouTrack no PR (ex.: `6I-22`).

## Divisão de módulos

Cada integrante é dono de um módulo e dos testes dele. O modelo da disciplina pede, por integrante, ao menos um teste de cada tipo: unitário, integração, funcionamento, regressão, aceitação, desempenho e segurança.

| Integrante | Módulos |
| --- | --- |
| Artur | Sonda TLS, classificador, assinatura ML-DSA |
| Luana | Escopo, sonda SSH, banco SQLite, CBOM, relatório |
| Murilo | Laboratório, CI, painel web, empacotamento |

## Regras que não mudam

- Nada sai da máquina do cliente. Nenhuma dependência de serviço externo em tempo de execução.
- A ferramenta só contata alvos do arquivo de escopo. Qualquer conexão nova passa pela mesma validação.
- Não implementamos primitivos criptográficos: usamos `cryptography` (OpenSSL 3.5+) ou `liboqs-python`.
- Chaves e certificados do laboratório são gerados localmente e nunca entram no git.
- Resultados de varreduras reais não entram no repositório.
