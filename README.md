# Post-Crypt

Varredura local de prontidão pós-quântica para equipes de 1 a 3 pessoas.

Em uma execução, sem instalar agentes e sem que nada saia da rede, o Post-Crypt mostra quais serviços ainda negociam chaves vulneráveis ao *Harvest Now, Decrypt Later*, quais certificados estão para vencer, e separa o que é troca de chave do que é cifra simétrica — a confusão por trás do "já usamos AES-256, estamos seguros".

Projeto de Engenharia da Computação — Universidade Presbiteriana Mackenzie, 2026.

## Estado

| Incremento | Entrega | Situação |
| --- | --- | --- |
| **I0 — Esqueleto** | `postcrypt scan` para TLS, classificador por regras, JSON e tabela | **Pronto** |
| **Painel web local** | Varredura pelo navegador, sem terminal (adiantado do I2) | **Pronto** |
| **Correlação de rede** | Achados que relacionam os alvos entre si, priorizados por impacto (estágio 1 da análise de rede) | **Pronto** |
| **Fingerprint de versão** | Produto e versão de cada serviço, suporte do fabricante e versão sem suporte repetida na rede (estágio 2) | **Pronto** |
| I1 — Inventário completo | Sonda SSH, SQLite, CBOM CycloneDX 1.6 | Próximo |
| I2 — Evidência | Relatório HTML/PDF, registro de certificados, assinatura ML-DSA e `verify` | Planejado |
| I3 — Validação | Benchmarks sob latência e perda, POCs, testes de usabilidade | Planejado |

## Painel (sem terminal)

Para quem não usa linha de comando: no Windows, dê **dois cliques em `abrir-painel.cmd`** na pasta do projeto. Na primeira vez ele prepara o ambiente com o [uv](https://docs.astral.sh/uv/) (`winget install astral-sh.uv`); depois abre direto no navegador. Em qualquer sistema, o mesmo painel abre com:

```bash
postcrypt painel                  # abre http://127.0.0.1:8765 no navegador
postcrypt painel --porta 9000 --sem-navegador
```

No painel a pessoa preenche quem autorizou, lista os serviços (ou abre um arquivo de escopo), clica em **Varrer** e recebe, para cada serviço, três respostas em linguagem simples: se o tráfego gravado hoje pode ser aberto no futuro, se a cifra é forte e se o certificado está em dia. O resultado pode ser baixado no mesmo JSON da linha de comando. No clone do repositório, o botão **Usar laboratório de teste** liga os sete serviços do laboratório e desliga ao fechar o painel.

O painel segue as regras da ferramenta: escuta só em `127.0.0.1`, recusa pedidos que não venham da própria página (token por execução e checagem do cabeçalho `Host`, contra DNS rebinding), passa pelo mesmo validador de escopo, não grava nada em disco e nunca monta dados da varredura como HTML. As cores da marca ficam em `:root`, no topo de `src/postcrypt/painel/static/painel.css`.

## Como usar

Requer Python 3.12+.

```bash
pip install -e .                     # ou: uv pip install -e .
postcrypt scan examples/escopo-exemplo.yaml
postcrypt scan escopo.yaml --json resultado.json
postcrypt scan escopo.yaml --fail-on-vulnerable   # código 1 se houver alvo vulnerável (pipelines)
```

Saída contra o laboratório:

```text
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Alvo         ┃ Status                 ┃ Troca de chave ┃ Cifra simétrica ┃ Certificado  ┃ Vence em ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ tls-hibrido  │ Híbrido PQC            │ X25519MLKEM768 │ AES_256_GCM     │ EC secp256r1 │    364 d │
│ tls-classico │ Vulnerável a HNDL      │ secp256r1      │ AES_256_GCM     │ EC secp256r1 │    364 d │
│ tls-legado   │ Vulnerável a HNDL      │ RSA            │ AES_256_GCM     │ RSA-2048     │    364 d │
│ tls-vencendo │ Híbrido PQC            │ X25519MLKEM768 │ AES_256_GCM     │ EC secp256r1 │      9 d │
│ desligado    │ Lacuna de visibilidade │ —              │ —               │ —            │        — │
└──────────────┴────────────────────────┴────────────────┴─────────────────┴──────────────┴──────────┘
```

### Arquivo de escopo

O Post-Crypt só contata o que está listado. Não há descoberta de rede, faixas de IP nem curingas, e o arquivo precisa dizer quem autorizou a varredura e quando.

```yaml
authorization:
  by: "Maria Souza (CISO)"
  date: 2026-10-17
  reference: "Termo de escopo nº 01/2026"

targets:
  - host: vpn.exemplo.com.br
    port: 443
    label: Portal VPN
  - host: 10.0.10.25
    port: 8443
    label: API do core bancário
    owner: third_party            # ativo de fornecedor
    sni: api.fornecedor.com.br
  - host: intranet.exemplo.com.br
    port: 443
    http_fingerprint: true        # autoriza 1 pedido HEAD / para identificar a versão
```

Alvo que não responde não some do resultado: vira **lacuna de visibilidade**.

`http_fingerprint` é opcional e vem desligado. Só com `true` (booleano, sem aspas) a varredura faz, naquele alvo, o único pedido HTTP do fingerprint de versão ([decisão 0002](docs/decisoes/0002-fingerprint-de-versao.md)).

## Como funciona

A sonda não completa o handshake TLS. Ela monta o próprio ClientHello oferecendo só os grupos que quer testar e envia `key_share` vazio. Um servidor que aceita algum desses grupos responde com *HelloRetryRequest* dizendo qual (RFC 8446, 4.1.4); um que não aceita responde com alerta. Assim dá para detectar X25519MLKEM768 e os demais grupos ML-KEM sem gerar chave pós-quântica e sem depender da versão do OpenSSL da máquina que varre.

Cada serviço recebe três respostas separadas:

| Pergunta | Exemplo de resposta |
| --- | --- |
| **Troca de chave** — o tráfego de hoje pode ser decifrado no futuro? | `X25519MLKEM768` → protegido · `x25519` → vulnerável a HNDL |
| **Cifra simétrica** — o conteúdo resiste a um adversário quântico? | `AES_256_GCM` → sim |
| **Autenticação** — até quando a assinatura do certificado vale? | `RSA-2048` → depreciado após 2030, proibido após 2035 (NIST IR 8547, rascunho) |

### A rede como um todo

Com dois ou mais alvos, a varredura também compara os serviços entre si. Nada novo é coletado: a correlação só lê o que a sonda e o fingerprint já observaram.

| Achado | O que relaciona |
| --- | --- |
| `NET_SHARED_CLASSICAL_CA` | A mesma autoridade certificadora, de assinatura clássica, emitiu o certificado de vários alvos: ponto único de falha |
| `NET_DUPLICATE_LEAF` | O mesmo certificado de servidor aparece em mais de um alvo |
| `NET_HNDL_EXPOSURE` | Proporção dos ativos próprios avaliados que só faz troca de chave clássica |
| `NET_VISIBILITY_GAP` | Quanto do escopo não respondeu ou é de terceiros |
| `NET_OUTDATED_VERSION` | A mesma versão de software, sem suporte do fabricante, em vários alvos (estágio 2) |

Cada achado traz os alvos afetados e uma prioridade, que é o peso da severidade multiplicado pelo número de alvos. Os achados aparecem numa seção própria do terminal, na chave `network` do JSON e na etapa Resultado do painel. Com um alvo só não há achado de rede. Uma CA cujo algoritmo não tem regra cadastrada vira `NET_SHARED_CA_UNCLASSIFIED`, em vez de ser dada como clássica.

### Versão do software (fingerprint)

Saber que software responde do outro lado muda a prioridade: um OpenSSL abaixo do 3.5 não negocia ML-KEM, e um que o fabricante não corrige mais acumula falhas. Para cada alvo, o fingerprint junta dois sinais:

| Sinal | De onde vem | Confiança |
| --- | --- | --- |
| Cabeçalhos `Server` e `X-Powered-By` | Um único `HEAD /` no mesmo host e porta, só com `http_fingerprint: true` | O servidor declara; pacotes de distribuição podem ter correções sem mudar o número |
| Assinatura da pilha TLS (estilo JA4S) | Ordem das extensões do ServerHello que a sonda já recebia: nenhuma conexão a mais | Heurística: só vira nome quando cadastrada nas regras e nunca gera achado sozinha |

O resultado de cada alvo fica na chave `fingerprint` do JSON, com a situação (`observed`, `not_observed`, `not_authorized` ou `unavailable`), os produtos com versão e suporte do fabricante, e se houve pedido HTTP. Sem sinal suficiente, a resposta é "não observado", nunca um chute. Na rede, `NET_OUTDATED_VERSION` aponta a mesma versão sem suporte em dois ou mais alvos. O suporte de cada produto fica na seção `fingerprint` das regras e precisa ser revisado a cada atualização.

As regras ficam em [`src/postcrypt/rules/default.yaml`](src/postcrypt/rules/default.yaml), não no código. Quando um padrão muda, atualiza-se o arquivo, ou passa-se outro com `--rules`.

## Laboratório

Um nginx com OpenSSL 3.5 serve seis casos com gabarito conhecido (híbrido, clássico, TLS 1.2 com troca de chave RSA, certificado vencendo, certificado vencido e um serviço para o banner de produto desconhecido) e uma porta fechada.

```bash
python lab/gerar_certificados.py              # CA e certificados em lab/certs/ (fora do git)
docker compose -f lab/docker-compose.yml up -d
postcrypt scan lab/escopo-lab.yaml --json resultado.json
python lab/verificar_gabarito.py resultado.json --sem-fingerprint
```

O CI roda exatamente isso a cada push e falha se algum serviço divergir do [gabarito](lab/gabarito.yaml) ou se algum achado de rede divergir do [gabarito de rede](lab/gabarito-rede.yaml). Todos os certificados do laboratório saem da mesma CA clássica, então o achado de ponto único de falha aparece com os seis serviços TLS.

Sem Docker, os mesmos casos e portas sobem em Python (o caso híbrido precisa de OpenSSL 3.5+, como o Python instalado pelo uv):

```bash
python lab/servidores_python.py          # Ctrl+C para parar
postcrypt scan lab/escopo-lab.yaml --json resultado.json
python lab/verificar_gabarito.py resultado.json
```

No laboratório em Python, quatro serviços respondem ao `HEAD /` com um cabeçalho `Server` conhecido de antemão (um deles de um produto sem regra, que precisa sair "suporte não avaliado"), e o [gabarito de fingerprint](lab/gabarito-fingerprint.yaml) confere produto, versão e suporte; um serviço autorizado não fala HTTP (precisa sair "não observado") e outro não tem a autorização. No Docker, o nginx responde HTTP em todas as portas com a versão real da imagem, por isso lá a conferência usa `--sem-fingerprint`.

## Desenvolvimento

```bash
uv venv --python 3.13 && uv pip install -e ".[dev]"   # Python do uv já traz OpenSSL 3.5
pytest                      # unitários + integração (servidores TLS locais)
ruff check src tests lab && ruff format --check src tests lab
bandit -q -r src -c pyproject.toml
pip-audit --skip-editable
```

O teste de integração do servidor híbrido precisa de um Python com OpenSSL 3.5+; sem ele, o teste é pulado e o restante roda normalmente.

No Windows, uma bateria completa (ambiente, ruff, pytest, bandit, pip-audit e laboratório: Docker se estiver aberto, senão Python) roda com:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\testar-local.ps1
powershell -ExecutionPolicy Bypass -File scripts\testar-local.ps1 -Laboratorio python   # força o laboratório sem Docker
```

Os logs de cada etapa e o `resumo.txt` ficam em `resultado-testes\`.

```text
src/postcrypt/
  cli.py          comando postcrypt
  scope.py        arquivo de escopo e validações
  scanner.py      orquestração paralela, só nos alvos do escopo
  tls/            ClientHello, leitura do ServerHello, sonda
  http_banner/    pedido HEAD mínimo do fingerprint e leitura da resposta
  fingerprint.py  produto, versão e suporte do fabricante (lógica pura)
  certs.py        leitura de certificados X.509
  classify.py     troca de chave × cifra × autenticação
  network.py      correlação entre alvos e prioridade por impacto
  rules/          regras em YAML
  output.py       tabela, seção de rede e JSON
lab/              nginx com gabarito, gerador de certificados, conferência
tests/            unitários, integração e PKI de teste
docs/decisoes/    registros de decisão
```

Fluxo de trabalho e divisão de módulos em [CONTRIBUTING.md](CONTRIBUTING.md). Decisões de escopo em [docs/decisoes](docs/decisoes).

## Equipe

Artur Siqueira Sudré · Luana Pavanelli · Murilo Rocha
