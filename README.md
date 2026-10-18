# Post-Crypt

Varredura local de prontidão pós-quântica para equipes de 1 a 3 pessoas.

Em uma execução, sem instalar agentes e sem que nada saia da rede, o Post-Crypt mostra quais serviços ainda negociam chaves vulneráveis ao *Harvest Now, Decrypt Later*, quais certificados estão para vencer, e separa o que é troca de chave do que é cifra simétrica — a confusão por trás do "já usamos AES-256, estamos seguros".

Projeto de Engenharia da Computação — Universidade Presbiteriana Mackenzie, 2026.

## Estado

| Incremento | Entrega | Situação |
| --- | --- | --- |
| **I0 — Esqueleto** | `postcrypt scan` para TLS, classificador por regras, JSON e tabela | **Pronto** |
| I1 — Inventário completo | Sonda SSH, SQLite, CBOM CycloneDX 1.6 | Próximo |
| I2 — Evidência | Relatório HTML/PDF, registro de certificados, assinatura ML-DSA e `verify`, painel web local | Planejado |
| I3 — Validação | Benchmarks sob latência e perda, POCs, testes de usabilidade | Planejado |

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
```

Alvo que não responde não some do resultado: vira **lacuna de visibilidade**.

## Como funciona

A sonda não completa o handshake TLS. Ela monta o próprio ClientHello oferecendo só os grupos que quer testar e envia `key_share` vazio. Um servidor que aceita algum desses grupos responde com *HelloRetryRequest* dizendo qual (RFC 8446, 4.1.4); um que não aceita responde com alerta. Assim dá para detectar X25519MLKEM768 e os demais grupos ML-KEM sem gerar chave pós-quântica e sem depender da versão do OpenSSL da máquina que varre.

Cada serviço recebe três respostas separadas:

| Pergunta | Exemplo de resposta |
| --- | --- |
| **Troca de chave** — o tráfego de hoje pode ser decifrado no futuro? | `X25519MLKEM768` → protegido · `x25519` → vulnerável a HNDL |
| **Cifra simétrica** — o conteúdo resiste a um adversário quântico? | `AES_256_GCM` → sim |
| **Autenticação** — até quando a assinatura do certificado vale? | `RSA-2048` → depreciado após 2030, proibido após 2035 (NIST IR 8547, rascunho) |

As regras ficam em [`src/postcrypt/rules/default.yaml`](src/postcrypt/rules/default.yaml), não no código. Quando um padrão muda, atualiza-se o arquivo, ou passa-se outro com `--rules`.

## Laboratório

Um nginx com OpenSSL 3.5 serve cinco casos com gabarito conhecido (híbrido, clássico, TLS 1.2 com troca de chave RSA, certificado vencendo, certificado vencido) e uma porta fechada.

```bash
python lab/gerar_certificados.py              # CA e certificados em lab/certs/ (fora do git)
docker compose -f lab/docker-compose.yml up -d
postcrypt scan lab/escopo-lab.yaml --json resultado.json
python lab/verificar_gabarito.py resultado.json
```

O CI roda exatamente isso a cada push e falha se algum serviço divergir do [gabarito](lab/gabarito.yaml).

Sem Docker, os mesmos casos e portas sobem em Python (o caso híbrido precisa de OpenSSL 3.5+, como o Python instalado pelo uv):

```bash
python lab/servidores_python.py          # Ctrl+C para parar
```

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
  certs.py        leitura de certificados X.509
  classify.py     troca de chave × cifra × autenticação
  rules/          regras em YAML
  output.py       tabela e JSON
lab/              nginx com gabarito, gerador de certificados, conferência
tests/            unitários, integração e PKI de teste
docs/decisoes/    registros de decisão
```

Fluxo de trabalho e divisão de módulos em [CONTRIBUTING.md](CONTRIBUTING.md). Decisões de escopo em [docs/decisoes](docs/decisoes).

## Equipe

Artur Siqueira Sudré · Luana Pavanelli · Murilo Rocha
