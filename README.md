# Post-Crypt

Varredura local de prontidão pós-quântica para equipes de 1 a 3 pessoas.

Em uma execução, sem instalar agentes e sem que nada saia da rede, o Post-Crypt verifica os serviços TLS e SSH listados num arquivo de escopo e mostra:

- quais ainda negociam troca de chave vulnerável ao *Harvest Now, Decrypt Later*, separando troca de chave de cifra simétrica — a confusão por trás do "já usamos AES-256, estamos seguros";
- quais certificados e chaves de servidor precisam migrar, e quais certificados estão para vencer;
- que software e versão responde em cada serviço, e se o fabricante ainda dá suporte;
- o que se repete na rede: a mesma CA em vários serviços, o mesmo certificado em mais de um lugar, a mesma versão sem suporte espalhada.

Projeto de Engenharia da Computação — Universidade Presbiteriana Mackenzie, 2026.

## Estado

| Incremento | Entrega | Situação |
| --- | --- | --- |
| **I0 — Esqueleto** | `postcrypt scan` para TLS, classificador por regras, JSON e tabela | **Pronto** |
| **Painel web local** | Varredura pelo navegador, sem terminal (adiantado do I2) | **Pronto** |
| **Correlação de rede** | Achados que relacionam os alvos entre si, priorizados por impacto (estágio 1 da análise de rede) | **Pronto** |
| **Fingerprint de versão** | Produto e versão de cada serviço, suporte do fabricante e versão sem suporte repetida na rede (estágio 2) | **Pronto** |
| **Suporte a SSH** | Sonda SSH (banner e algoritmos anunciados), classificação pós-quântica e versão do OpenSSH (estágio 3) | **Pronto** |
| **Aplicativo para Windows** | Instalador com assistente, atalhos e desinstalador; o painel abre numa janela própria | **Pronto** |
| I1 — Inventário completo | SQLite, CBOM CycloneDX 1.6 | Próximo |
| I2 — Evidência | Relatório HTML/PDF, registro de certificados, assinatura ML-DSA e `verify` | Planejado |
| I3 — Validação | Benchmarks sob latência e perda, POCs, testes de usabilidade | Planejado |

## Instalar no Windows

Baixe `Post-Crypt-Setup-<versão>.exe` na página [Releases](https://github.com/ArturSiqueiraSudre/post-crypt/releases) e execute. O assistente, em português, deixa escolher a pasta, criar o atalho na área de trabalho e no menu Iniciar, e abrir o programa ao terminar. Não pede senha de administrador: por padrão instala só para o usuário, em `%LOCALAPPDATA%\Programs\Post-Crypt`. Quem é administrador pode escolher instalar para todos. Para remover, use "Adicionar ou remover programas".

O Post-Crypt abre numa janela própria, com o mesmo painel descrito abaixo, e encerra quando a janela é fechada. A janela usa o WebView2, que já vem no Windows 10 e 11; se ele faltar, o painel abre no navegador padrão e uma mensagem fica aberta até a pessoa encerrar. Nada é instalado além do programa: nenhum serviço, nenhuma tarefa agendada. O registro de eventos (sem token e sem dados de varredura) fica em `%LOCALAPPDATA%\Post-Crypt\logs`.

Requer Windows 10 ou 11, 64 bits. Ao lado de cada instalador vai um arquivo `.sha256` para conferir o download (`Get-FileHash Post-Crypt-Setup-<versão>.exe`). Enquanto o instalador não for assinado digitalmente, o Windows pode mostrar o aviso "O Windows protegeu o computador": clique em **Mais informações** e em **Executar assim mesmo**.

## Painel (sem terminal)

Para quem não usa linha de comando: no Windows, dê **dois cliques em `abrir-painel.cmd`** na pasta do projeto. Na primeira vez ele prepara o ambiente com o [uv](https://docs.astral.sh/uv/) (`winget install astral-sh.uv`); depois abre direto no navegador. Em qualquer sistema, o mesmo painel abre com:

```bash
postcrypt painel                  # abre http://127.0.0.1:8765 no navegador
postcrypt painel --porta 9000 --sem-navegador
```

No painel a pessoa preenche quem autorizou, lista os serviços (ou abre um arquivo de escopo), clica em **Varrer** e recebe, para cada serviço, três respostas em linguagem simples: se o tráfego gravado hoje pode ser aberto no futuro, se a cifra é forte e se o certificado (ou, em SSH, a chave do servidor) está em dia. Cada serviço pode ser marcado como TLS ou SSH e, em TLS, pode ter a identificação da versão autorizada (caixa **Identificar**). O resultado também mostra a versão do software e a seção **A rede como um todo**, e pode ser baixado no mesmo JSON da linha de comando. No clone do repositório, o botão **Usar laboratório de teste** carrega os nove serviços do laboratório (oito ligados e uma porta fechada de propósito) e desliga tudo ao fechar o painel.

O painel segue as regras da ferramenta: escuta só em `127.0.0.1`, recusa pedidos que não venham da própria página (token por execução e checagem do cabeçalho `Host`, contra DNS rebinding), passa pelo mesmo validador de escopo, não grava nada em disco e nunca monta dados da varredura como HTML. As cores da marca ficam em `:root`, no topo de `src/postcrypt/painel/static/painel.css`.

## Como usar

Requer Python 3.12+.

```bash
pip install -e .                     # ou: uv pip install -e .
postcrypt scan examples/escopo-exemplo.yaml
postcrypt scan escopo.yaml --json resultado.json
postcrypt scan escopo.yaml --fail-on-vulnerable   # código 1 se houver alvo vulnerável (pipelines)
postcrypt scan escopo.yaml --timeout 3 --workers 4 --rules minhas-regras.yaml
postcrypt version
```

Saída contra o laboratório em Python (o terminal mostra depois os achados de cada alvo e a seção **Rede**):

```text
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Alvo             ┃ Status                 ┃ Troca de chave                                  ┃ Cifra simétrica               ┃ Certificado / chave          ┃ Vence em ┃ Software                     ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ tls-hibrido      │ Híbrido PQC            │ X25519MLKEM768                                  │ AES_256_GCM                   │ EC secp256r1                 │    364 d │ nginx 1.30.6                 │
│ 127.0.0.1:8441   │                        │                                                 │                               │                              │          │                              │
│ tls-classico     │ Vulnerável a HNDL      │ secp256r1                                       │ AES_256_GCM                   │ EC secp256r1                 │    364 d │ Apache httpd 2.4.58          │
│ 127.0.0.1:8442   │                        │                                                 │                               │                              │          │ OpenSSL 3.0.13 (sem suporte) │
│ tls-legado       │ Vulnerável a HNDL      │ RSA                                             │ AES_256_GCM                   │ RSA-2048                     │    364 d │ Apache httpd 2.4.58          │
│ 127.0.0.1:8443   │                        │                                                 │                               │                              │          │ OpenSSL 3.0.13 (sem suporte) │
│ tls-vencendo     │ Híbrido PQC            │ X25519MLKEM768                                  │ AES_256_GCM                   │ EC secp256r1                 │      9 d │ —                            │
│ 127.0.0.1:8444   │                        │                                                 │                               │                              │          │                              │
│ tls-vencido      │ Híbrido PQC            │ X25519MLKEM768                                  │ AES_256_GCM                   │ EC secp256r1                 │  vencido │ não autorizado               │
│ 127.0.0.1:8445   │                        │                                                 │                               │                              │          │                              │
│ tls-desconhecido │ Híbrido PQC            │ X25519MLKEM768                                  │ AES_256_GCM                   │ EC secp256r1                 │    364 d │ Caddy 2.8.4                  │
│ 127.0.0.1:8446   │                        │                                                 │                               │                              │          │                              │
│ ssh-hibrido      │ Híbrido PQC            │ mlkem768x25519-sha256, sntrup761x25519-sha512,  │ chacha20-poly1305@openssh.com │ rsa-sha2-512, rsa-sha2-256 … │        — │ OpenSSH 10.6                 │
│ 127.0.0.1:8447   │                        │ sntrup761x25519-sha512@openssh.com              │                               │                              │          │                              │
│ ssh-classico     │ Vulnerável a HNDL      │ curve25519-sha256                               │ aes128-ctr                    │ ssh-rsa, rsa-sha2-512 …      │        — │ OpenSSH 8.9p1 (sem suporte)  │
│ 127.0.0.1:8448   │                        │                                                 │                               │                              │          │                              │
│ desligado        │ Lacuna de visibilidade │ —                                               │ —                             │ —                            │        — │ —                            │
│ 127.0.0.1:8449   │                        │                                                 │                               │                              │          │                              │
└──────────────────┴────────────────────────┴─────────────────────────────────────────────────┴───────────────────────────────┴──────────────────────────────┴──────────┴──────────────────────────────┘
Híbrido PQC: 5 · Vulnerável a HNDL: 3 · Lacuna de visibilidade: 1
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
  - host: bastion.exemplo.com.br
    port: 22
    protocol: ssh                 # tls é o padrão
```

Alvo que não responde não some do resultado: vira **lacuna de visibilidade**.

`protocol` é `tls` (padrão) ou `ssh`. Num alvo SSH, `sni` e `http_fingerprint` são recusados ([decisão 0003](docs/decisoes/0003-suporte-a-ssh.md)).

`http_fingerprint` é opcional e vem desligado. Só com `true` (booleano, sem aspas) a varredura faz, naquele alvo, o único pedido HTTP do fingerprint de versão ([decisão 0002](docs/decisoes/0002-fingerprint-de-versao.md)).

## Como funciona

A sonda não completa o handshake TLS. Ela monta o próprio ClientHello oferecendo só os grupos que quer testar e envia `key_share` vazio. Um servidor que aceita algum desses grupos responde com *HelloRetryRequest* dizendo qual (RFC 8446, 4.1.4); um que não aceita responde com alerta. Assim dá para detectar X25519MLKEM768 e os demais grupos ML-KEM sem gerar chave pós-quântica e sem depender da versão do OpenSSL da máquina que varre.

Cada serviço recebe três respostas separadas:

| Pergunta | Exemplo de resposta |
| --- | --- |
| **Troca de chave** — o tráfego de hoje pode ser decifrado no futuro? | `X25519MLKEM768` → protegido · `x25519` → vulnerável a HNDL |
| **Cifra simétrica** — o conteúdo resiste a um adversário quântico? | `AES_256_GCM` → sim |
| **Autenticação** — até quando a assinatura do certificado vale? | `RSA-2048` → depreciado após 2030, proibido após 2035 (NIST IR 8547, rascunho) |

### SSH

A sonda SSH também não autentica nem faz troca de chave. O servidor SSH anuncia em claro, logo ao conectar, o banner de versão e a lista de algoritmos que aceita (mensagem KEXINIT, RFC 4253). A sonda lê o banner, manda a própria identificação, lê a lista e fecha: uma conexão, um prazo total, nenhuma biblioteca nova. As mesmas três perguntas valem:

| Pergunta | Exemplo de resposta |
| --- | --- |
| **Troca de chave** | `mlkem768x25519-sha256` ou `sntrup761x25519-sha512` aceitos → protegido · só `curve25519-sha256` → vulnerável a HNDL |
| **Cifra simétrica** | `chacha20-poly1305@openssh.com` → forte · `aes128-cbc` ainda aceito → achado `SSH_WEAK_CIPHER` |
| **Autenticação** | `ssh-ed25519`, `rsa-sha2-512` → clássicas, proibidas após 2035 · `ssh-rsa` (SHA-1) → achado `SSH_WEAK_HOST_KEY` |

O banner (`OpenSSH_9.6p1 Ubuntu-3ubuntu13`) entra no fingerprint de versão sem pedido extra, porque o próprio servidor o envia.

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

São nove serviços com gabarito conhecido, nas portas 8441 a 8449 de `127.0.0.1` ([escopo](lab/escopo-lab.yaml)): seis TLS (híbrido, clássico, TLS 1.2 com troca de chave RSA, certificado vencendo, certificado vencido e um produto sem regra cadastrada), dois SSH (híbrido e só clássico) e uma porta fechada de propósito. No Docker, um nginx com OpenSSL 3.5 serve os casos TLS e um OpenSSH de verdade serve os casos SSH (configurações em `lab/ssh/`).

```bash
python lab/gerar_certificados.py              # CA e certificados em lab/certs/ (fora do git)
docker compose -f lab/docker-compose.yml up -d
postcrypt scan lab/escopo-lab.yaml --json resultado.json
python lab/verificar_gabarito.py resultado.json --sem-fingerprint
```

O CI roda exatamente isso a cada push, no Linux, e falha se algum serviço divergir do [gabarito](lab/gabarito.yaml) ou se algum achado de rede divergir do [gabarito de rede](lab/gabarito-rede.yaml). Outro job, no Windows, roda o pytest e o `scripts/testar-local.ps1` com o laboratório em Python. Todos os certificados do laboratório saem da mesma CA clássica, então o achado de ponto único de falha aparece com os seis serviços TLS.

Sem Docker, os mesmos casos e portas sobem em Python. Os dois SSH imitam o banner e a lista de algoritmos de um OpenSSH real, e o caso TLS híbrido precisa de um Python com OpenSSL 3.5+, como o instalado pelo uv:

```bash
python lab/servidores_python.py          # Ctrl+C para parar
postcrypt scan lab/escopo-lab.yaml --json resultado.json
python lab/verificar_gabarito.py resultado.json
```

Resultado esperado: `9/9 serviços conferem`, `4/4 achados de rede conferem` e `9/9 fingerprints conferem`.

No laboratório em Python, quatro serviços respondem ao `HEAD /` com um cabeçalho `Server` conhecido de antemão (um deles de um produto sem regra, que precisa sair "suporte não avaliado"), e o [gabarito de fingerprint](lab/gabarito-fingerprint.yaml) confere produto, versão e suporte; um serviço autorizado não fala HTTP (precisa sair "não observado") e outro não tem a autorização. No Docker, o nginx responde HTTP em todas as portas com a versão real da imagem, por isso lá a conferência usa `--sem-fingerprint`.

## Desenvolvimento

```bash
uv venv --python 3.13 && uv pip install -e ".[dev]"   # Python do uv já traz OpenSSL 3.5
pytest                      # unitários + integração (servidores TLS e SSH locais)
ruff check src tests lab && ruff format --check src tests lab
bandit -q -r src -c pyproject.toml
pip-audit --skip-editable
```

Dois testes dependem do ambiente e são pulados quando ele falta, sem afetar o restante: o do servidor TLS híbrido precisa de um Python com OpenSSL 3.5+, e os dois com OpenSSH de verdade precisam do `sshd` instalado (no Windows são sempre pulados e rodam no CI).

No Windows, uma bateria completa (ambiente, ruff, pytest, bandit, pip-audit e laboratório: Docker se estiver aberto, senão Python) roda com:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\testar-local.ps1
powershell -ExecutionPolicy Bypass -File scripts\testar-local.ps1 -Laboratorio python   # força o laboratório sem Docker
```

Os logs de cada etapa e o `resumo.txt` ficam em `resultado-testes\`.

### Gerar o instalador

O instalador sai do PyInstaller (executável em pasta, sem console) e do [Inno Setup 6](https://jrsoftware.org/isinfo.php). No Windows, com o uv e o Inno Setup instalados (`winget install astral-sh.uv` e `winget install JRSoftware.InnoSetup`):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\gerar-instalador.ps1
```

O script roda os testes, gera `dist\Post-Crypt\Post-Crypt.exe`, confere o executável com `Post-Crypt.exe --autoteste` (sobe o painel sem janela, testa a página e o token, e sai com 0) e monta `dist\instalador\Post-Crypt-Setup-<versão>.exe` com o `.sha256` ao lado. A versão vem do `pyproject.toml`.

No GitHub, o workflow [Instalador Windows](.github/workflows/instalador.yml) faz o mesmo a cada push na `main` (o instalador fica nos artefatos da execução) e, numa tag `v<versão>` igual à do `pyproject.toml`, publica o instalador numa Release. Os arquivos do empacotamento ficam em `packaging/windows/`; o `AppId` do `post-crypt.iss` nunca deve mudar, porque é por ele que uma versão nova atualiza a anterior.

```text
src/postcrypt/
  cli.py           comandos postcrypt scan, painel e version
  scope.py         arquivo de escopo e validações
  scanner.py       orquestração paralela, só nos alvos do escopo
  tls/             ClientHello, leitura do ServerHello, sonda TLS
  ssh/             leitura do banner e do KEXINIT, sonda SSH
  http_banner/     pedido HEAD mínimo do fingerprint e leitura da resposta
  probe_errors.py  erro de conexão comum às sondas
  fingerprint.py   produto, versão e suporte do fabricante (lógica pura)
  certs.py         leitura de certificados X.509
  classify.py      troca de chave × cifra × autenticação (TLS)
  classify_ssh.py  as mesmas três perguntas para SSH
  network.py       correlação entre alvos e prioridade por impacto
  rules/           regras em YAML
  output.py        tabela, seção de rede e JSON
  painel/          servidor local do painel (FastAPI) e a página em static/
  desktop/         aplicativo de computador: janela, servidor em segundo plano, autoteste
packaging/windows/ PyInstaller (.spec), Inno Setup (.iss), ícone e imagens do instalador
lab/               escopo e gabaritos, servidores em Python, nginx e OpenSSH (Docker), conferência
examples/          arquivos de escopo de exemplo (um válido, um recusado)
scripts/           bateria de testes, gerador do instalador e roteiro de demonstração (PowerShell)
tests/             unitários, integração e servidores de teste (TLS, SSH, PKI)
docs/decisoes/     registros de decisão
abrir-painel.cmd   abre o painel com dois cliques no Windows
```

Fluxo de trabalho e divisão de módulos em [CONTRIBUTING.md](CONTRIBUTING.md). Decisões de escopo em [docs/decisoes](docs/decisoes).

## Equipe

Artur Siqueira Sudré · Luana Pavanelli · Murilo Rocha
