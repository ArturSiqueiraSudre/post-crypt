# 0002 — Fingerprint de versão de serviço (Estágio 2)

- **Situação:** aceita
- **Data:** 20/11/2026

## Contexto

Até o Estágio 1, a sonda TLS só negocia o handshake: sabe o que o serviço aceita em criptografia, mas não sabe que software responde do outro lado. As entrevistas de validação pediram um relatório da rede que mostre também ativos e versões. Saber que dois serviços rodam o mesmo OpenSSL sem suporte, por exemplo, muda a prioridade de migração: além de não ter correções, só o OpenSSL 3.5+ negocia ML-KEM.

Identificar a versão exige um sinal que o handshake sozinho não dá. O jeito mais direto é ler o cabeçalho `Server` de uma resposta HTTP, mas isso é uma interação nova, de camada de aplicação, que a autorização da decisão 0001 não previa.

## Decisão

1. **Módulo novo, de responsabilidade única.** `fingerprint.py` é lógica pura: recebe o que já foi observado e as regras em YAML e devolve produto, versão e suporte do fabricante. Não julga a postura criptográfica (isso continua no `classify.py`) e não faz I/O. O pedido HTTP fica num adaptador separado (`http_banner/probe.py`), e a leitura da resposta num parser próprio (`http_banner/parse.py`).
2. **Autorização própria, alvo a alvo (opt-in).** O pedido HTTP só sai quando o alvo tem `http_fingerprint: true` no arquivo de escopo. Sem o campo, o alvo é varrido exatamente como antes, e o fingerprint aparece como "não autorizado". Um escopo assinado antes deste estágio continua gerando o mesmo tráfego. O campo aceita só booleano: `"true"` entre aspas, `sim` ou `1` são recusados.
3. **Um pedido, mínimo, no mesmo alvo.** `HEAD /` com `Connection: close`, no mesmo host, porta e nome (SNI) já autorizados, com prazo total de no máximo 10 s, somando conexão TCP, handshake TLS e leitura, e teto de 16 KiB para a resposta. O adaptador não segue redirecionamento, não lê corpo, não tenta outro caminho, outra porta nem outro endereço, e não envia cookie, credencial ou segredo. O `User-Agent` declara que é a identificação autorizada do Post-Crypt.
4. **Sinal de pilha TLS sem tráfego extra.** A sonda passa a guardar a ordem das extensões do ServerHello que ela já recebia. O fingerprint calcula uma assinatura no layout do JA4S. Ela só vira nome de pilha quando está cadastrada em `rules/default.yaml` (`fingerprint.tls_stacks`, vazio por enquanto) e nunca gera achado sozinha, porque essa heurística tem falsos positivos conhecidos.
5. **Nunca adivinhar.** Sem resposta HTTP, resposta fora do formato, cabeçalho sem software ou versão escondida, o resultado é "não observado" ou "suporte não avaliado", com o motivo. Produto sem regra é registrado, mas não avaliado.
6. **Achado de rede reaproveita o Estágio 1.** `network.py` ganha `NET_OUTDATED_VERSION`: a mesma versão sem suporte, declarada pelo próprio servidor, em dois ou mais alvos. Severidade média (o cabeçalho pode mentir ou o pacote pode ter correções da distribuição), com a mesma prioridade severidade × raio de impacto.

## Consequências

- O escopo fechado da decisão 0001 continua valendo: nenhum alvo novo, nenhuma descoberta de porta ou caminho. O fingerprint só amplia o que se faz num alvo quando quem autorizou marca isso por escrito.
- O relatório registra, por alvo, se houve pedido HTTP (`fingerprint.http.requested`). Isso responde ao risco de a identificação ser lida como varredura agressiva.
- Tudo o que vem do servidor é tratado como hostil: só três cabeçalhos são lidos (`Server`, `X-Powered-By`, `X-AspNet-Version`), com allowlist de caracteres, até 256 caracteres por valor e no máximo 100 campos. Os outros cabeçalhos (cookies, por exemplo) são descartados sem serem guardados.
- O suporte de cada produto fica em YAML (`fingerprint.products`) com data em `updated`. Calendários de fabricante mudam (o OpenSSL 3.0 saiu de suporte em 07/09/2026), então a seção precisa ser revisada a cada atualização das regras.
- Pacotes de distribuição (Ubuntu, Debian, RHEL) podem receber correções sem mudar o número da versão. O relatório avisa quando o comentário do cabeçalho cita uma distribuição da lista `fingerprint.distributions` das regras (um comentário como `(Win64)` não gera o aviso), e o achado de rede pede confirmação com quem mantém o sistema.
- **Risco aceito: suítes antigas e certificado sem validação no pedido HTTP.** Para também identificar alvos legados (por exemplo, TLS 1.2 só com troca de chave RSA), o adaptador aceita as suítes que o servidor aceitar (`ALL:@SECLEVEL=1`, mínimo TLS 1.2) e não valida o certificado. É um desvio consciente da regra de usar só primitivas modernas, aceito porque o pedido não carrega segredo, cookie nem credencial, e o certificado já foi inventariado pela sonda TLS. A consequência é que alguém no caminho poderia trocar o banner. Por isso o banner é tratado como declaração do servidor, nunca como prova: o achado de rede nasce com severidade média e cita o cabeçalho de origem. Se o projeto preferir restringir a suítes modernas, alvos só legados passam a sair como "não observado".
- O laboratório em Python passa a ter banners conhecidos de antemão (`lab/gabarito-fingerprint.yaml`). No laboratório em Docker o nginx responde HTTP em todas as portas com a versão real da imagem, então lá o gabarito de fingerprint não se aplica (`verificar_gabarito.py --sem-fingerprint`).
