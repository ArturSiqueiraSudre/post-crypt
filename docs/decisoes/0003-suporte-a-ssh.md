# 0003 — Suporte a SSH (Estágio 3)

- **Situação:** aceita
- **Data:** 20/11/2026

## Contexto

Nas entrevistas de validação, SSH foi a "próxima superfície" mais citada depois do TLS: servidores, bastions, roteadores e appliances que a equipe de TI administra. O OpenSSH oferece troca de chave híbrida pós-quântica por padrão desde a versão 9.0 (`sntrup761x25519-sha512`), e o 10.0 passou a preferir `mlkem768x25519-sha256`. Mesmo assim, muitos servidores rodam versões antigas ou configurações que só aceitam troca clássica.

A decisão 0001 já previa SSH no MVP. O documento da análise de rede deixou três pontos em aberto: qual biblioteca usar, onde ficam as regras e como o banner entra no fingerprint.

## Decisão

1. **Sonda própria, sem biblioteca nova.** No SSH, o servidor anuncia em claro, antes de qualquer criptografia, a linha de identificação e a mensagem KEXINIT com as listas de algoritmos que aceita (RFC 4253). A sonda (`ssh/probe.py`) lê o banner, manda a linha de identificação do Post-Crypt, lê o KEXINIT e fecha. São uma conexão e um prazo total por alvo (conexão e leituras somadas, a lição da correção da sonda TLS). A leitura dos bytes hostis fica em `ssh/messages.py`, com teto em cada etapa: 255 bytes por linha, 35 000 por pacote, 128 nomes por lista e 64 caracteres por nome.
2. **Nenhuma troca de chave e nenhuma autenticação.** A sonda não manda o próprio KEXINIT, não faz Diffie-Hellman nem envia usuário ou senha. Completar a troca de chave para obter a chave pública do servidor (tamanho da chave RSA e "mesma chave em vários servidores") fica como feature futura e separada, que só acrescenta dados e terá autorização própria no escopo, como o `http_fingerprint`.
3. **Classificador separado, mesmo formato.** `classify_ssh.py` responde às mesmas três perguntas do TLS (troca de chave, cifra e autenticação) e devolve o mesmo `Assessment`. Assim a tabela, o JSON, o painel e a correlação de rede tratam os dois protocolos do mesmo jeito. Como a sonda vê o que o servidor *aceita*, e não o que foi negociado, o status vem do melhor que um cliente atual escolheria, e os algoritmos fracos ainda aceitos viram achados próprios (`SSH_WEAK_KEX`, `SSH_WEAK_CIPHER`, `SSH_WEAK_HOST_KEY`).
4. **Regras no mesmo `default.yaml`.** A seção `ssh` (troca de chave, chave do servidor e cifras) fica no arquivo do TLS, com uma única data em `updated` e um único `--rules`. As famílias de chave reaproveitam `public_keys`; a família `DSA` entrou nela.
5. **Escopo.** `protocol: ssh` passa a valer. Num alvo SSH, `sni` e `http_fingerprint` são recusados (não ignorados em silêncio), porque não fazem sentido fora do TLS.
6. **Banner SSH no fingerprint, sem autorização extra.** O servidor manda o banner sozinho ao conectar, e a sonda já o lê. Pela regra da decisão 0002 ("o que o handshake já expõe"), ele entra no fingerprint sem `http_fingerprint`. Um OpenSSH sem suporte em vários alvos gera `NET_OUTDATED_VERSION`, com o aviso de distribuição (Ubuntu, Debian etc.).

## Consequências

- O escopo fechado continua valendo: a sonda SSH só conecta no host e na porta listados, uma vez.
- `network.py` passa a contar alvos SSH na exposição a HNDL e nas lacunas de visibilidade sem mudar de estrutura. Os achados de certificado não se aplicam a SSH.
- Para o OpenSSH, "com suporte" é só a versão mais recente (10.6 em 20/11/2026), porque o projeto só corrige a última. Distribuições aplicam correções nas próprias versões, e o relatório avisa.
- O laboratório em Python ganha dois servidores SSH que imitam o banner e o KEXINIT de um OpenSSH real. O laboratório em Docker sobe um OpenSSH de verdade com os mesmos dois casos (`lab/ssh/`). Os testes de integração rodam contra o `sshd` local quando ele existe e são pulados quando não existe.
- Fora deste estágio: SSH versão 1 (só `SSH-2.0` e `SSH-1.99` são aceitos), a mitigação do ataque Terrapin (o campo `strict_kex` é registrado, mas não gera achado) e a avaliação dos MACs.
