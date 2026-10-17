# 0001 — MVP de feature única: varredura de prontidão pós-quântica

- **Situação:** aceita
- **Data:** 17/10/2026

## Contexto

O Relatório N1 define seis épicos (cofre, CBOM, rotação, API/CLI, modo híbrido, evidência) e uma janela de cerca de quatro semanas até a N2. A dor mais forte do levantamento de campo é o inventário criptográfico inexistente (Perfil B, HU-01), e as objeções mais comuns são "já usamos AES-256" e "nosso fornecedor cuida da criptografia".

Desde 2025, o OpenSSL 3.5 e o OpenSSH 10 já negociam troca de chave híbrida (ML-KEM) por padrão. O CBOMkit, da PQCA/Linux Foundation, já gera CBOM a partir de código-fonte e contêineres.

## Decisão

O MVP é uma única feature: a varredura de rede, caixa-preta e local, de serviços TLS e SSH explicitamente autorizados, com:

- classificação separada de troca de chave, cifra simétrica e autenticação;
- CBOM CycloneDX 1.6;
- relatório de evidência com registro de certificados, assinado com ML-DSA.

O modo híbrido deixa de ser implementado e passa a ser **verificado**. Cofre, rotação e varredura de código-fonte ficam fora do MVP.

## Consequências

- Nenhum segredo do cliente é armazenado, o que reduz o risco de segurança do próprio MVP.
- O arquivo de escopo é obrigatório e fechado: sem descoberta de rede, faixas ou curingas, e com registro de quem autorizou.
- As regras ficam em YAML, versionadas, para acompanhar a evolução dos padrões (NIST IR 8547 ainda é rascunho).
- A sonda TLS monta o próprio ClientHello, então detecta ML-KEM independentemente do OpenSSL da máquina que varre.
- Rotação de certificados é o próximo épico natural, porque consome o registro produzido aqui.
