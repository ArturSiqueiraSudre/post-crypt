## Baixar e instalar

1. Baixe **[Post-Crypt-Setup.exe](https://github.com/ArturSiqueiraSudre/post-crypt/releases/latest/download/Post-Crypt-Setup.exe)** (também está na lista de arquivos no fim desta página).
2. Dê dois cliques no arquivo baixado e siga o assistente: escolha a pasta, marque se quer o atalho na área de trabalho e clique em **Instalar**.
3. Se aparecer **"O Windows protegeu o computador"**, clique em **Mais informações** e depois em **Executar assim mesmo**. O aviso aparece porque o instalador ainda não tem assinatura digital.
4. No fim, deixe marcado **Executar Post-Crypt**. Depois, abra pelo atalho ou pelo menu Iniciar.

Não precisa de senha de administrador, de Python nem de internet para usar. Requer Windows 10 ou 11, 64 bits.

## O que o Post-Crypt faz

Você lista os serviços da sua empresa que tem autorização para verificar (sites, APIs, VPN, servidores SSH), clica em **Varrer** e recebe, para cada um, três respostas em linguagem simples:

- se o tráfego gravado hoje pode ser aberto no futuro por um computador quântico;
- se a cifra que protege o conteúdo é forte;
- se o certificado ou a chave do servidor está em dia e quando precisa migrar.

O resultado também mostra a versão do software de cada serviço, o que se repete na rede (a mesma autoridade certificadora em vários serviços, a mesma versão sem suporte) e pode ser baixado em JSON. Tudo roda no seu computador: nada é enviado para a internet, e só os serviços que você listar são contatados.

## Remover

Em **Configurações > Aplicativos**, procure **Post-Crypt** e clique em **Desinstalar**.

## Conferir o download (opcional)

O arquivo `.sha256` traz a impressão digital do instalador. No PowerShell:

```powershell
Get-FileHash .\Post-Crypt-Setup.exe
```

O resultado precisa ser igual ao que está no `.sha256`.

## Problemas ou sugestões

Abra uma [issue](https://github.com/ArturSiqueiraSudre/post-crypt/issues). O registro de eventos do programa fica em `%LOCALAPPDATA%\Post-Crypt\logs`.
