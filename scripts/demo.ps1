# Demonstração guiada do Post-Crypt (MVP Acadêmico).
#
# Uso (PowerShell, na raiz do repositório, depois de rodar testar-local.ps1 uma vez):
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 -SemPausa   # sem esperar Enter (ensaio/CI)
#
# Cada passo mostra o comando antes de rodá-lo e espera Enter. O laboratório
# sobe em Python nas portas 8441-8445 (8449 fica fechada) e é desligado no fim.

param([switch]$SemPausa)

$ErrorActionPreference = "Continue"
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:COLUMNS = "110"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$Py = Join-Path $Repo ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) {
    Write-Host "Ambiente não encontrado. Rode antes: scripts\testar-local.ps1" -ForegroundColor Red
    exit 2
}
$Saida = Join-Path $Repo "resultado-testes"
New-Item -ItemType Directory -Force -Path $Saida | Out-Null
$script:Falhas = 0

function Passo([string]$titulo, [string]$fala) {
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host " $titulo" -ForegroundColor Cyan
    if ($fala) { Write-Host " $fala" -ForegroundColor DarkGray }
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
}

function Pausa {
    if (-not $SemPausa) { Read-Host "  [Enter] próximo passo" | Out-Null }
}

function Mostrar([string]$comando) {
    Write-Host ""
    Write-Host "  > $comando" -ForegroundColor Yellow
    Write-Host ""
}

function Esperar-Porta([int]$porta, [int]$segundos = 20) {
    foreach ($i in 1..$segundos) {
        $c = New-Object Net.Sockets.TcpClient
        try {
            if ($c.ConnectAsync("127.0.0.1", $porta).Wait(500) -and $c.Connected) { return $true }
        } catch {} finally { $c.Close() }
        Start-Sleep -Seconds 1
    }
    return $false
}

# ------------------------------------------------------------------ preparo
& $Py lab\gerar_certificados.py | Out-Null   # validades sempre relativas a hoje
$lab = Start-Process -FilePath $Py -ArgumentList @("lab\servidores_python.py", "--duracao", "1800") `
    -WorkingDirectory $Repo -NoNewWindow -PassThru `
    -RedirectStandardOutput (Join-Path $Saida "demo-laboratorio.log") `
    -RedirectStandardError (Join-Path $Saida "demo-laboratorio-erros.log")
if (-not (Esperar-Porta 8445)) {
    Write-Host "O laboratório não subiu; veja resultado-testes\demo-laboratorio-erros.log" -ForegroundColor Red
    exit 3
}

try {
    Write-Host ""
    Write-Host "  Post-Crypt — varredura local de prontidão pós-quântica" -ForegroundColor White
    Write-Host "  Laboratório no ar: 5 serviços TLS em 127.0.0.1:8441-8445, porta 8449 fechada" -ForegroundColor DarkGray
    Pausa

    # 1 ------------------------------------------------------------- escopo
    Passo "1. O escopo: só o que foi autorizado" "Host e porta explícitos, e quem autorizou a varredura."
    Mostrar "type lab\escopo-lab.yaml"
    Get-Content lab\escopo-lab.yaml -Encoding UTF8 | ForEach-Object { Write-Host "    $_" }
    Pausa

    # 2 ---------------------------------------------------- escopo recusado
    Passo "2. Fora do escopo, a ferramenta se recusa" "Faixa de IP e curinga não passam; cada alvo é listado."
    Mostrar "postcrypt scan examples\escopo-recusado.yaml"
    & $Py -m postcrypt scan examples\escopo-recusado.yaml
    if ($LASTEXITCODE -ne 2) { $script:Falhas++ }
    Write-Host ""
    Write-Host "  código de saída: $LASTEXITCODE (recusado antes de qualquer conexão)" -ForegroundColor DarkGray
    Pausa

    # 3 ---------------------------------------------------------- varredura
    Passo "3. Varredura ao vivo" "Sem agente, sem completar o handshake, nada sai da máquina."
    Mostrar "postcrypt scan lab\escopo-lab.yaml --json resultado-testes\demo.json"
    & $Py -m postcrypt scan lab\escopo-lab.yaml --json resultado-testes\demo.json
    if ($LASTEXITCODE -ne 0) { $script:Falhas++ }
    Pausa

    # 4 ---------------------------------------------- a objeção do AES-256
    Passo "4. ""Já usamos AES-256"": por que não basta" "Mesma cifra, veredito diferente: o risco está na troca de chave."
    $dados = Get-Content resultado-testes\demo.json -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($nome in "tls-hibrido", "tls-classico") {
        $r = $dados.results | Where-Object { $_.target.label -eq $nome }
        $a = $r.assessment
        Write-Host ""
        Write-Host ("  {0}  ->  {1}" -f $nome, $a.status_label) -ForegroundColor White
        Write-Host ("    Troca de chave : {0}" -f $a.key_exchange.detail)
        Write-Host ("    Cifra simétrica: {0}" -f $a.symmetric.detail)
        Write-Host ("    Certificado    : {0}" -f $a.authentication.detail)
    }
    Pausa

    # 5 ------------------------------------------------------------ gabarito
    Passo "5. Conferência com o gabarito (critério de aceite CA2)" "O mesmo teste roda no CI a cada push, com nginx e OpenSSL 3.5."
    Mostrar "python lab\verificar_gabarito.py resultado-testes\demo.json"
    & $Py lab\verificar_gabarito.py resultado-testes\demo.json
    if ($LASTEXITCODE -ne 0) { $script:Falhas++ }
    Pausa

    # 6 ------------------------------------------------------------ pipeline
    Passo "6. Integração em pipeline" "Com --fail-on-vulnerable, um alvo vulnerável a HNDL quebra o build."
    Mostrar "postcrypt scan lab\escopo-lab.yaml --json - --fail-on-vulnerable"
    & $Py -m postcrypt scan lab\escopo-lab.yaml --json - --fail-on-vulnerable | Out-Null
    $codigo = $LASTEXITCODE
    if ($codigo -ne 1) { $script:Falhas++ }
    Write-Host "  código de saída: $codigo (1 = há alvo vulnerável; o pipeline para aqui)" -ForegroundColor White
    Pausa

    Passo "Fim da demonstração" "Próximos incrementos: SSH e CBOM (I1), relatório assinado com ML-DSA (I2), benchmarks (I3)."
} finally {
    if ($lab -and -not $lab.HasExited) { Stop-Process -Id $lab.Id -Force -ErrorAction SilentlyContinue }
}

if ($script:Falhas -gt 0) {
    Write-Host "  Atenção: $($script:Falhas) passo(s) não deram o resultado esperado." -ForegroundColor Red
}
exit $script:Falhas
