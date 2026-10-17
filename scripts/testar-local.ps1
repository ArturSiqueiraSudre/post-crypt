# Bateria completa de testes do Post-Crypt no Windows.
#
# Uso (PowerShell, na raiz do repositório):
#   powershell -ExecutionPolicy Bypass -File scripts\testar-local.ps1
#
# Etapas: ambiente -> ruff -> pytest -> bandit -> pip-audit -> laboratório
# (Docker) -> demonstração. Cada etapa grava o próprio log em
# resultado-testes\, e resultado-testes\resumo.txt traz o veredito de cada uma.
#
# Ferramentas auxiliares (uv e o Python com OpenSSL 3.5) ficam em
# ..\.ferramentas, fora do repositório e fora do disco C:.

param(
    [string]$Ferramentas = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) ".ferramentas"),
    [switch]$SemLaboratorio
)

$ErrorActionPreference = "Continue"
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo

$Saida = Join-Path $Repo "resultado-testes"
New-Item -ItemType Directory -Force -Path $Saida | Out-Null
Get-ChildItem $Saida -File -ErrorAction SilentlyContinue | Remove-Item -Force
New-Item -ItemType Directory -Force -Path $Ferramentas | Out-Null

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:UV_PYTHON_INSTALL_DIR = Join-Path $Ferramentas "uv-python"
$env:UV_CACHE_DIR = Join-Path $Ferramentas "uv-cache"
$env:COLUMNS = "120"

$Resumo = Join-Path $Saida "resumo.txt"
$script:Falhas = 0

function Registrar([string]$linha) {
    Add-Content -Path $Resumo -Value $linha -Encoding UTF8
    Write-Host $linha
}

# Roda um comando via cmd.exe, grava stdout+stderr em <nome>.log e registra o veredito.
function Etapa([string]$nome, [string]$comando, [switch]$Opcional) {
    $log = Join-Path $Saida "$nome.log"
    Write-Host ""
    Write-Host "== $nome" -ForegroundColor Cyan
    $inicio = Get-Date
    cmd.exe /d /c "$comando > `"$log`" 2>&1"
    $codigo = $LASTEXITCODE
    $seg = [int]((Get-Date) - $inicio).TotalSeconds
    Get-Content $log -Tail 15 -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "   $_" }
    if ($codigo -eq 0) {
        Registrar ("OK     {0,-22} {1,4}s" -f $nome, $seg)
    } elseif ($Opcional) {
        Registrar ("AVISO  {0,-22} {1,4}s  (código {2}, ver {0}.log)" -f $nome, $seg, $codigo)
    } else {
        $script:Falhas++
        Registrar ("FALHOU {0,-22} {1,4}s  (código {2}, ver {0}.log)" -f $nome, $seg, $codigo)
    }
    return $codigo
}

Registrar "Post-Crypt - testes locais em $env:COMPUTERNAME, $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Registrar "Repositório: $Repo"
Registrar ("Commit: " + (git -c safe.directory=* -C $Repo log -1 --format="%h %s" 2>$null))
Registrar ""

# ---------------------------------------------------------------- ambiente
$uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
if (-not $uv) {
    $uvLocal = Join-Path $Ferramentas "bootstrap\Scripts\uv.exe"
    if (Test-Path $uvLocal) {
        $uv = $uvLocal
    } else {
        $py = $null
        if (Get-Command py -ErrorAction SilentlyContinue) {
            foreach ($v in "3.13", "3.12", "3.14") {
                & py "-$v" -c "import sys" 2>$null
                if ($LASTEXITCODE -eq 0) { $py = "py -$v"; break }
            }
        }
        if (-not $py -and (Get-Command python -ErrorAction SilentlyContinue)) { $py = "python" }
        if (-not $py) {
            Registrar "FALHOU ambiente: nenhum Python encontrado (instale Python 3.12+ ou uv)"
            exit 1
        }
        $boot = Join-Path $Ferramentas "bootstrap"
        Etapa "instalar-uv" "$py -m venv `"$boot`" && `"$boot\Scripts\python.exe`" -m pip install -q --disable-pip-version-check uv" | Out-Null
        $uv = $uvLocal
    }
}

# O Python do uv (python-build-standalone) traz OpenSSL 3.5: habilita o teste
# de integração do servidor híbrido com ML-KEM.
Etapa "ambiente" "`"$uv`" venv --python 3.13 --allow-existing .venv && `"$uv`" pip install --python .venv\Scripts\python.exe -e .[dev]" | Out-Null
$Py = Join-Path $Repo ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) {
    Registrar "FALHOU ambiente: .venv não foi criado; veja ambiente.log"
    exit 1
}
Registrar ("Python: " + (& $Py -c "import sys, ssl; print(sys.version.split()[0], '|', ssl.OPENSSL_VERSION)"))
Registrar ""

# ---------------------------------------------------------------- qualidade
Etapa "ruff-check" "`"$Py`" -m ruff check src tests lab" | Out-Null
Etapa "ruff-format" "`"$Py`" -m ruff format --check src tests lab" | Out-Null
Etapa "pytest" "`"$Py`" -m pytest -v -rs --junitxml=resultado-testes\pytest.xml" | Out-Null
Etapa "bandit" "`"$Py`" -m bandit -r src -c pyproject.toml" | Out-Null
Etapa "pip-audit" "`"$Py`" -m pip_audit --skip-editable" -Opcional | Out-Null

# ---------------------------------------------------------------- laboratório
$docker = Get-Command docker -ErrorAction SilentlyContinue
$dockerOk = $false
if ($docker) {
    cmd.exe /d /c "docker info > nul 2>&1"
    $dockerOk = ($LASTEXITCODE -eq 0)
}
if ($SemLaboratorio) {
    Registrar "PULADO laboratorio             (-SemLaboratorio)"
} elseif (-not $dockerOk) {
    Registrar "PULADO laboratorio             (Docker indisponível ou Docker Desktop fechado)"
} else {
    Etapa "lab-certificados" "`"$Py`" lab\gerar_certificados.py" | Out-Null
    $subiu = Etapa "lab-subir" "docker compose -f lab\docker-compose.yml up -d"
    if ($subiu -eq 0) {
        foreach ($i in 1..30) {
            $c = New-Object Net.Sockets.TcpClient
            try { if ($c.ConnectAsync("127.0.0.1", 8445).Wait(500) -and $c.Connected) { break } } catch {} finally { $c.Close() }
            Start-Sleep -Seconds 1
        }
        Etapa "lab-varredura" "`"$Py`" -m postcrypt scan lab\escopo-lab.yaml --json resultado-testes\lab-resultado.json" | Out-Null
        Etapa "lab-gabarito" "`"$Py`" lab\verificar_gabarito.py resultado-testes\lab-resultado.json" | Out-Null
        cmd.exe /d /c "docker compose -f lab\docker-compose.yml exec -T tls nginx -V > `"$Saida\lab-nginx-versao.log`" 2>&1"
    }
    Etapa "lab-desligar" "docker compose -f lab\docker-compose.yml down" -Opcional | Out-Null
}

# ---------------------------------------------------------------- fim
Registrar ""
if ($script:Falhas -eq 0) {
    Registrar "RESULTADO: todas as etapas obrigatórias passaram"
} else {
    Registrar "RESULTADO: $($script:Falhas) etapa(s) falharam"
}
Registrar "FIM"
exit $script:Falhas
