# Gera o instalador do Post-Crypt para Windows.
#
# Uso (PowerShell, na raiz do repositório):
#   powershell -ExecutionPolicy Bypass -File scripts\gerar-instalador.ps1
#
# Etapas: ambiente (uv) -> testes do aplicativo -> PyInstaller -> autoteste do .exe ->
#         Inno Setup -> SHA-256 do instalador.
# Resultado: dist\instalador\Post-Crypt-Setup-<versão>.exe
#
# Precisa de: uv (winget install astral-sh.uv) e Inno Setup 6 (winget install JRSoftware.InnoSetup).

param(
    [switch]$SemTestes   # pula o pytest (use só para repetir um build que já passou)
)

# "Continue": no Windows PowerShell 5.1, o que o uv e o PyInstaller escrevem em stderr
# viraria erro fatal. Cada comando externo é conferido pelo código de saída.
$ErrorActionPreference = "Continue"
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo
$env:PYTHONUTF8 = "1"

function Passo([string]$texto) { Write-Host ""; Write-Host "== $texto" -ForegroundColor Cyan }
function Falhar([string]$texto) { Write-Host "ERRO: $texto" -ForegroundColor Red; exit 1 }
function Conferir([string]$etapa) { if ($LASTEXITCODE -ne 0) { Falhar "$etapa falhou (código $LASTEXITCODE)." } }

# Versão: uma fonte só, o pyproject.toml.
$linha = Select-String -Path (Join-Path $Repo "pyproject.toml") -Pattern '^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"' | Select-Object -First 1
if (-not $linha) { Falhar "versão não encontrada no pyproject.toml (formato x.y.z)." }
$Versao = $linha.Matches[0].Groups[1].Value
Write-Host "Post-Crypt $Versao"

Passo "Ambiente"
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { Falhar "uv não encontrado. Instale com: winget install astral-sh.uv" }
$Venv = Join-Path $Repo ".venv-instalador"
$Py = Join-Path $Venv "Scripts\python.exe"
if (-not (Test-Path $Py)) { uv venv --python 3.13 $Venv; Conferir "uv venv" }
uv pip install --python $Py -e ".[desktop,empacotar,dev]"; Conferir "instalação das dependências"

if (-not $SemTestes) {
    Passo "Testes"
    & $Py -m pytest -q; Conferir "pytest"
}

Passo "PyInstaller"
$Dist = Join-Path $Repo "dist"
$Build = Join-Path $Repo "build"
& $Py -m PyInstaller --noconfirm --clean --distpath $Dist --workpath $Build "packaging\windows\post-crypt.spec"
Conferir "PyInstaller"
$Exe = Join-Path $Dist "Post-Crypt\Post-Crypt.exe"
if (-not (Test-Path $Exe)) { Falhar "o PyInstaller não gerou $Exe." }

Passo "Autoteste do executável"
# O .exe é um programa de janela: o resultado vem pelo código de saída (0 = ok).
$proc = Start-Process -FilePath $Exe -ArgumentList "--autoteste" -Wait -PassThru -WindowStyle Hidden
if ($proc.ExitCode -ne 0) {
    $log = Join-Path $env:LOCALAPPDATA "Post-Crypt\logs\post-crypt.log"
    if (Test-Path $log) { Get-Content $log -Tail 30 -Encoding UTF8 }
    Falhar "o autoteste do executável falhou (código $($proc.ExitCode))."
}
Write-Host "autoteste ok"

Passo "Inno Setup"
$candidatos = @(
    (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
) | Where-Object { $_ -and (Test-Path $_) }
$Iscc = $candidatos | Select-Object -First 1
if (-not $Iscc) { Falhar "Inno Setup 6 não encontrado. Instale com: winget install JRSoftware.InnoSetup" }
$Saida = Join-Path $Dist "instalador"
& $Iscc "/DAppVersion=$Versao" "/DAppSource=$(Join-Path $Dist 'Post-Crypt')" "/DAppOutput=$Saida" "packaging\windows\post-crypt.iss"
Conferir "Inno Setup"

$Instalador = Join-Path $Saida "Post-Crypt-Setup-$Versao.exe"
if (-not (Test-Path $Instalador)) { Falhar "o Inno Setup não gerou $Instalador." }
$hash = (Get-FileHash -Algorithm SHA256 $Instalador).Hash.ToLower()
"$hash  Post-Crypt-Setup-$Versao.exe" | Set-Content -Path "$Instalador.sha256" -Encoding ASCII

Passo "Pronto"
Write-Host "Instalador: $Instalador"
Write-Host "SHA-256:    $hash"
