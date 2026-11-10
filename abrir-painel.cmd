@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title Post-Crypt
set "PYTHONUTF8=1"
set "PY=.venv\Scripts\python.exe"

rem Dois cliques neste arquivo abrem o painel no navegador.
rem Na primeira vez ele prepara o ambiente com o uv; depois abre direto.

if exist "%PY%" (
  "%PY%" -c "import postcrypt.painel, fastapi, uvicorn" >nul 2>nul && goto abrir
)

where uv >nul 2>nul
if errorlevel 1 goto sem_uv

echo.
echo  Preparando o Post-Crypt. Na primeira vez isso leva um ou dois minutos...
echo.
if not exist "%PY%" (
  uv venv --python 3.13 .venv
  if errorlevel 1 goto erro
)
uv pip install --python "%PY%" -e .
if errorlevel 1 goto erro

:abrir
echo.
"%PY%" -m postcrypt painel
if errorlevel 1 goto erro
exit /b 0

:sem_uv
echo.
echo  O Post-Crypt precisa do programa uv para se preparar na primeira vez.
echo.
echo   1. Abra o PowerShell e rode:  winget install astral-sh.uv
echo   2. Feche o PowerShell e dê dois cliques de novo neste arquivo.
echo.
pause
exit /b 1

:erro
echo.
echo  Algo deu errado. Copie as mensagens acima e envie para o grupo.
echo  Se for erro de conexão, a rede pode estar bloqueando downloads: tente outra rede.
echo.
pause
exit /b 1
