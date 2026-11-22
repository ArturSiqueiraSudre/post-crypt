# Especificação do PyInstaller para o aplicativo do Post-Crypt (Windows).
#
# Gera uma pasta (não um arquivo único): abre mais rápido, porque nada é extraído a cada
# execução, e antivírus desconfiam menos. O instalador (post-crypt.iss) empacota essa pasta.
#
# Uso, na raiz do repositório:  pyinstaller --noconfirm packaging/windows/post-crypt.spec
# ruff: noqa
import sys
import tomllib
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PASTA = Path(SPECPATH)  # noqa: F821 - definido pelo PyInstaller
RAIZ = PASTA.parent.parent
VERSAO = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
ICONE = PASTA / "post-crypt.ico"

# Regras (YAML) e a página do painel (static/) viajam junto com o código.
dados = collect_data_files("postcrypt", excludes=["**/__pycache__/**"])
dados.append((str(ICONE), "."))

ocultos = collect_submodules("uvicorn") + collect_submodules("postcrypt")

a = Analysis(  # noqa: F821
    [str(PASTA / "iniciar.py")],
    pathex=[str(RAIZ / "src")],
    datas=dados,
    hiddenimports=ocultos,
    excludes=["tkinter", "pytest", "ruff", "bandit", "pip_audit", "IPython", "matplotlib"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821

versao = None
if sys.platform == "win32":
    from PyInstaller.utils.win32 import versioninfo as vi

    numeros = tuple(int(p) for p in VERSAO.split(".")[:3]) + (0,)
    versao = vi.VSVersionInfo(
        ffi=vi.FixedFileInfo(filevers=numeros, prodvers=numeros),
        kids=[
            vi.StringFileInfo(
                [
                    vi.StringTable(
                        "041604B0",  # português (Brasil), Unicode
                        [
                            vi.StringStruct("CompanyName", "Equipe Post-Crypt"),
                            vi.StringStruct("FileDescription", "Post-Crypt"),
                            vi.StringStruct("FileVersion", VERSAO),
                            vi.StringStruct("InternalName", "Post-Crypt"),
                            vi.StringStruct("LegalCopyright", "© 2026 Equipe Post-Crypt"),
                            vi.StringStruct("OriginalFilename", "Post-Crypt.exe"),
                            vi.StringStruct("ProductName", "Post-Crypt"),
                            vi.StringStruct("ProductVersion", VERSAO),
                        ],
                    )
                ]
            ),
            vi.VarFileInfo([vi.VarStruct("Translation", [0x0416, 1200])]),
        ],
    )

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Post-Crypt",
    console=False,  # programa de janela: nada de console preto atrás
    icon=str(ICONE),
    version=versao,
    upx=False,  # UPX aumenta alarmes falsos de antivírus
)
coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    name="Post-Crypt",
    upx=False,
)
