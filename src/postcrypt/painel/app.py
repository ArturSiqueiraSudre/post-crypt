"""Aplicação FastAPI do painel local."""

from __future__ import annotations

import datetime as dt
import secrets
import threading
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from postcrypt import __version__
from postcrypt.classify import STATUS_LABELS, load_rules
from postcrypt.painel.laboratorio import Laboratorio, encontrar_raiz
from postcrypt.scanner import ScanResult, run_scan
from postcrypt.scope import Scope, ScopeError, load_scope, parse_scope

ESTATICOS = Path(__file__).resolve().parent / "static"
HOSTS_PERMITIDOS = ["127.0.0.1", "localhost"]
MAX_VARREDURAS_GUARDADAS = 10

CABECALHOS_SEGURANCA = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class EscopoEntrada(BaseModel):
    """Escopo vindo do formulário; a validação de verdade é a do ``parse_scope``."""

    authorization: dict[str, Any] = Field(default_factory=dict)
    targets: list[dict[str, Any]] = Field(default_factory=list)


class TextoYaml(BaseModel):
    texto: str = Field(max_length=1_000_000)


class PedidoVarredura(BaseModel):
    escopo: EscopoEntrada
    timeout: float = Field(default=5.0, ge=1, le=60)
    workers: int = Field(default=8, ge=1, le=32)


@dataclass
class Varredura:
    id: str
    total: int
    parciais: list[dict] = field(default_factory=list)
    resultado: ScanResult | None = None
    erro: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def estado(self) -> str:
        if self.erro:
            return "erro"
        return "concluida" if self.resultado else "rodando"

    def to_dict(self) -> dict:
        with self.lock:
            return {
                "id": self.id,
                "estado": self.estado,
                "total": self.total,
                "feitos": len(self.parciais),
                "parciais": list(self.parciais),
                "resultado": self.resultado.to_dict() if self.resultado else None,
                "erro": self.erro,
            }


def _limpar(valor: Any) -> Any:
    if isinstance(valor, str):
        valor = valor.strip()
        return valor or None
    return valor


def normalizar_escopo(entrada: EscopoEntrada) -> dict:
    """Tira campos vazios do formulário e converte a porta, sem afrouxar nenhuma regra."""
    auth = {k: _limpar(v) for k, v in entrada.authorization.items()}
    alvos = []
    for alvo in entrada.targets:
        limpo = {k: _limpar(v) for k, v in alvo.items()}
        limpo = {k: v for k, v in limpo.items() if v is not None}
        porta = limpo.get("port")
        if isinstance(porta, str) and porta.isdigit():
            limpo["port"] = int(porta)
        alvos.append(limpo)
    return {"authorization": auth, "targets": alvos}


def escopo_para_dict(scope: Scope) -> dict:
    auth = scope.authorization
    return {
        "authorization": {"by": auth.by, "date": auth.date, "reference": auth.reference},
        "targets": [t.to_dict() for t in scope.targets],
    }


def escopo_para_yaml(scope: Scope) -> str:
    auth = {"by": scope.authorization.by, "date": scope.authorization.date}
    if scope.authorization.reference:
        auth["reference"] = scope.authorization.reference
    alvos = []
    for t in scope.targets:
        alvo: dict[str, Any] = {"host": t.host, "port": t.port}
        if t.label:
            alvo["label"] = t.label
        if t.owner != "self":
            alvo["owner"] = t.owner
        if t.sni and t.sni != t.host:
            alvo["sni"] = t.sni
        alvos.append(alvo)
    corpo = yaml.safe_dump(
        {"authorization": auth, "targets": alvos}, allow_unicode=True, sort_keys=False
    )
    return "# Arquivo de escopo do Post-Crypt, salvo pelo painel.\n" + corpo


def _validar(entrada: EscopoEntrada) -> Scope:
    try:
        return parse_scope(normalizar_escopo(entrada))
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def create_app(
    *,
    token: str | None = None,
    laboratorio: Laboratorio | None = None,
    rules: dict | None = None,
) -> FastAPI:
    token = token or secrets.token_urlsafe(32)
    lab = laboratorio if laboratorio is not None else Laboratorio(encontrar_raiz())
    regras = rules if rules is not None else load_rules()
    varreduras: dict[str, Varredura] = {}
    trava = threading.Lock()

    @asynccontextmanager
    async def ciclo_de_vida(_app: FastAPI):
        yield
        lab.desligar()

    app = FastAPI(
        title="Post-Crypt",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=ciclo_de_vida,
    )
    # Bloqueia DNS rebinding: só responde a quem chamou pelo endereço local.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=HOSTS_PERMITIDOS)

    @app.middleware("http")
    async def cabecalhos(request: Request, call_next):
        resposta = await call_next(request)
        for nome, valor in CABECALHOS_SEGURANCA.items():
            resposta.headers.setdefault(nome, valor)
        return resposta

    def exigir_token(x_post_crypt_token: str = Header(default="")) -> None:
        # Outra página aberta no navegador não consegue ler o token nem mandar o cabeçalho.
        if not secrets.compare_digest(x_post_crypt_token, token):
            raise HTTPException(status_code=403, detail="pedido sem o token do painel")

    api = [Depends(exigir_token)]

    @app.get("/", response_class=HTMLResponse)
    def pagina() -> HTMLResponse:
        html = (ESTATICOS / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html.replace("{{TOKEN}}", token).replace("{{VERSAO}}", __version__))

    @app.get("/api/info", dependencies=api)
    def info() -> dict:
        return {
            "versao": __version__,
            "regras": str(regras.get("updated", "")),
            "hoje": dt.date.today().isoformat(),
            "status": STATUS_LABELS,
            "laboratorio": {
                "disponivel": lab.disponivel,
                "ligado": lab.disponivel and lab.ligado,
                "aviso": lab.aviso,
            },
        }

    @app.post("/api/escopo/validar", dependencies=api)
    def validar(entrada: EscopoEntrada) -> dict:
        return escopo_para_dict(_validar(entrada))

    @app.post("/api/escopo/importar", dependencies=api)
    def importar(pedido: TextoYaml) -> dict:
        try:
            dados = yaml.safe_load(pedido.texto)
            return escopo_para_dict(parse_scope(dados))
        except yaml.YAMLError as exc:
            raise HTTPException(422, "o arquivo não é um YAML válido") from exc
        except ScopeError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/escopo/yaml", dependencies=api)
    def exportar(entrada: EscopoEntrada) -> dict:
        return {"texto": escopo_para_yaml(_validar(entrada))}

    @app.post("/api/varreduras", dependencies=api, status_code=202)
    def iniciar(pedido: PedidoVarredura) -> dict:
        scope = _validar(pedido.escopo)
        with trava:
            if any(v.estado == "rodando" for v in varreduras.values()):
                raise HTTPException(409, "já existe uma varredura em andamento")
            job = Varredura(id=uuid.uuid4().hex, total=len(scope.targets))
            varreduras[job.id] = job
            while len(varreduras) > MAX_VARREDURAS_GUARDADAS:
                varreduras.pop(next(iter(varreduras)))

        def anotar(r) -> None:
            with job.lock:
                job.parciais.append(r.to_dict())

        def executar() -> None:
            try:
                resultado = run_scan(
                    scope, regras, timeout=pedido.timeout, workers=pedido.workers, on_result=anotar
                )
                with job.lock:
                    job.resultado = resultado
            except Exception as exc:  # o painel mostra o erro em vez de travar
                with job.lock:
                    job.erro = f"a varredura parou: {exc}"

        threading.Thread(target=executar, daemon=True, name=f"varredura-{job.id[:8]}").start()
        return {"id": job.id, "total": job.total}

    @app.get("/api/varreduras/{vid}", dependencies=api)
    def consultar(vid: str) -> dict:
        job = varreduras.get(vid)
        if job is None:
            raise HTTPException(404, "varredura não encontrada")
        return job.to_dict()

    @app.post("/api/laboratorio/ligar", dependencies=api)
    def ligar_lab() -> dict:
        if not lab.disponivel:
            raise HTTPException(404, "a pasta do laboratório não foi encontrada")
        try:
            lab.ligar()
            scope = load_scope(lab.escopo)
        except Exception as exc:
            raise HTTPException(500, f"não consegui ligar o laboratório: {exc}") from exc
        return {"escopo": escopo_para_dict(scope), "aviso": lab.aviso}

    @app.post("/api/laboratorio/desligar", dependencies=api)
    def desligar_lab() -> dict:
        lab.desligar()
        return {"ligado": lab.disponivel and lab.ligado}

    @app.exception_handler(HTTPException)
    async def erro_http(_request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse({"erro": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def erro_validacao(_request: Request, exc: RequestValidationError) -> JSONResponse:
        campos = ", ".join(".".join(str(p) for p in e["loc"][1:]) for e in exc.errors())
        return JSONResponse({"erro": f"dados inválidos em: {campos}"}, status_code=422)

    app.mount("/static", StaticFiles(directory=ESTATICOS), name="static")
    return app
