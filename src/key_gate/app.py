"""La app: `llm-gateway` (sem. 8) detrás de una puerta. Cada ruta dice qué permiso exige."""

from __future__ import annotations

from auth_base import Principal, register_auth, require
from cache_ratelimit import RateLimiter, RealClock
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from web_api_base import LLMHTTPError, create_app as make_web_app, llm_complete
from web_api_base.llm_route import CompleteRequest

from .client import DEFAULT_MODEL, build_client
from .models import IssueRequest
from .state import Gate, summarize

DEFAULT_RPM = 120
DEFAULT_BURST = 20
DEFAULT_TTL_SECONDS = 600.0
DEFAULT_CLIENT_RPM = 30
DEFAULT_CLIENT_BURST = 5


class ClientLimit:
    """Un token bucket por cliente (cache-ratelimit).

    El bucket global hacia el proveedor espera; este no. Aquí se rechaza con 429: un
    cliente no puede agotar a los demás ocupando el turno.
    """

    def __init__(self, *, rpm: float, burst: int, clock=None) -> None:
        self.rpm, self.burst = rpm, burst
        self._clock = clock if clock is not None else RealClock()
        self._limiters: dict[str, RateLimiter] = {}

    def admit(self, client: str) -> None:
        limiter = self._limiters.setdefault(client, RateLimiter(rpm=self.rpm, burst=self.burst, clock=self._clock))
        if limiter.tokens < 1.0:
            raise LLMHTTPError(429, "ritmo_excedido", detail=f"el cliente {client!r} agotó su ráfaga de {self.burst} llamadas")
        limiter.acquire()

    def stats(self) -> dict:
        return {client: limiter.stats() for client, limiter in sorted(self._limiters.items())}


def create_keygate_app(
    gate: Gate,
    *,
    inner_provider=None,
    rpm: float = DEFAULT_RPM,
    burst: int = DEFAULT_BURST,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
    client_rpm: float = DEFAULT_CLIENT_RPM,
    client_burst: int = DEFAULT_CLIENT_BURST,
    limiter_clock=None,
) -> FastAPI:
    from llm_client.providers.opencode_cli import OpenCodeCLI

    inner = inner_provider if inner_provider is not None else OpenCodeCLI(DEFAULT_MODEL)
    built = build_client(inner, rpm=rpm, burst=burst, ttl_seconds=ttl_seconds, clock=limiter_clock)
    client = built["client"]
    limites = ClientLimit(rpm=client_rpm, burst=client_burst, clock=limiter_clock)

    app = make_web_app(
        "key-gate",
        "0.1.0",
        client=client,
        enable_llm_endpoint=False,
        health_extra={
            "cache_ttl_seconds": ttl_seconds, "rpm": rpm, "burst": burst,
            "client_rpm": client_rpm, "client_burst": client_burst,
        },
    )
    register_auth(app)

    store = gate.store
    llm_access = require(store, "llm:complete")
    keys_admin = require(store, "keys:admin")
    access_read = require(store, "access:read")

    @app.post("/llm", tags=["llm"])
    async def llm(req: CompleteRequest, principal: Principal = Depends(llm_access)):
        limites.admit(principal.client)
        return JSONResponse(
            status_code=200,
            content=llm_complete(client, req),
            headers={"X-Cache": "hit" if built["probe"].last_hit else "miss"},
        )

    @app.post("/keys", status_code=201, tags=["keys"])
    async def issue(req: IssueRequest, _admin: Principal = Depends(keys_admin)):
        try:
            issued = gate.issue(req.client, scopes=req.scopes, ttl_seconds=req.ttl_seconds)
        except ValueError as exc:
            raise LLMHTTPError(422, "peticion_invalida", detail=str(exc)) from exc
        return issued.model_dump(mode="json")  # el secreto viaja aquí, una sola vez

    @app.get("/keys", tags=["keys"])
    async def keys(_admin: Principal = Depends(keys_admin)):
        return [record.public() for record in store.list()]

    @app.delete("/keys/{key_id}", tags=["keys"])
    async def revoke(key_id: str, _admin: Principal = Depends(keys_admin)):
        resultado = gate.revoke(key_id)
        if resultado == "desconocida":
            raise LLMHTTPError(404, "clave_desconocida", detail=f"no existe la clave {key_id!r}")
        return {"revoked": key_id, "ya_estaba": resultado == "ya_estaba"}  # DELETE es idempotente

    @app.get("/access", tags=["access"])
    async def access(_lector: Principal = Depends(access_read)):
        return summarize(gate.audit.read(), store, now=gate.clock.now())

    @app.get("/keygate/stats", tags=["access"])
    async def stats(_lector: Principal = Depends(access_read)):
        return {"limiter": built["limiter"].stats(), "cache": built["cached"].stats(), "clientes": limites.stats()}

    return app
