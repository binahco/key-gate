from __future__ import annotations

import json
import re
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from llm_client.provider import ProviderRequest, ProviderResponse
from test_kit import EvalDataset, run as run_evalset

from key_gate.app import create_keygate_app
from key_gate.client import DEFAULT_DATASET, build_client, judge_for, narrate, verificar_senales
from key_gate.main import main
from key_gate.models import AccessDigest, Watch
from key_gate.state import ACCESS, KEYS, Gate, facts_text, senales

LLM_BODY = {"prompt_id": "demo", "variables": {"text": "hola"}, "response_schema": None}
TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456"


class FakeClock:
    """Sirve de `AuthClock` (`now`) y de `LimiterClock` (`monotonic`/`sleep`): un reloj para todo."""

    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self._now = now

    def now(self) -> float:
        return self._now

    def monotonic(self) -> float:
        return self._now

    def sleep(self, seconds: float) -> None:
        self._now += seconds

    def advance(self, seconds: float) -> None:
        self._now += seconds


class StubProvider:
    """Responde `{}` al proxy. Si el mensaje es el digest, cita la primera clave que encuentre."""

    name = "stub"

    def __init__(self) -> None:
        self.calls = 0
        self.requests: list[ProviderRequest] = []

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        self.calls += 1
        self.requests.append(request)
        ultimo = request.messages[-1]["content"]
        clave = re.search(r"\b[0-9a-f]{12}\b", ultimo)
        if "ACCESOS" not in ultimo or clave is None:
            text = "{}"
        else:
            senal = clave.group()
            text = json.dumps(
                {"summary": "resumen", "watch": [{"senal": senal, "motivo": "medido", "accion": "mirar"}]},
                ensure_ascii=False,
            )
        return ProviderResponse(text=text, model=request.model)

    def stream(self, request: ProviderRequest) -> list[str]:
        return ["{}"]


def _torcida(key: str) -> str:
    return key[:-1] + ("A" if key[-1] != "A" else "B")


def _gate(tmp_path: Path, clock: FakeClock) -> Gate:
    return Gate(tmp_path / "estado", clock=clock)


def _app(gate: Gate, clock: FakeClock, provider: StubProvider, **ritmo):
    return create_keygate_app(gate, inner_provider=provider, limiter_clock=clock, **ritmo)


def _admin(gate: Gate):
    return gate.issue("ops", scopes=["keys:admin", "access:read"])


def _bearer(issued) -> dict:
    return {"Authorization": f"Bearer {issued.key}"}


# --------------------------------------------------------------------------
# la puerta
# --------------------------------------------------------------------------
def test_sin_clave_nadie_llega_al_llm_y_queda_registrado(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    gate = _gate(tmp_path, clock)
    resp = TestClient(_app(gate, clock, provider)).post("/llm", json=LLM_BODY)
    assert resp.status_code == 401
    assert resp.json() == {"error": "no_autenticado", "detail": "credencial ausente o inválida", "code": 401}
    assert provider.calls == 0
    assert [(e.outcome, e.reason, e.scope) for e in gate.audit.read()] == [("no_autenticado", "ausente", "llm:complete")]


def test_con_clave_valida_pasa_y_queda_registrado(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    gate = _gate(tmp_path, clock)
    emitida = gate.issue("fleet-bot", scopes=["llm:complete"])
    client = TestClient(_app(gate, clock, provider))
    resp = client.post("/llm", json=LLM_BODY, headers=_bearer(emitida))
    assert resp.status_code == 200 and resp.headers["x-cache"] == "miss"
    repetida = client.post("/llm", json=LLM_BODY, headers=_bearer(emitida))
    assert repetida.status_code == 200 and repetida.headers["x-cache"] == "hit"
    assert provider.calls == 1  # la repetida la sirvió la caché
    assert [(e.outcome, e.client, e.key_id) for e in gate.audit.read()] == [("ok", "fleet-bot", emitida.key_id)] * 2


def test_una_clave_sin_el_permiso_no_toca_el_llm(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    gate = _gate(tmp_path, clock)
    lector = gate.issue("catalogo", scopes=["prompts:read"])
    resp = TestClient(_app(gate, clock, provider)).post("/llm", json=LLM_BODY, headers=_bearer(lector))
    assert resp.status_code == 403
    assert resp.json() == {"error": "sin_permiso", "detail": "la clave no tiene el permiso 'llm:complete'", "code": 403}
    assert provider.calls == 0
    assert gate.audit.read()[-1].outcome == "sin_permiso"


def test_una_clave_vencida_no_entra(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    gate = _gate(tmp_path, clock)
    temporal = gate.issue("demo", scopes=["llm:complete"], ttl_seconds=60)
    client = TestClient(_app(gate, clock, provider))
    assert client.post("/llm", json=LLM_BODY, headers=_bearer(temporal)).status_code == 200
    clock.advance(60)
    assert client.post("/llm", json=LLM_BODY, headers=_bearer(temporal)).status_code == 401
    assert gate.audit.read()[-1].reason == "vencida"


def test_la_salud_sigue_publica(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    resp = TestClient(_app(_gate(tmp_path, clock), clock, provider)).get("/health")
    assert resp.status_code == 200 and resp.json()["service"] == "key-gate"


# --------------------------------------------------------------------------
# el ritmo por cliente
# --------------------------------------------------------------------------
def test_el_ritmo_es_por_cliente_y_rechaza_en_lugar_de_esperar(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    gate = _gate(tmp_path, clock)
    ruidoso = gate.issue("ruidoso", scopes=["llm:complete"])
    tranquilo = gate.issue("tranquilo", scopes=["llm:complete"])
    client = TestClient(_app(gate, clock, provider, client_rpm=60, client_burst=2))

    def llamar(emitida, texto: str):
        return client.post("/llm", json={**LLM_BODY, "variables": {"text": texto}}, headers=_bearer(emitida))

    assert [llamar(ruidoso, f"a{i}").status_code for i in range(2)] == [200, 200]
    tercera = llamar(ruidoso, "a9")
    assert tercera.status_code == 429
    assert tercera.json() == {"error": "ritmo_excedido", "detail": "el cliente 'ruidoso' agotó su ráfaga de 2 llamadas", "code": 429}
    assert llamar(tranquilo, "b1").status_code == 200  # un cliente no agota al otro
    clock.advance(1)  # 60 rpm: un token por segundo
    assert llamar(ruidoso, "a10").status_code == 200


# --------------------------------------------------------------------------
# administración de claves y estado en disco
# --------------------------------------------------------------------------
def test_admin_emite_lista_y_revoca(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    gate = _gate(tmp_path, clock)
    client = TestClient(_app(gate, clock, provider))
    cuerpo = {"client": "fleet-bot", "scopes": ["llm:complete"]}
    assert client.post("/keys", json=cuerpo).status_code == 401  # sin clave de admin no se emite
    admin = _admin(gate)
    resp = client.post("/keys", json=cuerpo, headers=_bearer(admin))
    assert resp.status_code == 201
    assert sorted(resp.json()) == ["client", "expires_at", "key", "key_id", "scopes"]
    emitida, key_id = resp.json()["key"], resp.json()["key_id"]
    lista = client.get("/keys", headers=_bearer(admin)).json()
    assert [k["key_id"] for k in lista] == sorted([admin.key_id, key_id])
    assert all("verifier" not in k and emitida.split(".")[1] not in json.dumps(k) for k in lista)
    assert client.post("/llm", json=LLM_BODY, headers={"Authorization": f"Bearer {emitida}"}).status_code == 200
    assert client.delete(f"/keys/{key_id}", headers=_bearer(admin)).json() == {"revoked": key_id, "ya_estaba": False}
    assert client.post("/llm", json=LLM_BODY, headers={"Authorization": f"Bearer {emitida}"}).status_code == 401
    repetido = client.delete(f"/keys/{key_id}", headers=_bearer(admin))
    assert repetido.status_code == 200 and repetido.json() == {"revoked": key_id, "ya_estaba": True}  # DELETE es idempotente
    assert client.delete("/keys/000000000000", headers=_bearer(admin)).status_code == 404
    assert client.post("/keys", json={**cuerpo, "scopes": ["*"]}, headers=_bearer(admin)).status_code == 422


def test_en_disco_no_hay_secretos_y_las_claves_sobreviven(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    gate = _gate(tmp_path, clock)
    emitida = gate.issue("fleet-bot", scopes=["llm:complete"])
    TestClient(_app(gate, clock, provider)).post("/llm", json=LLM_BODY, headers=_bearer(emitida))
    estado = tmp_path / "estado"
    for nombre in (KEYS, ACCESS):
        guardado = (estado / nombre).read_text()
        assert emitida.key not in guardado and emitida.key.split(".")[1] not in guardado
    assert stat.S_IMODE((estado / KEYS).stat().st_mode) == 0o600  # solo su dueño lo lee
    recargado = Gate(estado, clock=clock)
    assert recargado.store.authenticate(emitida.key).client == "fleet-bot"
    assert recargado.audit.read() == gate.audit.read()


def test_access_resume_el_registro_y_atribuye_cada_rechazo(tmp_path) -> None:
    clock, provider = FakeClock(), StubProvider()
    gate = _gate(tmp_path, clock)
    admin = _admin(gate)
    usada = gate.issue("fleet-bot", scopes=["llm:complete"])
    sin_uso = gate.issue("nueva", scopes=["llm:complete"])
    lector = gate.issue("catalogo", scopes=["prompts:read"])
    client = TestClient(_app(gate, clock, provider))
    client.post("/llm", json=LLM_BODY, headers=_bearer(usada))
    client.post("/llm", json=LLM_BODY)
    client.post("/llm", json=LLM_BODY, headers={"Authorization": f"Bearer {_torcida(usada.key)}"})
    client.post("/llm", json=LLM_BODY, headers=_bearer(lector))  # autentica, pero no tiene el permiso
    assert client.get("/access").status_code == 401
    resumen = client.get("/access", headers=_bearer(admin)).json()  # su propio acceso también cuenta
    assert resumen["intentos"] == 6
    assert resumen["por_outcome"] == {"ok": 2, "no_autenticado": 3, "sin_permiso": 1}
    assert resumen["razones"] == {"ausente": 2, "secreto_incorrecto": 1}
    assert resumen["por_cliente"] == {"(sin autenticar)": 2, "catalogo": 1, "fleet-bot": 2, "ops": 1}
    por_id = {c["key_id"]: c for c in resumen["claves"]}
    assert por_id[sin_uso.key_id]["usada"] is False
    assert por_id[usada.key_id]["rechazos"] == 1 and por_id[usada.key_id]["sin_permiso"] == {}
    assert por_id[lector.key_id]["sin_permiso"] == {"llm:complete": 1}
    texto = facts_text(resumen)
    assert f"clave {sin_uso.key_id}" in texto and "por desenlace: ok=2, no_autenticado=3, sin_permiso=1" in texto
    assert "sin_permiso=[llm:complete×1]" in texto


def test_la_cli_emite_lista_y_revoca_sin_perder_el_estado(tmp_path, capsys) -> None:
    estado = str(tmp_path / "estado")
    assert main(["issue", "--state", estado, "--client", "fleet-bot", "--scope", "llm:complete"]) == 0
    emitida = json.loads(capsys.readouterr().out)
    assert main(["issue", "--state", estado, "--client", "x", "--scope", "*"]) == 2  # sin comodines
    assert main(["list", "--state", estado]) == 0
    assert [k["key_id"] for k in json.loads(capsys.readouterr().out)] == [emitida["key_id"]]
    assert main(["revoke", "--state", estado, emitida["key_id"]]) == 0
    assert main(["revoke", "--state", estado, emitida["key_id"]]) == 0
    salidas = [json.loads(linea) for linea in capsys.readouterr().out.splitlines()]
    assert [s["ya_estaba"] for s in salidas] == [False, True]
    assert main(["revoke", "--state", estado, "000000000000"]) == 1
    assert Gate(Path(estado)).store.authenticate(emitida["key"]) is None


# --------------------------------------------------------------------------
# el digest: único LLM, validado o falla
# --------------------------------------------------------------------------
def _resumen(**cambios) -> dict:
    base = {
        "intentos": 12,
        "por_outcome": {"ok": 10, "no_autenticado": 2},
        "razones": {"secreto_incorrecto": 2},
        "por_cliente": {"(sin autenticar)": 2, "fleet-bot": 10},
        "claves": [
            {
                "key_id": "aaaaaaaaaaaa", "client": "fleet-bot", "scopes": ["llm:complete"],
                "created_at": 1.0, "expires_at": None, "revoked": False, "estado": "viva", "usada": True,
                "rechazos": 2, "sin_permiso": {},
            }
        ],
        "rechazos_por_clave": {"aaaaaaaaaaaa": 2},
    }
    return {**base, **cambios}


def test_el_digest_sin_accesos_no_llama_al_modelo() -> None:
    provider = StubProvider()
    digest = narrate(build_client(provider)["client"], _resumen(intentos=0))
    assert digest.watch == [] and provider.calls == 0


def test_el_digest_que_cita_una_senal_fuera_del_registro_se_anula() -> None:
    inventada = AccessDigest(summary="x", watch=[Watch(senal="ffffffffffff", motivo="m", accion="a")])
    with pytest.raises(RuntimeError, match="no están en el registro"):
        verificar_senales(inventada, senales(_resumen()))
    assert senales(_resumen()) == {"aaaaaaaaaaaa", "fleet-bot", "(sin autenticar)"}


def test_el_digest_valida_y_no_recibe_secretos() -> None:
    provider = StubProvider()
    cliente = f"ops con token {TOKEN}"
    clave = {**_resumen()["claves"][0], "client": cliente}
    resumen = _resumen(claves=[clave], por_cliente={cliente: 10, "(sin autenticar)": 2})
    digest = narrate(build_client(provider)["client"], resumen)
    assert [(w.senal, w.motivo, w.accion) for w in digest.watch] == [("aaaaaaaaaaaa", "medido", "mirar")]
    assert "ghp_" not in json.dumps(provider.requests[-1].messages, ensure_ascii=False)


def test_el_judge_exige_senales_del_registro_en_cada_caso() -> None:
    out = run_evalset(EvalDataset.from_jsonl(DEFAULT_DATASET), judge_for(build_client(StubProvider())["client"]), mode="full", threshold=1.0)
    assert (out.total, out.passed) == (3, 3)
