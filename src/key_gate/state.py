"""Lo que key-gate guarda en disco: las huellas de las claves y el registro de accesos.
Ninguno de los dos lleva un secreto — `KeyStore.export()` solo entrega huellas."""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from auth_base import AuthClock, AuthEvent, IssuedKey, KeyStore, RealClock

KEYS = "keys.json"
ACCESS = "access.jsonl"
SIN_AUTENTICAR = "(sin autenticar)"


class Gate:
    """El almacén de key-gate: claves persistidas y cada intento registrado."""

    def __init__(self, state_dir: Path, *, clock: AuthClock | None = None) -> None:
        self.dir = Path(state_dir)
        self.clock = clock if clock is not None else RealClock()
        self.audit = AuditLog(self.dir / ACCESS)
        self.store = self._load()

    @property
    def _keys_path(self) -> Path:
        return self.dir / KEYS

    def _load(self) -> KeyStore:
        if not self._keys_path.is_file():
            return KeyStore(clock=self.clock, audit=self.audit.append)
        records = json.loads(self._keys_path.read_text(encoding="utf-8"))
        return KeyStore.load(records, clock=self.clock, audit=self.audit.append)

    def _save(self) -> None:
        """Escritura atómica (tmp + replace), como `JsonRunStore` de bot-base."""
        self._keys_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.store.export(), indent=2, ensure_ascii=False) + "\n"
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self._keys_path.parent, delete=False) as tmp:
            tmp.write(payload)
            tmp_name = tmp.name
        Path(tmp_name).replace(self._keys_path)

    def issue(self, client: str, *, scopes: Iterable[str], ttl_seconds: float | None = None) -> IssuedKey:
        issued = self.store.issue(client, scopes=scopes, ttl_seconds=ttl_seconds)
        self._save()
        return issued

    def revoke(self, key_id: str) -> str:
        """`revocada` si estaba viva, `ya_estaba` si ya lo estaba, `desconocida` si no existe."""
        if not self.store.revoke(key_id):
            return "ya_estaba" if self.store.get(key_id) is not None else "desconocida"
        self._save()
        return "revocada"


class AuditLog:
    """El registro de accesos, una línea JSON por intento. Es la única fuente de verdad del digest."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def append(self, event: AuthEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")

    def read(self) -> list[AuthEvent]:
        if not self.path.is_file():
            return []
        lineas = self.path.read_text(encoding="utf-8").splitlines()
        return [AuthEvent.model_validate_json(linea) for linea in lineas if linea.strip()]


def summarize(events: list[AuthEvent], store: KeyStore, *, now: float | None = None) -> dict:
    """El registro, contado. Determinista: mismas líneas, mismas cifras."""
    desenlaces = Counter(e.outcome for e in events)
    razones = Counter(e.reason for e in events if e.outcome == "no_autenticado")
    rechazos = Counter(e.key_id for e in events if e.outcome == "no_autenticado" and e.key_id)
    usadas = {e.key_id for e in events if e.outcome == "ok"}
    # Un `sin_permiso` sí dice quién: la clave autenticó. Se cuenta qué permiso pidió.
    pedidos: dict[str, Counter] = {}
    for e in events:
        if e.outcome == "sin_permiso" and e.key_id:
            pedidos.setdefault(e.key_id, Counter())[e.scope or "?"] += 1
    claves = []
    for record in store.list():
        estado = "revocada" if record.revoked else "viva"
        if estado == "viva" and now is not None and record.expires_at is not None and now >= record.expires_at:
            estado = "vencida"
        claves.append(
            {
                **record.public(),
                "estado": estado,
                "usada": record.key_id in usadas,
                "rechazos": rechazos.get(record.key_id, 0),
                "sin_permiso": dict(sorted(pedidos.get(record.key_id, {}).items())),
            }
        )
    return {
        "intentos": len(events),
        "por_outcome": {k: desenlaces[k] for k in ("ok", "no_autenticado", "sin_permiso") if desenlaces[k]},
        "razones": dict(sorted(razones.items())),
        "por_cliente": dict(sorted(Counter(e.client or SIN_AUTENTICAR for e in events).items(), key=lambda kv: (-kv[1], kv[0]))),
        "claves": claves,
        "rechazos_por_clave": dict(sorted(rechazos.items())),
    }


def facts_text(resumen: dict) -> str:
    """El registro en texto plano: lo único que ve el LLM."""
    def lista(conteo: dict) -> str:
        return ", ".join(f"{k}={v}" for k, v in conteo.items()) or "ninguno"

    lineas = [
        "ACCESOS",
        f"intentos: {resumen['intentos']}",
        f"por desenlace: {lista(resumen['por_outcome'])}",
        f"razones de rechazo: {lista(resumen['razones'])}",
        f"por cliente: {lista(resumen['por_cliente'])}",
        "",
        "CLAVES",
    ]
    for clave in resumen["claves"]:
        permisos = ", ".join(clave["scopes"])
        pedidos = ", ".join(f"{scope}×{n}" for scope, n in clave["sin_permiso"].items())
        lineas.append(
            f"- clave {clave['key_id']} cliente={clave['client']} permisos=[{permisos}]"
            f" estado={clave['estado']} usada={'sí' if clave['usada'] else 'no'} rechazos={clave['rechazos']}"
            + (f" sin_permiso=[{pedidos}]" if pedidos else "")
        )
    conocidas = {clave["key_id"] for clave in resumen["claves"]}
    fuera = {k: v for k, v in resumen["rechazos_por_clave"].items() if k not in conocidas}
    if fuera:
        lineas.append("claves rechazadas que no existen: " + lista(fuera))
    return "\n".join(lineas)


def senales(resumen: dict) -> set[str]:
    """Lo que el digest puede citar: claves y clientes que están en el registro."""
    return {clave["key_id"] for clave in resumen["claves"]} | set(resumen["por_cliente"])
