# key-gate

Gateway `POST /llm` con acceso por clave (semana 25): nadie llega al modelo sin una clave
que lo autentique y que tenga el permiso `llm:complete`. Cada intento queda en un registro
y el ritmo se mide por cliente. Nace con el módulo nuevo del core: **`auth-base` (C14,
ADR-13)** — la capa de acceso que `web-api-base` dejó fuera a propósito y que cuatro
consumidores de la flota (`eval-api`, `llm-gateway`, `evidence-api`, `prompt-hub`)
esperaban desde sus limitaciones.

## Demo

```bash
uv sync
uv run key-gate issue --client ops --scope keys:admin --scope access:read  # la primera clave, antes de arrancar
uv run key-gate serve --port 18765 &

curl -s -X POST localhost:18765/llm -H 'Content-Type: application/json' \
     -d '{"prompt_id":"saludo","variables":{"text":"Di hola en tres palabras."}}'
# {"error":"no_autenticado","detail":"credencial ausente o inválida","code":401}

curl -s -X POST localhost:18765/keys -H "Authorization: Bearer $OPS" -H 'Content-Type: application/json' \
     -d '{"client":"fleet-bot","scopes":["llm:complete"]}'
# {"key":"<clave>","key_id":"02701a102b19","client":"fleet-bot","scopes":["llm:complete"],"expires_at":null}

curl -s -X POST localhost:18765/llm -H "Authorization: Bearer $FLEET" -H 'Content-Type: application/json' \
     -d '{"prompt_id":"saludo","variables":{"text":"Di hola en tres palabras."}}'
# {"span_id":"a5d8540b41964fa381cb015b99b60bf5","prompt_id":"saludo","prompt_version":"0.0.0",
#  "model":"opencode/big-pickle","content":"Hola, ¿cómo estás?","validation_ok":true,…

curl -s -X DELETE localhost:18765/keys/02701a102b19 -H "Authorization: Bearer $OPS"
# {"revoked":"02701a102b19","ya_estaba":false}

uv run key-gate digest   # se recorta `registro`
# {"summary": "8 intentos medidos: 5 ok y 3 no_autenticado (ausente, revocada, secreto_incorrecto);
#              la clave revocada 02701a102b19 de fleet-bot registra 2 rechazos y la clave viva de ops, 0.",
#  "watch": [{"senal": "02701a102b19",
#             "motivo": "Clave de fleet-bot en estado revocada, usada=sí y con 2 rechazos medidos; …",
#             "accion": "Dejar de usarla y emitir a fleet-bot una clave nueva solo con llm:complete, …"}]}
```

Salida del 2026-11-23, con un servidor local y llamadas reales a `opencode/big-pickle`.
El gate es **determinista** (misma clave, mismo veredicto; mismo registro, mismas cifras);
el digest es el único LLM que key-gate llama por su cuenta.

## Cómo funciona

```
cliente ──Authorization: Bearer <key_id>.<secreto>──▶ key-gate
  ├─ auth-base: require(store, permiso de la ruta) → 401 no_autenticado · 403 sin_permiso
  │    └─ un AuthEvent por intento → .keygate/access.jsonl
  ├─ cache-ratelimit: un token bucket por cliente → 429 ritmo_excedido (rechaza, no espera)
  ├─ web-api-base: POST /llm con el pipeline de llm-client y errores uniformes
  └─ key-gate digest: el registro contado → LLM validado (access-digest-v1)
       └─ la señal invalida: citar una clave o cliente que no está en el registro anula el digest
```

| Ruta | Permiso | Qué hace |
|---|---|---|
| `GET /health` | público | liveness, de `web-api-base` |
| `POST /llm` | `llm:complete` | llama al modelo por `llm-client`; responde `X-Cache` hit o miss |
| `POST /keys` | `keys:admin` | emite una clave: el secreto viaja en esta respuesta, una sola vez |
| `GET /keys` | `keys:admin` | lista las claves, sin huellas ni secretos |
| `DELETE /keys/{key_id}` | `keys:admin` | revoca; repetido responde `ya_estaba: true` |
| `GET /access` | `access:read` | el registro contado: desenlaces, razones, claves sin uso |
| `GET /keygate/stats` | `access:read` | bucket global, caché y buckets por cliente |

Al que llama solo le llegan dos errores. La razón fina (ausente, secreto incorrecto,
revocada, vencida) va al registro, que es de quien opera.

## Recicla de

| Módulo | Uso |
|---|---|
| `auth-base` | seed (C14, sem. 25): clave con permisos exactos, falla cerrado, 401/403 uniformes |
| `web-api-base` | `create_app`, el `POST /llm` del pipeline y los errores uniformes |
| `llm-client` | la llamada al modelo y la del digest |
| `schema-validate` | el digest valida contra `access-digest-v1` o falla |
| `secure-base` | el registro que entra al digest va saneado |
| `cache-ratelimit` | caché TTL y bucket global hacia el proveedor, y un bucket por cliente |
| `test-kit` | dataset congelado + replay determinista (D4) |

## Limitaciones

- La CLI y el servidor no comparten memoria. La CLI es para antes de arrancar o con el
  servidor parado; con el servidor arriba, las claves se manejan por `POST /keys` y
  `DELETE /keys/{key_id}`. Dos escritores a la vez sobre `keys.json` se pisan.
- Solo `POST /llm`: no hay `/llm/stream` ni caché en disco (`llm-gateway` sí tiene el stream).
- El registro de accesos crece sin poda ni rotación, y no alerta solo: el digest narra.
- Sin TLS: es del despliegue. Una clave viaja en claro si el servidor no está detrás de HTTPS.
- El bucket por cliente vive en memoria: al reiniciar, empieza lleno.
- `response_schema=None` pasa sin validar (el opt-out explícito de `web-api-base`).
- El eval no mide prudencia. Congela que el digest tenga forma válida y que sus señales
  existan; que las acciones no propongan usar la clave de otro cliente se leyó a mano al
  grabar, después de que una grabación lo propusiera.

## Roadmap

- [x] Acceso por clave en `/llm`, ritmo por cliente y registro de accesos (sem. 25, seed de `auth-base`)
- [x] Primer consumidor de `auth-base`
- [ ] Retrofit: `eval-api`, `evidence-api` y `prompt-hub` detrás de `require(...)`, deuda que declaran en sus READMEs
- [ ] `CacheProbe` (la cabecera `X-Cache`) al core en su tercer uso (D12): hoy la repiten `llm-gateway` y `key-gate`
- [ ] Poda y rotación del registro de accesos
