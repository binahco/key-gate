from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_client import ReplayProvider
from llm_client.providers.opencode_cli import OpenCodeCLI

from .app import create_keygate_app
from .client import DEFAULT_MODEL, ROOT, build_client, narrate, run_dataset
from .state import ACCESS, KEYS, Gate, summarize

STATE_DIR = ".keygate"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="key-gate", description="Gateway POST /llm con acceso por clave (semana 25).")
    parser.add_argument(
        "command", nargs="?", default="serve",
        choices=["serve", "issue", "revoke", "list", "digest", "record", "replay-check"],
    )
    parser.add_argument("--state", default=str(ROOT / STATE_DIR), help=f"directorio con {KEYS} y {ACCESS}")
    parser.add_argument("--client", help="issue: a quién pertenece la clave")
    parser.add_argument("--scope", action="append", default=[], help="issue: permiso de la clave (se puede repetir)")
    parser.add_argument("--ttl", type=float, default=None, help="issue: vigencia en segundos")
    parser.add_argument("key_id", nargs="?", help="revoke: identificador de la clave")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    if args.command in {"record", "replay-check"}:
        if args.command == "replay-check":
            provider = ReplayProvider(ROOT / "cassettes", record=False)
        else:
            provider = ReplayProvider(ROOT / "cassettes", record=True, inner=OpenCodeCLI(DEFAULT_MODEL))
        return run_dataset(provider)

    gate = Gate(Path(args.state))
    if args.command == "issue":
        if not args.client or not args.scope:
            parser.error("issue necesita --client y al menos un --scope")
        try:
            issued = gate.issue(args.client, scopes=args.scope, ttl_seconds=args.ttl)
        except ValueError as exc:
            print(f"key-gate: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(issued.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return 0

    if args.command == "revoke":
        if not args.key_id:
            parser.error("revoke necesita el identificador de la clave")
        resultado = gate.revoke(args.key_id)
        if resultado == "desconocida":
            print(f"key-gate: no existe la clave {args.key_id}", file=sys.stderr)
            return 1
        print(json.dumps({"revoked": args.key_id, "ya_estaba": resultado == "ya_estaba"}))
        return 0

    if args.command == "list":
        print(json.dumps([record.public() for record in gate.store.list()], ensure_ascii=False, indent=2))
        return 0

    if args.command == "digest":
        resumen = summarize(gate.audit.read(), gate.store, now=gate.clock.now())
        digest = narrate(build_client(OpenCodeCLI(DEFAULT_MODEL))["client"], resumen)
        print(json.dumps({"registro": resumen, "digest": digest.model_dump()}, ensure_ascii=False, indent=2))
        return 0

    import uvicorn

    uvicorn.run(create_keygate_app(gate), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
