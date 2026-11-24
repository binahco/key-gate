"""El único LLM de key-gate: narra el registro de accesos ya medido. Todo lo demás es determinista."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

import yaml
from cache_ratelimit import CachedProvider, RateLimiter, RealClock, ThrottledProvider
from llm_client import CompletionRequest, CompletionResult, LlmClient, Span
from schema_validate import SchemaRegistry
from secure_base import sanitize_for_prompt
from test_kit import EvalCase, EvalDataset, run

from .models import AccessDigest
from .state import facts_text, senales

DEFAULT_MODEL = "opencode/big-pickle"
SCHEMA_ID = "access-digest-v1"
PROMPT_ID = "access-digest-generator"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROMPT = ROOT / "prompts" / f"{PROMPT_ID}.md"
DEFAULT_DATASET = ROOT / "evals" / f"{PROMPT_ID}.jsonl"
TAGS = ["key-gate", "week-25"]


def load_prompt(path: Path) -> tuple[str, str, str, Path]:
    text = path.read_text()
    if not text.startswith("---"):
        raise SystemExit(f"{path}: falta frontmatter")
    _, frontmatter, body = text.split("---", 2)
    data = yaml.safe_load(frontmatter)
    eval_path = ROOT / data["eval"] if not Path(data["eval"]).is_absolute() else Path(data["eval"])
    return data["id"], data["version"], body.strip(), eval_path


def render_digest(prompt_id: str, prompt_version: str, variables: dict) -> list[dict]:
    if prompt_id == PROMPT_ID:
        _, _, body, _ = load_prompt(DEFAULT_PROMPT)
        system_part = body.split("## Sistema\n", 1)[1].split("## Usuario\n", 1)[0].strip()
        user_part = body.split("## Usuario\n", 1)[1].strip().format(facts=variables["facts"])
        return [{"role": "system", "content": system_part}, {"role": "user", "content": user_part}]
    payload = {"prompt_id": prompt_id, "prompt_version": prompt_version, "variables": variables}
    return [{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]


class CacheProbe:
    """Anota si el último `complete` del `CachedProvider` fue hit, para la cabecera `X-Cache`."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.last_hit = False

    @property
    def name(self) -> str:
        return self.inner.name

    def complete(self, request):
        antes = self.inner.hits
        response = self.inner.complete(request)
        self.last_hit = self.inner.hits > antes
        return response

    def stream(self, request):
        return self.inner.stream(request)


def build_emitter(span_file: Path | None):
    def emit(span: Span, _result) -> None:
        if span_file is not None:
            with span_file.open("a") as handle:
                handle.write(span.as_jsonl() + "\n")
        else:
            sys.stderr.write(span.as_jsonl() + "\n")

    return emit


def build_client(inner_provider, *, rpm=120, burst=20, ttl_seconds=600.0, clock=None, span_file=None) -> dict:
    """Hacia el proveedor: caché TTL + un bucket global. La cadencia por cliente vive en la app."""
    clock = RealClock() if clock is None else clock
    cached = CachedProvider(inner_provider, ttl_seconds=ttl_seconds, clock=clock)
    probe = CacheProbe(cached)
    limiter = RateLimiter(rpm=rpm, burst=burst, clock=clock)
    provider = ThrottledProvider(probe, limiter)
    registry = SchemaRegistry()
    registry.register(SCHEMA_ID, AccessDigest)
    client = LlmClient(
        provider,
        consumer_repo="key-gate",
        model_aliases={"fast": DEFAULT_MODEL},
        renderer=render_digest,
        validator=registry.make_validator(SCHEMA_ID),
        emitter=build_emitter(span_file),
    )
    return {"client": client, "probe": probe, "cached": cached, "limiter": limiter}


def verificar_senales(digest: AccessDigest, validas: set[str]) -> None:
    """La regla: el digest solo puede citar claves y clientes que están en el registro."""
    inventadas = sorted({w.senal for w in digest.watch} - validas)
    if inventadas:
        raise RuntimeError(f"el digest cita señales que no están en el registro: {inventadas}")


def narrate(client: LlmClient, resumen: dict) -> AccessDigest:
    if resumen["intentos"] == 0:
        return AccessDigest(summary="sin accesos registrados: no hay nada que narrar")
    texto = sanitize_for_prompt(facts_text(resumen)).text.replace("{", "(").replace("}", ")")
    result = client.complete(
        CompletionRequest(
            prompt_id=PROMPT_ID,
            prompt_version="0.1.0",
            variables={"facts": texto},
            model_alias="fast",
            response_schema=SCHEMA_ID,
            tags=TAGS,
        )
    )
    if not result.validation.ok:
        raise RuntimeError("; ".join(result.validation.errors))
    digest = result.parsed
    if not isinstance(digest, AccessDigest):
        raise RuntimeError("el digest validó pero no es un AccessDigest")
    verificar_senales(digest, senales(resumen))
    return digest


def judge_for(client: LlmClient) -> Callable[[EvalCase], CompletionResult]:
    def judge(case: EvalCase) -> CompletionResult:
        result = client.complete(
            CompletionRequest(
                prompt_id=case.prompt_id,
                prompt_version=case.prompt_version,
                variables=case.input,
                model_alias="fast",
                response_schema=SCHEMA_ID,
                tags=TAGS,
            )
        )
        if result.validation.ok and isinstance(result.parsed, AccessDigest):
            verificar_senales(result.parsed, set(case.input["senales"]))
        return result

    return judge


def run_dataset(provider) -> int:
    out = run(EvalDataset.from_jsonl(DEFAULT_DATASET), judge_for(build_client(provider)["client"]), mode="full", threshold=1.0)
    print(f"pass={out.passed}/{out.total} threshold_ok={out.threshold_ok}")
    return 0 if out.threshold_ok else 1
