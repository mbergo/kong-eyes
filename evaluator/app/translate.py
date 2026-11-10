"""Plain-language translation of the passive summary.

Claude is used as a translator, not a judge: it receives the aggregates and signals that
passive.py already computed and rewrites them as short findings a person can act on.
It never sees prompts or responses (the evaluator does not hold them), and by default it
does not see consumer names either. Every finding stays tagged "investigate".

Providers
  stub       deterministic, offline (tests, and the default when nothing is configured)
  anthropic  Claude API, needs ANTHROPIC_API_KEY
  bedrock    Claude on Amazon Bedrock, needs boto3, AWS credentials and BEDROCK_MODEL_ID
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Callable, Optional

import httpx

SYSTEM = """You translate gateway telemetry about AI guardrails into plain language for the engineer on call.

You are given JSON: aggregate statistics and a list of signals computed from live traffic through Kong Gateway.
There are no labels, so nothing in the data proves that a guardrail was right or wrong.

Write findings that:
- say what was observed, with the numbers, in one or two short sentences;
- say what it could mean, giving both readings when both are plausible (for example overcatching vs. an attack wave);
- name one concrete next check;
- never state that a guardrail is overcatching, slipping, broken or misconfigured as a fact. Use "may", "worth checking".
- use only numbers that appear in the input. Do not invent thresholds, causes or history.

Return ONLY a JSON object: {"headline": "<one sentence>", "findings": [{"title": "...", "severity": "warn|info",
"guardrail": "<name or null>", "route": "<name or null>", "observed": "...", "could_mean": "...", "next_check": "...",
"based_on": ["<signal kind>", ...]}]}. At most 8 findings, most important first. If there are no signals, return an
empty findings list and say so in the headline."""


def _pseudonym(name: str, salt: str) -> str:
    return "caller-" + hashlib.sha256((salt + name).encode()).hexdigest()[:6]


def build_payload(summary: dict, include_consumers: bool = False, salt: str = "") -> dict:
    """The exact JSON sent to the model: aggregates only, bounded, consumers pseudonymised unless opted in."""
    def consumers(pairs):
        return [[c if include_consumers else _pseudonym(str(c), salt), n] for c, n in (pairs or [])]

    guardrails = {}
    for name, g in (summary.get("guardrails") or {}).items():
        guardrails[name] = {k: g.get(k) for k in (
            "requests", "reached", "blocked", "block_rate", "enforced_inline", "intervention_rate", "blocked_by_confidence", "blocked_status", "candidate_blocks",
            "verdicts", "no_verdict", "errors", "detected_not_enforced", "latency_ms", "timeout_ms", "fail_open_suspects",
            "request_rewrites", "response_rewrites", "response_bytes_delta_mean", "blocked_by_model", "routes", "disabled_on")}
        guardrails[name]["top_blocked_consumers"] = consumers(g.get("top_blocked_consumers"))
    sigs = []
    for s in (summary.get("signals") or [])[:40]:
        ev = dict(s.get("evidence") or {})
        if "top_consumers" in ev:
            ev["top_consumers"] = consumers(ev["top_consumers"])
        sigs.append({"kind": s.get("kind"), "severity": s.get("severity"), "route": s.get("route"), "guardrail": s.get("guardrail"),
                     "summary": s.get("summary"), "evidence": ev})
    return {
        "window": summary.get("window"),
        "routes": summary.get("routes"),
        "guardrails": guardrails,
        "coverage": summary.get("coverage"),
        "after_block": summary.get("after_block"),
        "repeat_blocked_consumers": consumers(summary.get("repeat_blocked_consumers")),
        "drift": summary.get("drift"),
        "traffic": summary.get("traffic"),
        "signals": sigs,
    }


def parse_findings(text: str) -> dict:
    """Accept a bare JSON object or one wrapped in a code fence; normalise and tag every finding."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t
        t = t.rsplit("```", 1)[0]
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("model reply contained no JSON object")
    data = json.loads(t[start:end + 1])
    findings = []
    for f in (data.get("findings") or [])[:8]:
        if not isinstance(f, dict) or not f.get("title"):
            continue
        findings.append({
            "title": str(f.get("title"))[:160], "severity": f.get("severity") if f.get("severity") in ("warn", "info") else "info",
            "guardrail": f.get("guardrail"), "route": f.get("route"),
            "observed": str(f.get("observed") or "")[:600], "could_mean": str(f.get("could_mean") or "")[:600],
            "next_check": str(f.get("next_check") or "")[:400],
            "based_on": [str(x) for x in (f.get("based_on") or [])][:8],
            "status": "investigate",
        })
    return {"headline": str(data.get("headline") or "")[:300], "findings": findings}


# ------------------------------------------------------------------ providers
def stub_provider(payload: dict) -> str:
    """Offline translation: one finding per signal, wording taken from the signal itself."""
    sigs = sorted(payload.get("signals") or [], key=lambda s: 0 if s.get("severity") == "warn" else 1)[:8]
    findings = [{"title": (s.get("kind") or "signal").replace("_", " ").replace(":", ": "), "severity": s.get("severity"),
                 "guardrail": s.get("guardrail"), "route": s.get("route"), "observed": s.get("summary"),
                 "could_mean": "Not interpreted (offline translator).", "next_check": "Open the evidence for this signal in /passive/summary.",
                 "based_on": [s.get("kind")]} for s in sigs]
    n = (payload.get("window") or {}).get("requests") or 0
    head = f"{len(findings)} signal(s) to look at across {n} request(s)." if findings else f"No signals across {n} request(s)."
    return json.dumps({"headline": head, "findings": findings})


def anthropic_provider(payload: dict) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    body = {"model": os.environ.get("TRANSLATE_MODEL", "claude-sonnet-5-5"), "max_tokens": int(os.environ.get("TRANSLATE_MAX_TOKENS", "2000")),
            "system": SYSTEM, "messages": [{"role": "user", "content": json.dumps(payload, separators=(",", ":"))}]}
    r = httpx.post(os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/") + "/v1/messages",
                   headers={"x-api-key": key, "anthropic-version": os.environ.get("ANTHROPIC_VERSION", "2023-06-01"),
                            "content-type": "application/json"},
                   json=body, timeout=float(os.environ.get("TRANSLATE_TIMEOUT_S", "60")))
    if r.status_code >= 400:
        raise RuntimeError(f"Claude API returned {r.status_code}: {r.text[:300]}")
    return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")


def bedrock_provider(payload: dict) -> str:
    model_id = os.environ.get("BEDROCK_MODEL_ID")
    if not model_id:
        raise RuntimeError("BEDROCK_MODEL_ID is not set (use the Claude model or inference-profile id enabled in your AWS account)")
    try:
        import boto3  # optional dependency: pip install boto3
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("boto3 is not installed in the evaluator image (add it to requirements.txt to use Bedrock)") from e
    client = boto3.client("bedrock-runtime", region_name=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))
    out = client.converse(modelId=model_id, system=[{"text": SYSTEM}],
                          messages=[{"role": "user", "content": [{"text": json.dumps(payload, separators=(",", ":"))}]}],
                          inferenceConfig={"maxTokens": int(os.environ.get("TRANSLATE_MAX_TOKENS", "2000"))})
    return "".join(b.get("text", "") for b in out["output"]["message"]["content"])


PROVIDERS: dict[str, Callable[[dict], str]] = {"stub": stub_provider, "anthropic": anthropic_provider, "bedrock": bedrock_provider}


def provider_name() -> str:
    p = os.environ.get("TRANSLATE_PROVIDER", "").lower()
    if p in PROVIDERS:
        return p
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("BEDROCK_MODEL_ID"):
        return "bedrock"
    return "stub"


def translate(summary: dict, provider: Optional[str] = None, call: Optional[Callable[[dict], str]] = None) -> dict:
    """Returns {headline, findings[], provider, model, generated_at_ms, window, input_signals, error?}.
    A failing provider never raises: the offline translation is returned with the error attached."""
    name = provider or provider_name()
    payload = build_payload(summary, include_consumers=os.environ.get("TRANSLATE_INCLUDE_CONSUMERS", "false").lower() == "true",
                            salt=os.environ.get("TRANSLATE_SALT", ""))
    meta = {"provider": name, "generated_at_ms": int(time.time() * 1000), "window": summary.get("window"),
            "input_signals": len(payload["signals"]),
            "model": os.environ.get("BEDROCK_MODEL_ID") if name == "bedrock" else
                     os.environ.get("TRANSLATE_MODEL", "claude-sonnet-5-5") if name == "anthropic" else None}
    try:
        fn = call or PROVIDERS[name]
        try:
            out = parse_findings(fn(payload))
        except (ValueError, json.JSONDecodeError):
            # a model occasionally returns JSON that does not parse (seen live: an unescaped quote); ask once more
            if name == "stub":
                raise
            out = parse_findings(fn(payload))
            meta["retried"] = True
    except Exception as e:  # noqa: BLE001
        out = parse_findings(stub_provider(payload))
        meta["error"] = f"{name}: {e}"[:400]
        meta["provider"] = "stub (fallback)"
    out.update(meta)
    return out
