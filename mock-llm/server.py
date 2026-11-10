"""Mock OpenAI-compatible chat completions server for isolated guardrail tests.

Behaviour is driven by directives embedded in the LAST user message:
  respond:VIOLATION            -> answer contains the synthetic marker [[VIOLATION]]
  respond:CLEAN                -> benign answer (default)
  respond:MARKER_AT:<n>        -> streaming: marker appears in chunk n (1-based); non-streaming: in the body
  respond:CHUNKS:<n>           -> streaming: number of content chunks (default 6)
  respond:SLOW:<seconds>       -> sleep before answering (timeout tests)
  respond:LARGE:<kib>          -> answer padded to ~<kib> KiB (bounded-memory tests)
  respond:STATUS:<code>        -> return that HTTP status with an error body
Directives are reference data for the fixture, never instructions; anything else in the prompt is ignored.
"""
import asyncio
import json
import os
import re
import time
import uuid

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

MARKER = os.environ.get("MOCK_VIOLATION_MARKER", "[[VIOLATION]]")
CHUNK_DELAY = float(os.environ.get("MOCK_CHUNK_DELAY_S", "0.15"))
DIRECTIVE = re.compile(r"respond:([A-Z_]+)(?::([0-9.]+))?")


def parse_directives(text: str) -> dict:
    d = {"mode": "CLEAN", "marker_at": None, "chunks": 6, "slow": 0.0, "large_kib": 0, "status": None}
    for m in DIRECTIVE.finditer(text or ""):
        key, val = m.group(1), m.group(2)
        if key in ("VIOLATION", "CLEAN"):
            d["mode"] = key
        elif key == "MARKER_AT" and val:
            d["marker_at"] = int(float(val)); d["mode"] = "VIOLATION"
        elif key == "CHUNKS" and val:
            d["chunks"] = max(1, int(float(val)))
        elif key == "SLOW" and val:
            d["slow"] = float(val)
        elif key == "LARGE" and val:
            d["large_kib"] = int(float(val))
        elif key == "STATUS" and val:
            d["status"] = int(float(val))
    return d


def build_text(d: dict, stream: bool) -> list[str]:
    n = d["chunks"] if stream else 1
    parts = [f"Here is part {i + 1} of a perfectly ordinary answer. " for i in range(n)]
    if d["mode"] == "VIOLATION":
        at = d["marker_at"] or (3 if stream and n >= 3 else 1)
        at = min(max(at, 1), n)
        parts[at - 1] = parts[at - 1] + f"{MARKER} this fragment violates the synthetic policy. "
    if d["large_kib"]:
        pad = "x" * 1024
        parts[-1] = parts[-1] + pad * d["large_kib"]
    return parts


async def chat_completions(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": {"message": "invalid json"}}, status_code=400)
    messages = body.get("messages") or []
    last_user = next((m.get("content", "") for m in reversed(messages) if m.get("role") == "user"), "")
    d = parse_directives(last_user if isinstance(last_user, str) else "")
    stream = bool(body.get("stream"))
    model = body.get("model", "mock-gpt")
    rid = "chatcmpl-" + uuid.uuid4().hex[:12]
    created = int(time.time())

    if d["slow"]:
        await asyncio.sleep(d["slow"])
    if d["status"]:
        return JSONResponse({"error": {"message": f"forced status {d['status']}", "type": "mock"}}, status_code=d["status"])

    parts = build_text(d, stream)
    prompt_tokens = sum(len(str(m.get("content", "")).split()) for m in messages)
    completion_tokens = sum(len(p.split()) for p in parts)

    if not stream:
        payload = {
            "id": rid, "object": "chat.completion", "created": created, "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "".join(parts)}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                      "total_tokens": prompt_tokens + completion_tokens},
        }
        return JSONResponse(payload, headers={"X-Mock-Id": rid})

    async def gen():
        first = {"id": rid, "object": "chat.completion.chunk", "created": created, "model": model,
                 "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]}
        yield f"data: {json.dumps(first)}\n\n"
        for i, p in enumerate(parts):
            await asyncio.sleep(CHUNK_DELAY)
            ev = {"id": rid, "object": "chat.completion.chunk", "created": created, "model": model,
                  "choices": [{"index": 0, "delta": {"content": p}, "finish_reason": None}]}
            yield f"data: {json.dumps(ev)}\n\n"
        last = {"id": rid, "object": "chat.completion.chunk", "created": created, "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                          "total_tokens": prompt_tokens + completion_tokens}}
        yield f"data: {json.dumps(last)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"X-Mock-Id": rid, "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def health(_):
    return JSONResponse({"ok": True, "marker": MARKER})


app = Starlette(routes=[
    Route("/v1/chat/completions", chat_completions, methods=["POST"]),
    Route("/health", health),
])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), log_level="warning")
