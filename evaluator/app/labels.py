"""Names people give to guardrails. Kong knows a guardrail by its plugin name (say `ai-prompt-guard`); a person can
give it a readable one on the dashboard, and every page then shows that name. Stored next to the database."""
from __future__ import annotations

import json
import os
import re
import threading

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()
PATH = os.path.join(os.path.dirname(os.environ.get("EVAL_DB_PATH", "/data/evaluator.db")) or ".", "labels.json")
_lock = threading.Lock()
_labels: dict[str, str] | None = None
_pattern: re.Pattern | None = None
on_change = lambda: None          # set by main.py: drop cached summaries


def all_labels() -> dict[str, str]:
    global _labels
    with _lock:
        if _labels is None:
            try:
                with open(PATH, encoding="utf-8") as f:
                    raw = json.load(f)
                _labels = {str(k): str(v) for k, v in raw.items() if isinstance(v, str) and v.strip()}
            except (OSError, ValueError, AttributeError):
                _labels = {}
        return dict(_labels)


def _save(labels: dict[str, str]) -> None:
    global _labels, _pattern
    with _lock:
        tmp = PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(labels, f, ensure_ascii=False, indent=1)
        os.replace(tmp, PATH)
        _labels, _pattern = dict(labels), None
    on_change()


def text(s):
    """Replace each plugin name that stands as a word of its own with the name a person gave it."""
    global _pattern
    labels = all_labels()
    if not labels or not isinstance(s, str) or not s:
        return s
    if _pattern is None:
        _pattern = re.compile(r"(?<![\w-])(" + "|".join(re.escape(k) for k in sorted(labels, key=len, reverse=True)) + r")(?![\w-])")
    return _pattern.sub(lambda m: labels.get(m.group(1), m.group(1)), s)


def deep(x):
    """text() on every string inside lists and dicts (values only; keys stay plugin names)."""
    if isinstance(x, str):
        return text(x)
    if isinstance(x, list):
        return [deep(v) for v in x]
    if isinstance(x, dict):
        return {k: deep(v) for k, v in x.items()}
    return x


def apply_summary(s: dict) -> dict:
    """Put the given names on a passive summary: the chain labels and the wording of the signals."""
    labels = all_labels()
    if not labels:
        return s
    for r in (s.get("routes") or {}).values():
        for c in r.get("chain") or []:
            if c.get("name") in labels:
                c["label"] = labels[c["name"]]
    for sig in s.get("signals") or []:
        for k in ("summary", "detail"):
            if isinstance(sig.get(k), str):
                sig[k] = text(sig[k])
    return s


@router.get("/api/labels")
def get_labels():
    return {"labels": all_labels()}


@router.put("/api/labels/{name}")
async def put_label(name: str, request: Request):
    """Body: {"label": "Readable name"}. An empty label goes back to the plugin name."""
    try:
        label = str((await request.json()).get("label") or "").strip()
    except (ValueError, AttributeError):
        raise HTTPException(400, 'send {"label": "..."}') from None
    if not re.fullmatch(r"[\w.:-]{1,80}", name):
        raise HTTPException(400, "that is not a plugin name")
    if len(label) > 40 or any(ord(ch) < 32 for ch in label):
        raise HTTPException(400, "a name can be up to 40 characters")
    labels = all_labels()
    if label and label != name:
        labels[name] = label
    else:
        labels.pop(name, None)
    _save(labels)
    return {"labels": labels}
