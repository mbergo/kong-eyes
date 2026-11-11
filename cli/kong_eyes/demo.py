"""koe demo: drive the demo so the pictures move.

  koe demo traffic --kong-url URL --apikey KEY [--path /ai/named] [--rps 60] [--minutes 10] [--calm]

Sends a lot of synthetic requests through Kong, fast, from this process (never from the collector, so heavy
traffic cannot slow the thing that is watching). By default it runs a "storm": the mix changes every few
seconds, so block rates, timeouts and the 3D chain visibly move:

  calm      almost all honest requests
  attack    a burst of plain attacks (the first stand-in guardrail stops them)
  disguise  a burst of disguised attacks (only the second one looks for these)
  slow      the guardrail backend "goes slow": requests wait for its timeout and are let through
  recover   honest callers who were blocked by mistake try again

The prompts carry the markers the repo's synthetic stand-in guardrails and mock model react to, so this is for
the demo routes only. For load against a real route use scripts/kong-load.py.
"""
from __future__ import annotations

import collections
import http.client
import json
import random
import ssl
import threading
import time
import urllib.parse

BENIGN = ["Summarise the attached meeting notes.", "Draft a polite reply to this customer.", "Explain this stack trace.",
          "Translate the paragraph to Portuguese.", "List three risks in this plan.", "Write release notes for the new build.",
          "Rewrite this for a non-technical reader.", "Give three alternatives to a nightly cron job.", "Outline a one-hour onboarding session.",
          "What does HTTP status 429 mean?", "Compare blue-green and canary deployments.", "Suggest a subject line for a maintenance notice."]
# share of each kind per phase (the rest is benign), and how long the phase lasts in seconds
STORM = [("calm", 8, {"violation": 3, "obfuscated": 2}), ("attack", 7, {"violation": 45, "obfuscated": 5}),
         ("calm", 5, {"violation": 3, "obfuscated": 2}), ("disguise", 7, {"violation": 5, "obfuscated": 40}),
         ("slow", 7, {"slow": 35, "violation": 3}), ("recover", 6, {"violation": 2})]
CALM = [("calm", 3600, {"violation": 5, "obfuscated": 3, "slow": 2})]


def prompt(kind: str) -> str:
    b = random.choice(BENIGN)
    return {"benign": f"{b} respond:CLEAN", "violation": f"{b} [[VIOLATION]]", "obfuscated": f"{b} [[VI0LATION]] respond:CLEAN",
            "slow": f"[[FIXTURE_SLOW]] {b} respond:CLEAN"}[kind]


def phase_at(t: float, plan) -> tuple[str, dict]:
    t %= sum(p[1] for p in plan)
    for name, dur, mix in plan:
        if t < dur:
            return name, mix
        t -= dur
    return plan[0][0], plan[0][2]


def traffic(a) -> int:
    u = urllib.parse.urlsplit(a.kong_url.rstrip("/") + a.path)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise SystemExit("--kong-url must be Kong's proxy address, e.g. http://localhost:8000")
    ctx = ssl.create_default_context() if u.scheme == "https" else None
    keys = {"caller-a": a.apikey, "caller-b": a.attacker_apikey or a.apikey}
    plan = CALM if a.calm else STORM
    local, lock = threading.local(), threading.Lock()
    stats, window, lat, retry = collections.Counter(), collections.Counter(), [], collections.deque(maxlen=200)
    sem = threading.Semaphore(a.workers)

    def conn():
        c = getattr(local, "c", None)
        if c is None:
            c = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=30, context=ctx) if ctx else http.client.HTTPConnection(u.hostname, u.port or 80, timeout=30)
            local.c = c
        return c

    def one(kind: str, who: str):
        body = json.dumps({"model": a.model, "messages": [{"role": "user", "content": prompt(kind)}]})
        t0, status = time.time(), 0
        try:
            for _ in (1, 2):
                try:
                    c = conn(); c.request("POST", u.path, body=body, headers={"Content-Type": "application/json", "apikey": keys[who]})
                    r = c.getresponse(); r.read(); status = r.status
                    break
                except Exception:  # noqa: BLE001  reconnect once
                    local.c = None
        finally:
            with lock:
                stats[status] += 1; window[status] += 1; lat.append((time.time() - t0) * 1000)
                if kind == "benign" and status == 403:
                    retry.append(who)               # an honest caller blocked by mistake will try again
            sem.release()

    # a fixed pool: threads keep their connection, which is what makes high rates possible
    import queue
    jobs: queue.Queue = queue.Queue()

    def worker():
        while True:
            j = jobs.get()
            if j is None:
                return
            one(*j)
    pool = [threading.Thread(target=worker, daemon=True) for _ in range(a.workers)]
    for t in pool:
        t.start()

    print(f"koe demo traffic -> {u.scheme}://{u.netloc}{u.path}  ~{a.rps:g} requests/s for {a.minutes:g} min  ({'calm' if a.calm else 'storm'})", flush=True)
    start = last = time.time(); sent = skipped = 0; nxt = start
    try:
        while time.time() - start < a.minutes * 60:
            now = time.time(); name, mix = phase_at(now - start, plan)
            rate = a.rps * (1.4 if name in ("attack", "disguise") else 1.0)
            w = dict(mix); w["benign"] = max(5, 100 - sum(mix.values()))
            kind = random.choices(list(w), list(w.values()))[0]
            who = "caller-b" if kind in ("violation", "obfuscated") else "caller-a"
            if name == "recover" and retry and random.random() < 0.7:
                who, kind = retry.popleft(), "benign"
            if sem.acquire(blocking=False):
                jobs.put((kind, who)); sent += 1
            else:
                skipped += 1                         # every worker is busy: Kong is answering slower than the asked rate
            if now - last >= a.report_s:
                with lock:
                    w2 = dict(window); window.clear(); l = sorted(lat[-800:])
                p95 = l[int(len(l) * 0.95)] if l else 0
                print(f"{int(now - start) // 60:02d}:{int(now - start) % 60:02d} {name:<8} sent={sent} " + " ".join(f"{k or 'ERR'}={v}" for k, v in sorted(w2.items()))
                      + f"  p95={p95:.0f}ms" + (f"  skipped={skipped}" if skipped else ""), flush=True)
                last = now
            nxt += random.expovariate(rate)
            d = nxt - time.time()
            if d > 0:
                time.sleep(d)
            elif d < -1:
                nxt = time.time()                    # fell behind: do not try to catch up in one burst
    except KeyboardInterrupt:
        print("\nstopping", flush=True)
    for _ in pool:
        jobs.put(None)
    for _ in range(a.workers):
        sem.acquire(timeout=35)
    took = time.time() - start
    total = sum(stats.values())
    print(f"done: {total} responses in {took:.0f} s ({total / max(took, 1):.0f}/s)  " + " ".join(f"{k or 'ERR'}={v}" for k, v in sorted(stats.items()))
          + (f"  skipped={skipped}" if skipped else ""), flush=True)
    return 0 if total and stats.get(0, 0) < total * 0.05 else 1
