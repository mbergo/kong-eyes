"""Unit tests for the checks on ordinary traffic (no Kong needed)."""
from app import passive


def obs(t=0, route="r1", status=200, source="service", blocker=None, conf="high", cands=None, gaps=None, rgaps=None,
        verdicts=None, configured=("ai-proxy", "g1"), guardrails=None, consumer="alice", fp="fp1", timeouts=None,
        duration=100, body="b1", stream=False, **extra):
    g = {"event_id": f"e{t}{route}{status}", "started_at_ms": t, "route": {"name": route}, "environment": "test",
         "response": {"status": status, "source": source}, "duration_ms": duration, "policy_fingerprint": fp,
         "consumer": {"username": consumer} if consumer else None,
         "request": {"body_sha256": body, "model": "m1", "stream_requested": stream},
         "configured_plugins": {"plugins": [{"name": n, "enabled": True} for n in configured]},
         "guardrails_configured": [{"name": n, "enabled": e} for n, e in (guardrails if guardrails is not None else {"g1": True}).items()],
         "guardrails": verdicts if verdicts is not None else [{"guardrail": "g1", "verdict": "allow"}],
         "trail": {"request": [{"p": 790, "t": 0}], "probes_expected": [773], "gaps": gaps if gaps is not None else [
             {"from": 790, "to": 773, "ms": 3, "plugins": ["g1"]}], "response_gaps": rgaps or []}}
    if blocker or source == "exit":
        g["exit"] = {"plugin_name": blocker, "confidence": conf, "probe_trail": {"candidates": cands or ([blocker] if blocker else [])}}
        g["trail"]["exit"] = {"candidates": cands or ([blocker] if blocker else []), "ms": 2}
        g["trail"]["gaps"] = []
    if timeouts:
        g["thresholds"] = {"guardrail_timeouts_ms": timeouts}
    g.update(extra)
    return g


def kinds(s):
    return [x["kind"] for x in s["signals"]]


def test_quantile_and_empty_window():
    assert passive.quantile([], 0.5) is None
    assert passive.quantile([10], 0.95) == 10
    assert passive.quantile([1, 2, 3, 4, 5], 0.5) == 3
    s = passive.summarize([])
    assert s["window"]["requests"] == 0 and s["signals"] == []


def test_block_rate_latency_and_high_block_signal():
    evs = [obs(t=i) for i in range(12)] + [obs(t=100 + i, status=403, source="exit", blocker="g1", verdicts=[{"guardrail": "g1", "verdict": "deny", "enforced_by": "g1"}]) for i in range(8)]
    s = passive.summarize(evs)
    g = s["guardrails"]["g1"]
    assert g["reached"] == 20 and g["blocked"] == 8 and g["block_rate"] == 0.4
    assert g["latency_ms"]["n"] == 20          # 12 allowed gaps + 8 exit gaps
    assert g["blocked_by_confidence"] == {"high": 8}
    assert "high_block_rate" in kinds(s)
    assert s["routes"]["r1"]["block_rate"] == 0.4


def test_small_samples_do_not_raise_rate_signals():
    s = passive.summarize([obs(t=0), obs(t=1, status=403, source="exit", blocker="g1")])
    assert "high_block_rate" not in kinds(s)


def test_suspected_fail_open_needs_timeout_and_no_decision():
    slow_silent = obs(t=1, gaps=[{"from": 790, "to": 773, "ms": 400, "plugins": ["g1"]}], verdicts=[], timeouts={"g1": 400})
    slow_but_denied = obs(t=2, status=403, source="exit", blocker="g1", timeouts={"g1": 400})
    fast = obs(t=3, timeouts={"g1": 400})
    s = passive.summarize([slow_silent, slow_but_denied, fast])
    assert s["guardrails"]["g1"]["fail_open_suspects"] == 1
    assert "suspected_fail_open" in kinds(s)
    assert s["guardrails"]["g1"]["no_verdict"] == 1


def test_shared_gap_gives_no_latency_and_is_reported():
    e = obs(configured=("ai-proxy", "g1", "g2"), guardrails={"g1": True, "g2": True},
            gaps=[{"from": 790, "to": 760, "ms": 9, "plugins": ["g1", "g2"]}],
            verdicts=[{"guardrail": "g1", "verdict": "allow"}, {"guardrail": "g2", "verdict": "allow"}])
    s = passive.summarize([e])
    assert s["guardrails"]["g1"]["latency_ms"] is None and s["guardrails"]["g1"]["latency_shared_gap_requests"] == 1
    assert any(c["kind"] == "guardrails_share_a_gap" for c in s["coverage"])


def test_unattributed_block_counts_candidates_not_blocks():
    e = obs(status=400, source="exit", blocker=None, cands=["g1", "g2"], guardrails={"g1": True, "g2": True}, verdicts=[])
    s = passive.summarize([e])
    assert s["guardrails"]["g1"]["blocked"] == 0 and s["guardrails"]["g1"]["candidate_blocks"] == 1
    assert s["routes"]["r1"]["blocked"] == 1


def test_coverage_missing_disabled_and_no_probes():
    covered = obs(t=1, route="covered")
    bare = obs(t=2, route="bare", guardrails={}, verdicts=[], gaps=[], configured=("ai-proxy",))
    off = obs(t=3, route="off", guardrails={"g1": False}, verdicts=[], gaps=[])
    noprobe = obs(t=4, route="noprobe")
    noprobe["trail"]["probes_expected"] = []
    not_ai = obs(t=5, route="plain", guardrails={}, verdicts=[], gaps=[], configured=("key-auth",))
    s = passive.summarize([covered, bare, off, noprobe, not_ai])
    by = {(c["route"], c["kind"]) for c in s["coverage"]}
    assert ("bare", "ai_route_without_guardrail") in by
    assert ("bare", "guardrail_missing_vs_peers") in by
    assert ("off", "guardrail_disabled") in by
    assert ("noprobe", "no_probes") in by
    assert not any(r == "plain" for r, _ in by)          # not an AI route: nothing to cover
    assert not any(r == "covered" for r, _ in by)


def test_rewrites_request_and_response_side():
    e = obs(gaps=[{"from": 790, "to": 773, "ms": 1, "plugins": ["g1"], "rewritten": True}],
            rgaps=[{"from": 765, "to": 750, "plugins": ["out"], "changed": True, "bytes_delta": -139}],
            guardrails={"g1": True, "out": True},
            verdicts=[{"guardrail": "g1", "verdict": "allow"}, {"guardrail": "out", "verdict": "deny", "enforced_by": "out"}])
    s = passive.summarize([e])
    assert s["guardrails"]["g1"]["request_rewrites"] == 1
    assert s["guardrails"]["out"]["response_rewrites"] == 1 and s["guardrails"]["out"]["response_bytes_delta_mean"] == -139
    assert s["guardrails"]["out"]["detected_not_enforced"] == 0   # it enforced by rewriting
    assert s["guardrails"]["out"]["enforced_inline"] == 1 and s["guardrails"]["out"]["intervention_rate"] == 1.0
    assert s["guardrails"]["out"]["blocked"] == 0


def test_detected_not_enforced():
    e = obs(verdicts=[{"guardrail": "g1", "verdict": "deny", "mode": "detect"}])
    s = passive.summarize([e])
    assert s["guardrails"]["g1"]["detected_not_enforced"] == 1 and "detected_not_enforced" in kinds(s)


def test_after_block_retry_gets_through_and_window():
    evs = []
    for i in range(4):
        base = i * 1_000_000
        evs.append(obs(t=base, status=403, source="exit", blocker="g1", body=f"a{i}"))
        evs.append(obs(t=base + 5_000, body=f"b{i}"))                      # same caller, rephrased, allowed
    evs.append(obs(t=9_000_000, status=403, source="exit", blocker="g1", consumer="bob"))
    evs.append(obs(t=9_000_000 + 500_000, consumer="bob"))                # outside the 120 s window
    s = passive.summarize(evs)
    a = s["after_block"]["g1"]
    assert a["blocks"] == 5 and a["followed_by_retry"] == 4 and a["retry_got_through"] == 4 and a["retry_changed_body"] == 4
    assert "retry_gets_through" in kinds(s)
    assert s["repeat_blocked_consumers"][0] == ("alice", 4)


def test_drift_after_config_change():
    before = [obs(t=i, fp="A") for i in range(10)]
    after = [obs(t=100 + i, fp="B", status=403, source="exit", blocker="g1") for i in range(6)] + [obs(t=200 + i, fp="B") for i in range(4)]
    s = passive.summarize(before + after)
    d = s["drift"][0]
    assert d["from"] == "A" and d["to"] == "B" and d["block_rate_before"] == 0 and d["block_rate_after"] == 0.6
    sig = [x for x in s["signals"] if x["kind"] == "guardrail_config_changed"][0]
    assert sig["severity"] == "warn"


def test_traffic_facts_tokens_models_retries_streaming():
    e1 = obs(t=1000, stream=True, ai_native={"proxy": {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15, "cost": 0.002},
                                                         "meta": {"request_model": "m1", "response_model": "m2"}}},
             attempts=[{}, {}])
    e1["stream"] = {"first_chunk_at_ms": 1250, "chunks": 7}
    e2 = obs(t=2000, status=502, source="service")
    s = passive.summarize([e1, e2])
    t = s["traffic"]
    assert t["tokens"]["total_tokens"] == 15 and t["cost"] == 0.002 and t["model_mismatch"] == 1
    assert t["retried"] == 1 and t["upstream_errors"] == 1 and t["streamed"] == 1
    assert t["time_to_first_chunk_ms"]["p50"] == 250 and t["stream_chunks"]["max"] == 7


def test_every_signal_is_marked_investigate():
    evs = [obs(t=i, status=403, source="exit", blocker="g1") for i in range(25)]
    s = passive.summarize(evs)
    assert s["signals"] and all(x["status"] == "investigate" for x in s["signals"])


def test_prune_drops_old_ordinary_traffic_and_keeps_labelled_runs(tmp_path):
    import time
    from app.store import Store
    st = Store(str(tmp_path / "t.db")); now = int(time.time() * 1000)
    def obs(eid, age_h, run=None):
        with st.tx() as c:
            c.execute("INSERT INTO kong_observations(event_id, received_at, run_id, started_at_ms, payload) VALUES (?,?,?,?,?)",
                      (eid, time.time(), run, now - int(age_h * 3600_000), "{}"))
    obs("old", 30); obs("new", 1); obs("old-run", 30, run="r1")
    st.enqueue("otlp", "e1", {"a": 1}); st.mark_sent([st.q1("SELECT id FROM outbox")["id"]])
    with st.tx() as c:
        c.execute("UPDATE outbox SET created_at = created_at - 7200")
    n = st.prune(24)
    assert n["observations"] == 1 and n["outbox_sent"] == 1
    assert {r["event_id"] for r in st.q("SELECT event_id FROM kong_observations")} == {"new", "old-run"}
