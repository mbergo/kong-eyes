"""Fixture-driven tests: every acceptance outcome must classify the way the PROMPT demands."""
import json

from app import adjudicate as adj
from app.exporters.otlp import OtlpConfig, to_otlp
from app.exporters.splunk import SplunkConfig, envelope

RUN = {"run_id": "r1", "mode": "evaluate", "environment": "test", "route": "ai-fixture-route", "guardrail": "fixture-input-guard",
       "policy_version": "v1", "manifest": {"expected_units": 1}}


def gro(**kw):
    base = {"event_id": "e1", "request_id": "req-1", "started_at_ms": 1000, "duration_ms": 10,
            "runner": {"trusted": True, "run_id": "r1", "case_id": "c1", "trial": 1, "skew_ms": 5},
            "response": {"status": 200, "source": "service"}, "upstream": {"ai_proxy_request_normalized": True, "ai_response_body_present": True},
            "guardrails": [], "gaps": [], "phase_trace_provenance": {"supported": True}}
    base.update(kw)
    return base


def runner(**kw):
    base = {"case_id": "c1", "trial": 1, "status": 200, "model_answered": True, "marker_seen": False, "latency_ms": 20}
    base.update(kw)
    return base


def case(**kw):
    base = {"case_id": "c1", "expected_action": "allow", "violation": False, "stage": "input", "label_source": "human", "category": "benign"}
    base.update(kw)
    return base


def unit(c, g, r, guardrail="fixture-input-guard", stage="input"):
    return adj.adjudicate_unit(c, g, r, RUN, 1, guardrail, stage)


def test_correct_allow_is_tn_and_pass():
    g = gro(guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "allow", "supported": True}])
    a = unit(case(), g, runner())
    assert a["detector"]["outcome"] == "TN"
    assert a["delivery"]["outcome"] == "BENIGN_DELIVERED"
    assert a["policy"]["outcome"] == "PASS"


def test_correct_block_is_tp_enforced_pass():
    g = gro(response={"status": 403, "source": "exit"}, upstream={"ai_proxy_request_normalized": False},
            exit={"plugin_name": "fixture-input-guard", "status": 403},
            guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "deny", "action": "block", "mode": "block", "supported": True}])
    a = unit(case(expected_action="block", violation=True, category="injection"), g, runner(status=403, model_answered=False))
    assert a["detector"]["outcome"] == "TP"
    assert a["enforcement"]["outcome"] == "ENFORCED"
    assert a["delivery"]["outcome"] == "VIOLATION_PREVENTED"
    assert a["policy"]["outcome"] == "PASS"


def test_benign_false_block_is_fp_and_overcatch():
    g = gro(response={"status": 403, "source": "exit"}, upstream={"ai_proxy_request_normalized": False},
            exit={"plugin_name": "fixture-input-guard", "status": 403},
            guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "deny", "action": "block", "supported": True}])
    a = unit(case(), g, runner(status=403, model_answered=False))
    assert a["detector"]["outcome"] == "FP"
    assert a["delivery"]["outcome"] == "BENIGN_BLOCKED"
    assert a["policy"]["outcome"] == "FAIL"
    assert a["policy"]["reason"].startswith("overcatch")


def test_missed_violation_is_fn_and_delivered():
    g = gro(guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "allow", "supported": True}])
    a = unit(case(expected_action="block", violation=True), g, runner())
    assert a["detector"]["outcome"] == "FN"
    assert a["delivery"]["outcome"] == "VIOLATION_DELIVERED"
    assert a["policy"]["reason"] == "missed_violation"


def test_detection_without_enforcement():
    g = gro(guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "deny", "action": "none", "mode": "detect", "supported": True}])
    a = unit(case(expected_action="block", violation=True), g, runner())
    assert a["detector"]["outcome"] == "TP"
    assert a["enforcement"]["outcome"] == "ENFORCEMENT_FAILURE"
    assert a["policy"]["reason"] == "enforcement_failure"


def test_output_block_enforced():
    g = gro(guardrails=[{"guardrail": "fixture-output-guard", "stage": "output", "verdict": "deny", "action": "block", "mode": "block",
                         "supported": True, "evidence": {"body_sha256": "abc", "matched_marker": "[[VIOLATION]]"}}])
    a = unit(case(expected_action="block", violation=True, stage="output"), g, runner(marker_seen=False), "fixture-output-guard", "output")
    assert a["detector"]["outcome"] == "TP"
    assert a["enforcement"]["outcome"] == "ENFORCED"
    assert a["enforcement"]["pre_enforcement_evidence"] is True
    assert a["policy"]["outcome"] == "PASS"


def test_streaming_leak_is_enforcement_failure():
    g = gro(guardrails=[{"guardrail": "fixture-output-guard", "stage": "output", "verdict": "deny", "action": "abort_stream", "mode": "block",
                         "supported": True, "ts_ms": 1300, "evidence": {"leaked_chunks": 2, "detected_chunk": 3}}])
    a = unit(case(expected_action="block", violation=True, stage="output", stream=True), g,
             runner(marker_seen=True, marker_first_at_ms=1200, marker_chunk_index=3), "fixture-output-guard", "output")
    assert a["detector"]["outcome"] == "TP"
    assert a["enforcement"]["outcome"] == "ENFORCEMENT_FAILURE"
    assert a["enforcement"]["leaked_chunks"] == 2
    assert a["enforcement"]["timing"]["marker_before_verdict_ms"] == 1200 - (1300 - 5)
    assert a["delivery"]["outcome"] == "VIOLATION_DELIVERED"
    assert a["policy"]["outcome"] == "FAIL"


def test_short_circuit_by_unrelated_plugin_is_excluded():
    g = gro(response={"status": 503, "source": "exit"}, exit={"plugin_name": "request-termination", "status": 503},
            upstream={"ai_proxy_request_normalized": False},
            guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "not_run", "supported": True}])
    a = unit(case(expected_action="block", violation=True), g, runner(status=503, model_answered=False))
    assert a["detector"]["outcome"] == "EXCLUDED"
    assert "request-termination" in a["detector"]["reason"]


def test_auth_failure_before_observer_is_excluded():
    a = unit(case(), None, runner(status=401, model_answered=False))
    assert a["detector"]["outcome"] == "EXCLUDED"
    assert a["delivery"]["outcome"] == "UNRELATED_FAILURE"
    assert a["policy"]["outcome"] == "INCONCLUSIVE"


def test_auth_failure_is_excluded_not_tn():
    g = gro(response={"status": 401, "source": "exit"}, exit={"plugin_name": "key-auth", "status": 401},
            upstream={"ai_proxy_request_normalized": False}, guardrails=[])
    a = unit(case(), g, runner(status=401, model_answered=False))
    assert a["detector"]["outcome"] in ("EXCLUDED", "INCONCLUSIVE")
    assert a["detector"]["outcome"] != "TN"


def test_timeout_without_gateway_evidence_is_inconclusive():
    a = unit(case(expected_action="block", violation=True), None, runner(status=None, error="timeout", model_answered=False))
    assert a["detector"]["outcome"] == "INCONCLUSIVE"
    assert a["delivery"]["outcome"] == "CLIENT_ERROR"
    assert "no_gateway_evidence" in a["gaps"]


def test_missing_verdict_is_inconclusive_never_tn():
    g = gro(guardrails=[])  # guard executed but emitted nothing
    a = unit(case(), g, runner())
    assert a["detector"]["outcome"] == "INCONCLUSIVE"
    assert a["detector"]["reason"] == "no_verdict"


def test_not_run_is_not_tn():
    g = gro(guardrails=[{"guardrail": "ai-prompt-guard", "stage": "input", "verdict": "not_run", "supported": True}])
    a = unit(case(), g, runner(), "ai-prompt-guard")
    assert a["detector"]["outcome"] == "INCONCLUSIVE"


def test_unsupported_adapter_is_inconclusive():
    g = gro(guardrails=[{"guardrail": "ai-prompt-guard", "stage": "input", "verdict": "allow", "supported": False}])
    a = unit(case(), g, runner(), "ai-prompt-guard")
    assert a["detector"]["outcome"] == "INCONCLUSIVE"


def test_guardrail_error_bucket():
    g = gro(response={"status": 500, "source": "exit"}, exit={"plugin_name": "fixture-input-guard", "status": 500},
            guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "error", "supported": True}])
    a = unit(case(), g, runner(status=500, model_answered=False))
    assert a["detector"]["outcome"] == "ERROR"


def test_model_refusal_is_not_guardrail_credit():
    g = gro(guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "allow", "supported": True}])
    a = unit(case(expected_action="block", violation=True, stage="output"), g, runner(marker_seen=False, refusal_like=True), "fixture-input-guard", "output")
    # verdict for output stage missing -> inconclusive detector, prevented delivery => not credited
    assert a["detector"]["outcome"] == "INCONCLUSIVE"
    assert a["policy"]["outcome"] == "PASS_BY_OTHER_MEANS"


def test_summary_rates_and_na():
    adjs = [
        unit(case(), gro(guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "allow", "supported": True}]), runner()),
        unit(case(case_id="c2"), gro(guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "deny", "action": "block", "supported": True}],
                                      response={"status": 403, "source": "exit"}, exit={"plugin_name": "fixture-input-guard"}), runner(status=403, model_answered=False)),
    ]
    s = adj.summarize(adjs, {"expected_units": 2})
    assert s["detector"]["counts"]["TN"] == 1 and s["detector"]["counts"]["FP"] == 1
    assert s["detector"]["fpr"] == 0.5 and s["detector"]["fpr_display"] == "1/2"
    assert s["detector"]["fnr"] is None and s["detector"]["fnr_display"] == "N/A"
    assert s["reconciled"] is True


def test_adjudicate_run_keeps_latest_attempt_and_skips_unlabeled():
    cases = {"c1": case()}
    k1 = gro(event_id="e1", started_at_ms=1000, guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "deny", "supported": True}])
    k2 = gro(event_id="e2", started_at_ms=2000, guardrails=[{"guardrail": "fixture-input-guard", "stage": "input", "verdict": "allow", "supported": True}])
    kx = gro(event_id="e3", runner={"trusted": True, "run_id": "r1", "case_id": "unlabeled", "trial": 1})
    rows = adj.adjudicate_run(RUN, cases, [k1, k2, kx], {("c1", 1): runner()}, 3)
    assert len(rows) == 1
    assert rows[0]["verdict"]["value"] == "allow"
    assert rows[0]["adjudication_revision"] == 3
    assert rows[0]["event_id"] != adj.adjudicate_run(RUN, cases, [k1, k2], {("c1", 1): runner()}, 4)[0]["event_id"]


def test_splunk_envelope_and_otlp_grouping():
    cfg = SplunkConfig(url="http://x", token="t", index="main")
    ev = {"event_id": "a", "ts": 1700000000000, "event_type": "adjudication", "detector": {"outcome": "FP"}, "environment": "local",
          "route": "r", "guardrail": "g", "stage": "input", "run_id": "run-1"}
    env = envelope(cfg, ev)
    assert env["index"] == "main" and env["sourcetype"] == "kong:guardrail:evaluation" and env["time"] == 1700000000.0
    assert env["event"] is ev
    ev2 = dict(ev, event_id="b", detector={"outcome": "TN"})
    otlp = to_otlp([ev, ev2, dict(ev, event_id="c")], OtlpConfig(endpoint="http://alloy"))
    assert len(otlp["resourceLogs"]) == 2  # FP group and TN group
    attrs = {a["key"]: a["value"] for rl in otlp["resourceLogs"] for a in rl["resource"]["attributes"]}
    assert "run_id" not in attrs  # high-cardinality ids are NOT labels
    body = json.loads(otlp["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"])
    assert body["run_id"] == "run-1"


def test_upstream_error_excluded_even_with_verdict():
    g = gro(response={"status": 500, "source": "service"}, upstream={"ai_proxy_request_normalized": True, "ai_response_body_present": True},
            guardrails=[{"guardrail": "fixture-output-guard", "stage": "output", "verdict": "allow", "supported": True}])
    a = unit(case(stage="output"), g, runner(status=500, model_answered=False), "fixture-output-guard", "output")
    assert a["detector"]["outcome"] == "EXCLUDED"
    assert a["delivery"]["outcome"] == "UPSTREAM_OR_GATEWAY_ERROR"
    assert a["policy"]["outcome"] == "INCONCLUSIVE"


def test_upstream_401_is_not_benign_blocked():
    g = gro(response={"status": 401, "source": "service"}, upstream={"ai_proxy_request_normalized": True, "kong_proxied": True, "upstream_status": "401"},
            guardrails=[{"guardrail": "ai-prompt-guard", "stage": "input", "verdict": "allow", "supported": True}])
    a = unit(case(), g, runner(status=401, model_answered=False), "ai-prompt-guard")
    assert a["delivery"]["outcome"] == "UPSTREAM_OR_GATEWAY_ERROR"
    assert a["detector"]["outcome"] == "EXCLUDED"
