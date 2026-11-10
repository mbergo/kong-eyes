import json

from app import passive, translate
from tests.test_passive import obs


def _summary():
    evs = [obs(t=i) for i in range(12)] + [obs(t=100 + i, status=403, source="exit", blocker="g1") for i in range(8)]
    return passive.summarize(evs)


def test_payload_has_no_consumer_names_by_default():
    p = translate.build_payload(_summary(), salt="s")
    raw = json.dumps(p)
    assert "alice" not in raw and "caller-" in raw
    assert "alice" in json.dumps(translate.build_payload(_summary(), include_consumers=True))


def test_stub_translation_tags_everything_investigate():
    out = translate.translate(_summary(), provider="stub")
    assert out["provider"] == "stub" and out["findings"]
    assert all(f["status"] == "investigate" for f in out["findings"])
    assert out["input_signals"] >= 1


def test_model_reply_is_parsed_from_a_code_fence_and_bounded():
    reply = "```json\n" + json.dumps({"headline": "h", "findings": [{"title": "t", "severity": "critical", "observed": "o",
                                                                       "could_mean": "c", "next_check": "n", "based_on": ["high_block_rate"]}] * 12}) + "\n```"
    out = translate.translate(_summary(), provider="anthropic", call=lambda payload: reply)
    assert len(out["findings"]) == 8
    assert out["findings"][0]["severity"] == "info"          # unknown severity is normalised
    assert out["findings"][0]["status"] == "investigate"


def test_provider_failure_falls_back_to_offline_translation():
    def boom(payload):
        raise RuntimeError("503 overloaded")
    out = translate.translate(_summary(), provider="anthropic", call=boom)
    assert "503 overloaded" in out["error"] and out["provider"] == "stub (fallback)" and out["findings"]


def test_no_signals_gives_empty_findings():
    out = translate.translate(passive.summarize([obs(t=1)]), provider="stub")
    assert out["findings"] == [] and "No signals" in out["headline"]
