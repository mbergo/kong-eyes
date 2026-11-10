"""Prometheus exposition.

Adjudicated classifications are *recomputed gauges* over the newest revision of
the newest finalized run per (environment, route, guardrail, policy_version) -
never ever-increasing counters, because a label correction must be able to
lower a number. Labels are bounded: no run/case/request ids.
Missing populations are omitted (not rendered as zero) so dashboards show
"no data" rather than "no errors".
"""
from __future__ import annotations

from prometheus_client import CollectorRegistry, Gauge, Histogram, generate_latest, REGISTRY
from prometheus_client.core import GaugeMetricFamily

from .store import Store
from .adjudicate import summarize

SCOPE = ["environment", "route", "guardrail", "policy_version", "suite"]

GATEWAY_DURATION = Histogram("go_gateway_duration_ms", "Observer-measured gateway duration (access->log) per request",
                             ["environment", "route"], buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000))
CLIENT_LATENCY = Histogram("go_client_latency_ms", "Runner-measured end-to-end latency", ["environment", "route"],
                           buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000))


class AdjudicationCollector:
    def __init__(self, store: Store):
        self.store = store

    def collect(self):
        counts = GaugeMetricFamily("go_eval_units", "Adjudicated units by detector outcome (latest revision, latest run per scope)",
                                   labels=SCOPE + ["outcome"])
        fpr = GaugeMetricFamily("go_eval_fpr", "FP/(FP+TN) - omitted when denominator is 0", labels=SCOPE)
        fnr = GaugeMetricFamily("go_eval_fnr", "FN/(FN+TP) - omitted when denominator is 0", labels=SCOPE)
        fpden = GaugeMetricFamily("go_eval_fpr_denominator", "FP+TN", labels=SCOPE)
        fnden = GaugeMetricFamily("go_eval_fnr_denominator", "FN+TP", labels=SCOPE)
        enf = GaugeMetricFamily("go_eval_enforcement_failures", "Detected violations that still reached the client", labels=SCOPE)
        benign_blocked = GaugeMetricFamily("go_eval_benign_blocked", "Benign requests blocked or altered", labels=SCOPE)
        viol_deliv = GaugeMetricFamily("go_eval_violations_delivered", "Violating content delivered to client", labels=SCOPE)
        incon = GaugeMetricFamily("go_eval_inconclusive", "Units without a matrix classification", labels=SCOPE)
        cov = GaugeMetricFamily("go_eval_labeled_coverage", "Share of units with a binary classification", labels=SCOPE)
        recon = GaugeMetricFamily("go_eval_manifest_reconciled", "1 if unit count equals runner manifest", labels=SCOPE)
        rev = GaugeMetricFamily("go_eval_revision", "Adjudication revision in use", labels=SCOPE)
        synthetic = GaugeMetricFamily("go_eval_synthetic", "1 if the scope's guardrail is a synthetic fixture", labels=SCOPE)
        by_cat = GaugeMetricFamily("go_eval_units_by_category", "Units by category and outcome", labels=SCOPE + ["category", "outcome"])

        for run in self.store.latest_runs_per_scope():
            adjs = self.store.latest_adjudications(run["run_id"])
            if not adjs:
                continue
            s = summarize(adjs, run.get("manifest") and __import__("json").loads(run["manifest"]))
            lv = [str(run.get("environment")), str(run.get("route")), str(run.get("guardrail")), str(run.get("policy_version")), str(run.get("suite"))]
            for k, v in s["detector"]["counts"].items():
                counts.add_metric(lv + [k], v)
            if s["detector"]["fpr"] is not None:
                fpr.add_metric(lv, s["detector"]["fpr"])
            if s["detector"]["fnr"] is not None:
                fnr.add_metric(lv, s["detector"]["fnr"])
            fpden.add_metric(lv, s["detector"]["fpr_denominator"])
            fnden.add_metric(lv, s["detector"]["fnr_denominator"])
            enf.add_metric(lv, s["enforcement_failures"])
            benign_blocked.add_metric(lv, s["benign_blocked_or_altered"])
            viol_deliv.add_metric(lv, s["violations_delivered"])
            incon.add_metric(lv, s["inconclusive"])
            if s["detector"]["labeled_coverage"] is not None:
                cov.add_metric(lv, s["detector"]["labeled_coverage"])
            if s["reconciled"] is not None:
                recon.add_metric(lv, 1 if s["reconciled"] else 0)
            rev.add_metric(lv, run.get("revision") or 0)
            synthetic.add_metric(lv, 1 if any(a.get("synthetic") for a in adjs) else 0)
            for cat, c in s["by_category"].items():
                for k, v in c.items():
                    by_cat.add_metric(lv + [cat, k], v)
        for m in (counts, fpr, fnr, fpden, fnden, enf, benign_blocked, viol_deliv, incon, cov, recon, rev, synthetic, by_cat):
            yield m


class OutboxCollector:
    def __init__(self, store: Store):
        self.store = store

    def collect(self):
        g = GaugeMetricFamily("go_outbox_events", "Outbox rows by destination and status", labels=["destination", "status"])
        for dest, st in self.store.outbox_stats().items():
            for status, n in st.items():
                g.add_metric([dest, status], n)
        yield g
        u = GaugeMetricFamily("go_unmatched_observations", "Observations without a join partner after the join timeout", labels=["side"])
        um = self.store.unmatched(300)
        u.add_metric(["kong_without_runner"], len(um["kong_without_runner"]))
        u.add_metric(["runner_without_kong"], len(um["runner_without_kong"]))
        u.add_metric(["untrusted_or_passive"], um["untrusted_or_passive_kong_observations"])
        yield u


class PassiveCollector:
    """Recomputed gauges over the last PASSIVE_WINDOW_S of ordinary traffic. Labels stay bounded:
    route and guardrail names only, never consumers or request ids."""

    def __init__(self, store: Store):
        self.store = store
        self._cache: tuple[float, dict] | None = None

    def _summary(self) -> dict:
        import os, time
        from . import passive
        now = time.time()
        if self._cache and now - self._cache[0] < 10:
            return self._cache[1]
        w = float(os.environ.get("PASSIVE_WINDOW_S", "900"))
        s = passive.summarize(self.store.observations_since(int((now - w) * 1000)))
        self._cache = (now, s)
        return s

    def collect(self):
        s = self._summary()
        R, G = ["route"], ["guardrail"]
        req = GaugeMetricFamily("go_live_requests", "Ordinary requests seen in the window", labels=R)
        rblk = GaugeMetricFamily("go_live_route_blocked", "Requests stopped inside the gateway", labels=R)
        share = GaugeMetricFamily("go_live_chain_share", "Median share of gateway time spent in the guardrail chain", labels=R)
        chain = GaugeMetricFamily("go_live_chain_ms", "Time in the guardrail chain", labels=R + ["quantile"])
        gen = GaugeMetricFamily("go_live_route_guardrails_enabled", "Known guardrail plugins enabled on the route", labels=R)
        reached = GaugeMetricFamily("go_live_guardrail_reached", "Requests that reached the guardrail", labels=G)
        blk = GaugeMetricFamily("go_live_guardrail_blocked", "Requests the guardrail stopped", labels=G)
        inl = GaugeMetricFamily("go_live_guardrail_enforced_inline", "Requests the guardrail altered without ending them", labels=G)
        rate = GaugeMetricFamily("go_live_guardrail_block_rate", "(blocked + altered) / reached - omitted when nothing reached it", labels=G)
        lat = GaugeMetricFamily("go_live_guardrail_latency_ms", "Time spent in the guardrail's gap", labels=G + ["quantile"])
        fo = GaugeMetricFamily("go_live_guardrail_fail_open_suspects", "Allowed after about the configured timeout with no decision", labels=G)
        nov = GaugeMetricFamily("go_live_guardrail_no_verdict", "Ran without recording a decision", labels=G)
        err = GaugeMetricFamily("go_live_guardrail_errors", "Guardrail reported an error", labels=G)
        dne = GaugeMetricFamily("go_live_guardrail_detected_not_enforced", "Flagged but still served", labels=G)
        rw = GaugeMetricFamily("go_live_guardrail_rewrites", "Requests whose body changed across the guardrail", labels=G + ["side"])
        ab = GaugeMetricFamily("go_live_after_block", "What callers did after a block", labels=G + ["outcome"])
        cov = GaugeMetricFamily("go_live_coverage_findings", "Coverage findings", labels=R + ["kind"])
        sig = GaugeMetricFamily("go_live_signals", "Signals to investigate", labels=["kind", "severity"])
        drift = GaugeMetricFamily("go_live_config_changes", "Guardrail configuration changes seen in the window", labels=R)
        tok = GaugeMetricFamily("go_live_tokens", "Tokens in the window", labels=["type"])
        misc = GaugeMetricFamily("go_live_traffic", "Request facts in the window", labels=["fact"])
        ttfc = GaugeMetricFamily("go_live_time_to_first_chunk_ms", "Streaming: time to first chunk", labels=["quantile"])

        for name, r in s["routes"].items():
            req.add_metric([name], r["requests"]); rblk.add_metric([name], r["blocked"])
            gen.add_metric([name], len(r["guardrails_enabled"]))
            if r["chain_share_p50"] is not None:
                share.add_metric([name], r["chain_share_p50"])
            for q in ("p50", "p95", "p99"):
                if r["chain_ms"] and r["chain_ms"][q] is not None:
                    chain.add_metric([name, q], r["chain_ms"][q])
            if len(r["policy_fingerprints"]) > 1:
                drift.add_metric([name], len(r["policy_fingerprints"]) - 1)
        for name, g in s["guardrails"].items():
            reached.add_metric([name], g["reached"]); blk.add_metric([name], g["blocked"])
            inl.add_metric([name], g["enforced_inline"])
            if g["intervention_rate"] is not None:
                rate.add_metric([name], g["intervention_rate"])
            for q in ("p50", "p95", "p99"):
                if g["latency_ms"] and g["latency_ms"][q] is not None:
                    lat.add_metric([name, q], g["latency_ms"][q])
            fo.add_metric([name], g["fail_open_suspects"]); nov.add_metric([name], g["no_verdict"])
            err.add_metric([name], g["errors"]); dne.add_metric([name], g["detected_not_enforced"])
            rw.add_metric([name, "request"], g["request_rewrites"]); rw.add_metric([name, "response"], g["response_rewrites"])
        for name, a in s["after_block"].items():
            for k in ("blocks", "followed_by_retry", "retry_blocked_again", "retry_got_through", "retry_changed_body"):
                ab.add_metric([name, k], a[k])
        counts: dict = {}
        for c in s["coverage"]:
            counts[(c["route"], c["kind"])] = counts.get((c["route"], c["kind"]), 0) + 1
        for (route, kind), n in counts.items():
            cov.add_metric([route, kind], n)
        counts = {}
        for x in s["signals"]:
            counts[(x["kind"], x["severity"])] = counts.get((x["kind"], x["severity"]), 0) + 1
        for (kind, sev), n in counts.items():
            sig.add_metric([kind, sev], n)
        t = s["traffic"]
        for k, v in t["tokens"].items():
            tok.add_metric([k], v)
        for k in ("requests", "retried", "upstream_errors", "streamed", "model_mismatch"):
            misc.add_metric([k], t[k])
        misc.add_metric(["cost"], t["cost"])
        for q in ("p50", "p95", "p99"):
            if t["time_to_first_chunk_ms"] and t["time_to_first_chunk_ms"][q] is not None:
                ttfc.add_metric([q], t["time_to_first_chunk_ms"][q])
        for m in (req, rblk, share, chain, gen, reached, blk, inl, rate, lat, fo, nov, err, dne, rw, ab, cov, sig, drift, tok, misc, ttfc):
            yield m


_registered = False


def register(store: Store):
    global _registered
    if _registered:
        return
    REGISTRY.register(AdjudicationCollector(store))
    REGISTRY.register(OutboxCollector(store))
    REGISTRY.register(PassiveCollector(store))
    _registered = True


def render() -> bytes:
    return generate_latest(REGISTRY)
