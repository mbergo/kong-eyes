"""Prometheus counters shared by ingestion and exporters (avoid import cycles)."""
from prometheus_client import Counter

INGEST = Counter("go_ingest_events_total", "Observations received by the evaluator",
                 ["source", "result"])  # source=kong|runner ; result=accepted|duplicate|rejected|unauthorized
EXPORT = Counter("go_export_events_total", "Events handed to destinations", ["destination", "result"])  # result=sent|retry


def ingest_result(source: str, result: str, n: int = 1):
    INGEST.labels(source=source, result=result).inc(n)


def export_result(destination: str, result: str, n: int = 1):
    EXPORT.labels(destination=destination, result=result).inc(n)
