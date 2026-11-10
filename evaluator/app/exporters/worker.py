"""Per-destination outbox workers. One thread per destination; a Splunk outage
never blocks Grafana and vice versa. Events are acknowledged to Kong/runner
only after they are in SQLite (see main.py), so a worker restart replays the
pending rows; duplicates downstream are deduplicated by event_id.
"""
from __future__ import annotations

import json
import logging
import threading
import time

from ..store import Store
from . import metrics_hooks

log = logging.getLogger("exporter")


class OutboxWorker(threading.Thread):
    def __init__(self, store: Store, destination: str, sender, batch_size: int = 100, interval_s: float = 1.0,
                 max_attempts: int = 1000, base_delay_s: float = 1.0, max_delay_s: float = 60.0):
        super().__init__(name=f"outbox-{destination}", daemon=True)
        self.store, self.destination, self.sender = store, destination, sender
        self.batch_size, self.interval_s = batch_size, interval_s
        self.max_attempts, self.base_delay_s, self.max_delay_s = max_attempts, base_delay_s, max_delay_s
        self._stop = threading.Event()
        self.last_result: tuple[bool, str] | None = None
        self.last_success_at: float | None = None

    def stop(self):
        self._stop.set()

    def run_once(self) -> int:
        rows = self.store.due(self.destination, self.batch_size)
        if not rows:
            return 0
        events = [json.loads(r["payload"]) for r in rows]
        ids = [r["id"] for r in rows]
        ok, detail = self.sender.send(events)
        self.last_result = (ok, detail)
        if ok:
            self.store.mark_sent(ids)
            self.last_success_at = time.time()
            metrics_hooks.export_result(self.destination, "sent", len(ids))
        else:
            attempts = max(r["attempts"] for r in rows) + 1
            delay = min(self.max_delay_s, self.base_delay_s * (2 ** min(attempts, 10)))
            self.store.mark_retry(ids, detail, delay, self.max_attempts)
            metrics_hooks.export_result(self.destination, "retry", len(ids))
            log.warning("%s export failed (attempt %d, retry in %.1fs): %s", self.destination, attempts, delay, detail)
        return len(ids)

    def run(self):
        while not self._stop.is_set():
            try:
                n = self.run_once()
            except Exception as e:  # noqa: BLE001
                log.exception("outbox worker error: %s", e)
                n = 0
            if n == 0:
                self._stop.wait(self.interval_s)
