"""SQLite persistence for the evaluator. Single file, WAL mode, no ORM.

Tables
  kong_observations   one row per Kong request seen by the observer (dedup on event_id)
  runner_observations one row per (run_id, case_id, trial) as seen by the test runner
  runs                run manifests, mode, status
  cases               labeled cases per run (ground truth, never sent to the guardrail)
  adjudications       versioned classification per evaluation unit
  outbox              per-destination durable export queue
  ingest_log          raw ingestion accounting (accepted / duplicate / rejected)
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS kong_observations (
  event_id TEXT PRIMARY KEY,
  received_at REAL NOT NULL,
  request_id TEXT,
  run_id TEXT, case_id TEXT, trial INTEGER,
  runner_trusted INTEGER NOT NULL DEFAULT 0,
  environment TEXT, route TEXT, status INTEGER,
  started_at_ms INTEGER,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_kobs_unit ON kong_observations(run_id, case_id, trial);
CREATE INDEX IF NOT EXISTS ix_kobs_req ON kong_observations(request_id);
-- every live number is a time-window query; without this each one scans the whole table
CREATE INDEX IF NOT EXISTS ix_kobs_started ON kong_observations(started_at_ms);

CREATE TABLE IF NOT EXISTS runner_observations (
  run_id TEXT NOT NULL, case_id TEXT NOT NULL, trial INTEGER NOT NULL,
  received_at REAL NOT NULL,
  request_id TEXT,
  payload TEXT NOT NULL,
  PRIMARY KEY (run_id, case_id, trial)
);

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  created_at REAL NOT NULL,
  mode TEXT NOT NULL,                 -- observe | evaluate
  status TEXT NOT NULL,               -- open | finalized
  environment TEXT, route TEXT, guardrail TEXT, policy_version TEXT, suite TEXT,
  manifest TEXT NOT NULL,
  finalized_at REAL,
  revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cases (
  run_id TEXT NOT NULL, case_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY (run_id, case_id)
);

CREATE TABLE IF NOT EXISTS adjudications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  run_id TEXT NOT NULL, case_id TEXT NOT NULL, trial INTEGER NOT NULL,
  guardrail TEXT NOT NULL, stage TEXT NOT NULL,
  revision INTEGER NOT NULL,
  created_at REAL NOT NULL,
  detector_outcome TEXT, enforcement_outcome TEXT, delivery_outcome TEXT, policy_outcome TEXT,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_adj_unit ON adjudications(run_id, case_id, trial, guardrail, stage, revision);

CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  destination TEXT NOT NULL,
  event_id TEXT NOT NULL,
  created_at REAL NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',   -- pending | sent | failed
  last_error TEXT,
  payload TEXT NOT NULL,
  UNIQUE(destination, event_id)
);
CREATE INDEX IF NOT EXISTS ix_outbox_due ON outbox(destination, status, next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_outbox_status_created ON outbox(status, created_at);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at REAL NOT NULL,
  provider TEXT,
  payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at REAL NOT NULL,
  source TEXT NOT NULL,
  result TEXT NOT NULL,       -- accepted | duplicate | rejected | unauthorized
  detail TEXT
);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(SCHEMA)
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(runs)")}
        if "suite" not in cols:
            self._conn.execute("ALTER TABLE runs ADD COLUMN suite TEXT")

    @contextmanager
    def tx(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def q(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def q1(self, sql: str, params: Iterable[Any] = ()) -> Optional[sqlite3.Row]:
        rows = self.q(sql, params)
        return rows[0] if rows else None

    # ------------------------------------------------------------ ingestion
    def log_ingest(self, source: str, result: str, detail: str | None = None):
        with self.tx() as c:
            c.execute("INSERT INTO ingest_log(received_at, source, result, detail) VALUES (?,?,?,?)",
                      (time.time(), source, result, detail))

    def insert_kong_observation(self, gro: dict, full_event: dict | None = None) -> bool:
        """Returns True if inserted, False if duplicate (same event_id). Stores the normalized observation."""
        runner = gro.get("runner") or {}
        trusted = 1 if runner.get("trusted") else 0
        route = (gro.get("route") or {}).get("name") or (gro.get("route") or {}).get("id")
        with self.tx() as c:
            try:
                c.execute(
                    """INSERT INTO kong_observations(event_id, received_at, request_id, run_id, case_id, trial,
                       runner_trusted, environment, route, status, started_at_ms, payload)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (gro["event_id"], time.time(), gro.get("request_id"),
                     runner.get("run_id") if trusted else None,
                     runner.get("case_id") if trusted else None,
                     runner.get("trial") if trusted else None,
                     trusted, gro.get("environment"), route,
                     (gro.get("response") or {}).get("status"), gro.get("started_at_ms"),
                     json.dumps(gro, separators=(",", ":"))))
                return True
            except sqlite3.IntegrityError:
                return False

    def observations_since(self, since_ms: int, include_runs: bool = False, route: str | None = None, limit: int = 50000) -> list[dict]:
        """Observations that started at or after since_ms. Ordinary traffic only unless include_runs."""
        sql = "SELECT payload FROM kong_observations WHERE started_at_ms >= ?"
        params: list[Any] = [since_ms]
        if not include_runs:
            sql += " AND runner_trusted = 0"
        if route:
            sql += " AND route = ?"
            params.append(route)
        sql += " ORDER BY started_at_ms DESC LIMIT ?"
        params.append(limit)
        return [json.loads(r["payload"]) for r in self.q(sql, params)]

    def prune(self, keep_hours: float, keep_sent_minutes: float = 30) -> dict:
        """Retention. Ordinary-traffic observations older than keep_hours go; labelled runs are kept (they are the
        record of a test). Exported outbox rows are copies of events already delivered, so they go after
        keep_sent_minutes. Freed pages are reused; the file does not shrink without a VACUUM."""
        now = time.time()
        with self.tx() as c:
            a = c.execute("DELETE FROM kong_observations WHERE run_id IS NULL AND started_at_ms < ?",
                          (int((now - keep_hours * 3600) * 1000),)).rowcount
            b = c.execute("DELETE FROM outbox WHERE status='sent' AND created_at < ?", (now - keep_sent_minutes * 60,)).rowcount
            d = c.execute("DELETE FROM ingest_log WHERE received_at < ?", (now - keep_hours * 3600,)).rowcount
        try:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        return {"observations": a, "outbox_sent": b, "ingest_log": d}

    def save_findings(self, doc: dict) -> int:
        with self.tx() as c:
            cur = c.execute("INSERT INTO findings(created_at, provider, payload) VALUES (?,?,?)",
                            (time.time(), doc.get("provider"), json.dumps(doc, separators=(",", ":"))))
            return cur.lastrowid

    def latest_findings(self, limit: int = 1) -> list[dict]:
        return [json.loads(r["payload"]) for r in self.q("SELECT payload FROM findings ORDER BY id DESC LIMIT ?", (limit,))]

    def upsert_runner_observation(self, run_id: str, case_id: str, trial: int, obs: dict):
        with self.tx() as c:
            c.execute(
                """INSERT INTO runner_observations(run_id, case_id, trial, received_at, request_id, payload)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(run_id, case_id, trial) DO UPDATE SET received_at=excluded.received_at,
                     request_id=excluded.request_id, payload=excluded.payload""",
                (run_id, case_id, trial, time.time(), obs.get("request_id"), json.dumps(obs, separators=(",", ":"))))

    # ----------------------------------------------------------------- runs
    def create_run(self, run_id: str, mode: str, manifest: dict, cases: list[dict]):
        with self.tx() as c:
            c.execute(
                """INSERT OR REPLACE INTO runs(run_id, created_at, mode, status, environment, route, guardrail,
                   policy_version, suite, manifest) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (run_id, time.time(), mode, "open", manifest.get("environment"), manifest.get("route"),
                 manifest.get("guardrail"), manifest.get("policy_version"), manifest.get("suite"), json.dumps(manifest)))
            c.execute("DELETE FROM cases WHERE run_id=?", (run_id,))
            for case in cases:
                c.execute("INSERT INTO cases(run_id, case_id, payload) VALUES (?,?,?)",
                          (run_id, case["case_id"], json.dumps(case)))

    def get_run(self, run_id: str) -> Optional[dict]:
        r = self.q1("SELECT * FROM runs WHERE run_id=?", (run_id,))
        if not r:
            return None
        d = dict(r)
        d["manifest"] = json.loads(d["manifest"])
        return d

    def list_runs(self, limit: int = 100) -> list[dict]:
        out = []
        for r in self.q("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)):
            d = dict(r); d["manifest"] = json.loads(d["manifest"]); out.append(d)
        return out

    def get_cases(self, run_id: str) -> dict[str, dict]:
        return {r["case_id"]: json.loads(r["payload"]) for r in self.q("SELECT case_id, payload FROM cases WHERE run_id=?", (run_id,))}

    def update_case(self, run_id: str, case: dict):
        with self.tx() as c:
            c.execute("INSERT OR REPLACE INTO cases(run_id, case_id, payload) VALUES (?,?,?)",
                      (run_id, case["case_id"], json.dumps(case)))

    def kong_obs_for_run(self, run_id: str) -> list[dict]:
        return [json.loads(r["payload"]) for r in self.q(
            "SELECT payload FROM kong_observations WHERE run_id=? AND runner_trusted=1 ORDER BY started_at_ms", (run_id,))]

    def runner_obs_for_run(self, run_id: str) -> dict[tuple[str, int], dict]:
        return {(r["case_id"], r["trial"]): json.loads(r["payload"]) for r in self.q(
            "SELECT case_id, trial, payload FROM runner_observations WHERE run_id=?", (run_id,))}

    def bump_revision(self, run_id: str, finalize: bool) -> int:
        with self.tx() as c:
            r = c.execute("SELECT revision FROM runs WHERE run_id=?", (run_id,)).fetchone()
            rev = (r["revision"] if r else 0) + 1
            c.execute("UPDATE runs SET revision=?, status=?, finalized_at=? WHERE run_id=?",
                      (rev, "finalized" if finalize else "open", time.time() if finalize else None, run_id))
            return rev

    def insert_adjudications(self, rows: list[dict]):
        with self.tx() as c:
            for a in rows:
                c.execute(
                    """INSERT OR IGNORE INTO adjudications(event_id, run_id, case_id, trial, guardrail, stage, revision,
                       created_at, detector_outcome, enforcement_outcome, delivery_outcome, policy_outcome, payload)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (a["event_id"], a["run_id"], a["case_id"], a["trial"], a["guardrail"], a["stage"], a["adjudication_revision"],
                     time.time(), a["detector"]["outcome"], a["enforcement"]["outcome"], a["delivery"]["outcome"],
                     a["policy"]["outcome"], json.dumps(a, separators=(",", ":"))))

    def latest_adjudications(self, run_id: str) -> list[dict]:
        rows = self.q(
            """SELECT a.payload FROM adjudications a
               JOIN (SELECT run_id, case_id, trial, guardrail, stage, MAX(revision) AS rev
                     FROM adjudications WHERE run_id=? GROUP BY run_id, case_id, trial, guardrail, stage) m
               ON a.run_id=m.run_id AND a.case_id=m.case_id AND a.trial=m.trial AND a.guardrail=m.guardrail
                  AND a.stage=m.stage AND a.revision=m.rev""", (run_id,))
        return [json.loads(r["payload"]) for r in rows]

    def latest_runs_per_scope(self) -> list[dict]:
        """Newest finalized run per (environment, route, guardrail, policy_version, suite) for gauge recomputation."""
        rows = self.q(
            """SELECT r.* FROM runs r JOIN (
                 SELECT environment, route, guardrail, policy_version, suite, MAX(created_at) AS ca FROM runs
                 WHERE status='finalized' GROUP BY environment, route, guardrail, policy_version, suite) m
               ON r.environment IS m.environment AND r.route IS m.route AND r.guardrail IS m.guardrail
                  AND r.policy_version IS m.policy_version AND r.suite IS m.suite AND r.created_at=m.ca""")
        return [dict(r) for r in rows]

    # --------------------------------------------------------------- outbox
    def enqueue(self, destination: str, event_id: str, payload: dict):
        with self.tx() as c:
            c.execute("""INSERT OR IGNORE INTO outbox(destination, event_id, created_at, next_attempt_at, payload)
                         VALUES (?,?,?,?,?)""",
                      (destination, event_id, time.time(), time.time(), json.dumps(payload, separators=(",", ":"))))

    def due(self, destination: str, limit: int) -> list[sqlite3.Row]:
        return self.q("""SELECT * FROM outbox WHERE destination=? AND status='pending' AND next_attempt_at<=?
                         ORDER BY id LIMIT ?""", (destination, time.time(), limit))

    def mark_sent(self, ids: list[int]):
        if not ids:
            return
        with self.tx() as c:
            c.executemany("UPDATE outbox SET status='sent', last_error=NULL WHERE id=?", [(i,) for i in ids])

    def mark_retry(self, ids: list[int], error: str, delay_s: float, max_attempts: int):
        if not ids:
            return
        with self.tx() as c:
            for i in ids:
                c.execute("""UPDATE outbox SET attempts=attempts+1, last_error=?, next_attempt_at=?,
                             status=CASE WHEN attempts+1>=? THEN 'failed' ELSE 'pending' END WHERE id=?""",
                          (error[:500], time.time() + delay_s, max_attempts, i))

    def outbox_stats(self) -> dict:
        out: dict[str, dict[str, int]] = {}
        for r in self.q("SELECT destination, status, COUNT(*) AS n FROM outbox GROUP BY destination, status"):
            out.setdefault(r["destination"], {})[r["status"]] = r["n"]
        return out

    def requeue_failed(self, destination: str) -> int:
        with self.tx() as c:
            cur = c.execute("UPDATE outbox SET status='pending', attempts=0, next_attempt_at=? WHERE destination=? AND status='failed'",
                            (time.time(), destination))
            return cur.rowcount

    # ------------------------------------------------------------ unmatched
    def unmatched(self, join_timeout_s: float) -> dict:
        cutoff = time.time() - join_timeout_s
        kong_only = self.q(
            """SELECT k.event_id, k.run_id, k.case_id, k.trial, k.request_id, k.received_at FROM kong_observations k
               LEFT JOIN runner_observations r ON r.run_id=k.run_id AND r.case_id=k.case_id AND r.trial=k.trial
               WHERE k.runner_trusted=1 AND r.run_id IS NULL AND k.received_at<? ORDER BY k.received_at DESC LIMIT 500""", (cutoff,))
        runner_only = self.q(
            """SELECT r.run_id, r.case_id, r.trial, r.request_id, r.received_at FROM runner_observations r
               LEFT JOIN kong_observations k ON r.run_id=k.run_id AND r.case_id=k.case_id AND r.trial=k.trial AND k.runner_trusted=1
               WHERE k.event_id IS NULL AND r.received_at<? ORDER BY r.received_at DESC LIMIT 500""", (cutoff,))
        untrusted = self.q1("SELECT COUNT(*) AS n FROM kong_observations WHERE runner_trusted=0")
        return {"join_timeout_s": join_timeout_s,
                "kong_without_runner": [dict(r) for r in kong_only],
                "runner_without_kong": [dict(r) for r in runner_only],
                "untrusted_or_passive_kong_observations": untrusted["n"] if untrusted else 0}

    def ingest_counts(self) -> dict:
        out: dict[str, dict[str, int]] = {}
        for r in self.q("SELECT source, result, COUNT(*) AS n FROM ingest_log GROUP BY source, result"):
            out.setdefault(r["source"], {})[r["result"]] = r["n"]
        return out
