"""Long-term history in a small SQLite file (history.db in NetScan's data folder), kept for 30 days:
devices online per check, per-minute latency from the Monitor, speed tests and internet checks."""

import os
import sqlite3
import threading
import time

from .devices import data_dir

KEEP_DAYS = 30
_LOCK = threading.Lock()


def _connect():
    db = sqlite3.connect(os.path.join(data_dir(), "history.db"), timeout=5)
    db.execute("CREATE TABLE IF NOT EXISTS samples (ts REAL, kind TEXT, key TEXT, value REAL)")
    db.execute("CREATE INDEX IF NOT EXISTS samples_kind_ts ON samples (kind, ts)")
    return db


def record(kind, key, value, ts=None):
    """Store one value. kinds: online, latency, loss, down, up, bloat, dns_ms, internet_ms."""
    record_many([(ts or time.time(), kind, key, value)])


def record_many(rows):
    if not rows:
        return
    with _LOCK:
        try:
            with _connect() as db:
                db.executemany("INSERT INTO samples VALUES (?, ?, ?, ?)", rows)
        except sqlite3.Error:
            pass  # history is a nice-to-have; never break a scan over it


def prune():
    with _LOCK:
        try:
            with _connect() as db:
                db.execute("DELETE FROM samples WHERE ts < ?", (time.time() - KEEP_DAYS * 86400,))
        except sqlite3.Error:
            pass


def series(kind, since, max_points=400):
    """{key: [(ts, value)]} for one kind since a time, averaged into at most max_points buckets per key."""
    with _LOCK:
        try:
            with _connect() as db:
                rows = db.execute("SELECT ts, key, value FROM samples WHERE kind = ? AND ts >= ? ORDER BY ts",
                                  (kind, since)).fetchall()
        except sqlite3.Error:
            return {}
    by_key = {}
    for ts, key, value in rows:
        by_key.setdefault(key, []).append((ts, value))
    span = max(time.time() - since, 1)
    width = span / max_points
    out = {}
    for key, points in by_key.items():
        if len(points) <= max_points:
            out[key] = points
            continue
        buckets = {}
        for ts, value in points:  # average within equal time buckets so long ranges stay light
            buckets.setdefault(int((ts - since) // width), []).append((ts, value))
        out[key] = [(sum(t for t, _v in b) / len(b), sum(v for _t, v in b) / len(b)) for _i, b in sorted(buckets.items())]
    return out


class MinuteAverager:
    """Collects Monitor pings and writes one average (and loss %) per target per minute."""

    def __init__(self):
        self.minute = None
        self.acc = {}  # label -> [sum_ms, replies, sent]

    def add(self, label, ms, now=None):
        now = now or time.time()
        minute = int(now // 60)
        if self.minute is not None and minute != self.minute:
            self.flush()
        self.minute = minute
        a = self.acc.setdefault(label, [0.0, 0, 0])
        a[2] += 1
        if ms is not None:
            a[0] += ms
            a[1] += 1

    def flush(self):
        if self.minute is None or not self.acc:
            return
        ts = self.minute * 60 + 30
        rows = []
        for label, (total, replies, sent) in self.acc.items():
            if replies:
                rows.append((ts, "latency", label, total / replies))
            rows.append((ts, "loss", label, 100 * (sent - replies) / sent))
        record_many(rows)
        self.acc = {}
