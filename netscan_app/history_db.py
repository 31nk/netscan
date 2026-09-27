"""Long-term history in a small SQLite file (history.db in NetScan's data folder), kept for 30 days:
devices online per check, per-minute latency from the Monitor, speed tests and internet checks."""

import os
import sqlite3
import threading
import time
from contextlib import closing

from .devices import data_dir

KEEP_DAYS = 30
_LOCK = threading.Lock()


_READY = set()  # database files already set up in this run


def _connect():
    path = os.path.join(data_dir(), "history.db")
    fresh = path not in _READY or not os.path.exists(path)  # (the data folder may have been deleted meanwhile)
    db = sqlite3.connect(path, timeout=5)
    if fresh:
        db.execute("PRAGMA journal_mode=WAL")  # the background checks can write while a chart reads
        db.execute("CREATE TABLE IF NOT EXISTS samples (ts REAL, kind TEXT, key TEXT, value REAL)")
        db.execute("CREATE INDEX IF NOT EXISTS samples_kind_ts ON samples (kind, ts)")
        _READY.add(path)
    return db


def record(kind, key, value, ts=None):
    """Store one value. kinds: online, latency, loss, down, up, bloat, dns_ms, internet_ms."""
    record_many([(ts or time.time(), kind, key, value)])


def record_many(rows):
    if not rows:
        return
    with _LOCK:
        try:
            with closing(_connect()) as db, db:
                db.executemany("INSERT INTO samples VALUES (?, ?, ?, ?)", rows)
        except sqlite3.Error:
            pass  # history is a nice-to-have; never break a scan over it


def prune():
    with _LOCK:
        try:
            with closing(_connect()) as db, db:
                db.execute("DELETE FROM samples WHERE ts < ?", (time.time() - KEEP_DAYS * 86400,))
        except sqlite3.Error:
            pass


def series(kind, since, max_points=400):
    """{key: [(ts, value)]} for one kind since a time, averaged into at most max_points buckets per key.
    The averaging happens in SQLite, so a month of per-minute samples stays quick."""
    width = max(time.time() - since, 1) / max_points
    with _LOCK:
        try:
            with closing(_connect()) as db, db:
                most = db.execute("SELECT MAX(n) FROM (SELECT COUNT(*) AS n FROM samples WHERE kind = ? AND ts >= ? "
                                  "GROUP BY key)", (kind, since)).fetchone()[0] or 0
                if most <= max_points:  # few enough: every sample as it was recorded
                    rows = db.execute("SELECT key, ts, value, 1 FROM samples WHERE kind = ? AND ts >= ? "
                                      "ORDER BY key, ts", (kind, since)).fetchall()
                else:
                    rows = db.execute("SELECT key, AVG(ts), AVG(value), COUNT(*) FROM samples WHERE kind = ? AND "
                                      "ts >= ? GROUP BY key, CAST((ts - ?) / ? AS INTEGER) ORDER BY key, MIN(ts)",
                                      (kind, since, since, width)).fetchall()
        except sqlite3.Error:
            return {}
    out = {}
    for key, ts, value, _n in rows:
        out.setdefault(key, []).append((ts, value))
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


def rows(kind, since, until=None, key=None):
    """Raw [(ts, key, value)] for one kind (optionally one key) between two times, oldest first."""
    sql = "SELECT ts, key, value FROM samples WHERE kind = ? AND ts >= ? AND ts <= ?"
    args = [kind, since, until or time.time() + 1]
    if key is not None:
        sql += " AND key = ?"
        args.append(key)
    with _LOCK:
        try:
            with closing(_connect()) as db, db:
                return db.execute(sql + " ORDER BY ts", args).fetchall()
        except sqlite3.Error:
            return []
