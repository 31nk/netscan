"""Long-term history (SQLite), the LAN speed test, and small helpers for charts and the command palette."""

import os
import socket
import time
import unittest

import _support

from netscan_app import history_db, lanspeed
from netscan_app.palette import PaletteDialog
from netscan_app.widgets import nice_ceiling


class History(unittest.TestCase):
    def setUp(self):
        db = os.path.join(_support.TMP, "data", "history.db")
        if os.path.exists(db):
            os.remove(db)

    def test_record_series_and_prune(self):
        now = time.time()
        history_db.record_many([(now - 40 * 86400, "online", "net", 3),  # older than 30 days
                                (now - 60, "online", "net", 5), (now, "online", "net", 6),
                                (now, "down", "Cloudflare", 500)])
        self.assertEqual(history_db.series("online", now - 3600), {"net": [(now - 60, 5), (now, 6)]})
        history_db.prune()
        self.assertEqual(len(history_db.series("online", 0)["net"]), 2)

    def test_downsampled_to_max_points(self):
        now = time.time()
        history_db.record_many([(now - 3600 + i, "latency", "Router", float(i % 10)) for i in range(3600)])
        points = history_db.series("latency", now - 3600, max_points=100)["Router"]
        self.assertLessEqual(len(points), 101)
        self.assertAlmostEqual(sum(v for _t, v in points) / len(points), 4.5, delta=0.5)

    def test_minute_averager(self):
        avg = history_db.MinuteAverager()
        base = (time.time() // 60) * 60
        for ms in (10.0, 20.0, None, 30.0):
            avg.add("Router", ms, base + 1)
        avg.add("Router", 5.0, base + 61)  # next minute: writes the first one
        latency = history_db.series("latency", base - 60)["Router"]
        loss = history_db.series("loss", base - 60)["Router"]
        self.assertEqual(latency, [(base + 30, 20.0)])
        self.assertEqual(loss, [(base + 30, 25.0)])
        avg.flush()
        self.assertEqual(len(history_db.series("latency", base - 60)["Router"]), 2)


class LanSpeed(unittest.TestCase):
    def test_against_own_listener(self):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", lanspeed.LAN_PORT)) == 0:
                self.skipTest("port in use (NetScan's listener is on?)")
        server = lanspeed.LanSpeedServer()
        server.start("127.0.0.1")
        try:
            result = lanspeed.lan_speed_test("127.0.0.1", seconds=1)
        finally:
            server.stop()
        self.assertGreater(result["down"], 10)
        self.assertGreater(result["up"], 10)


class Helpers(unittest.TestCase):
    def test_nice_ceiling(self):
        self.assertEqual([nice_ceiling(v) for v in (0, 0.7, 3, 12, 51, 1000)], [1.0, 1, 5, 20, 100, 1000])

    def test_palette_ranking(self):
        score = PaletteDialog.score
        self.assertEqual(score("", "Anything"), 0)
        self.assertEqual(score("spe", "Speed test"), 1)
        self.assertEqual(score("test", "Speed test"), 1)
        self.assertEqual(score("whois", "IP info", "whois rdap owner"), 1.5)
        self.assertIsNone(score("xyz", "Speed test"))
        self.assertLess(score("spt", "Speed test"), score("spt", "Subnet calculator for pt"[:17]) or 99)


if __name__ == "__main__":
    unittest.main()
