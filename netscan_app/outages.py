"""Internet outage log and the ISP report.

While the optional connection watch is on, the router and two public servers (1.1.1.1, 8.8.8.8) are pinged
every 30 seconds. The internet counts as down when the router answers but neither public server does for a
minute; when the router doesn't answer either, it's the home network (or this computer's link) that's down,
which isn't the provider's fault and is listed separately."""

import datetime
import html
import json
import os
import statistics
import time

from . import history_db
from .devices import data_dir
from .report import REPORT_CSS

WATCH_SECONDS = 30
MISSES_TO_OPEN = 2          # two failed checks in a row (about a minute) before calling it an outage
KEEP_DAYS = 90
LATENCY_KEY, ROUTER_KEY = "Internet (connection watch)", "Router (connection watch)"


def outages_file():
    return os.path.join(data_dir(), "outages.json")


def _fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"


class OutageLog:
    """Turns watch samples into outages: [{"start", "end", "kind": "internet"|"home"}] (times are epoch seconds)."""

    def __init__(self, path=None):
        self.path = path or outages_file()
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        self.outages = d.get("outages", [])
        self.ongoing = d.get("ongoing")   # {"start", "kind"} once confirmed
        self.misses = {"internet": 0, "home": 0}
        self.first_miss = {}

    def save(self):
        cutoff = time.time() - KEEP_DAYS * 86400
        self.outages = [o for o in self.outages if o["end"] >= cutoff]
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"outages": self.outages, "ongoing": self.ongoing}, f, indent=1)
        os.replace(tmp, self.path)

    def sample(self, router_ok, internet_ok, now=None):
        """Feed one check. Returns ("started", outage) / ("ended", outage) / None."""
        now = now or time.time()
        kind = None if internet_ok else ("internet" if router_ok else "home")
        event = None
        if self.ongoing and self.ongoing["kind"] != kind:  # the outage is over (or changed kind)
            done = {**self.ongoing, "end": now}
            self.outages.append(done)
            self.ongoing = None
            event = ("ended", done)
        for k in self.misses:
            if k == kind:
                self.misses[k] += 1
                self.first_miss.setdefault(k, now)
            else:
                self.misses[k] = 0
                self.first_miss.pop(k, None)
        if kind and not self.ongoing and self.misses[kind] >= MISSES_TO_OPEN:
            self.ongoing = {"start": self.first_miss[kind], "kind": kind}
            event = event or ("started", self.ongoing)
        if event:
            self.save()
        return event

    def resume_check(self, now=None):
        """At startup: an outage left open by a closed NetScan can't be timed, so close it at its last known point."""
        if self.ongoing:
            self.outages.append({**self.ongoing, "end": self.ongoing["start"], "unknown_end": True})
            self.ongoing = None
            self.save()

    def between(self, since, until=None):
        until = until or time.time()
        items = [o for o in self.outages if o["end"] >= since and o["start"] <= until]
        if self.ongoing and self.ongoing["start"] <= until:
            items.append({**self.ongoing, "end": until, "ongoing": True})
        return sorted(items, key=lambda o: o["start"])


def summarize(outages, watched_minutes, since, until):
    """Counts, downtime and uptime % (internet outages only) for a period."""
    internet = [o for o in outages if o["kind"] == "internet"]
    clip = lambda o: max(0.0, min(o["end"], until) - max(o["start"], since))
    down = sum(clip(o) for o in internet)
    watched = watched_minutes * 60
    return {"count": len(internet), "down_seconds": down, "longest": max((clip(o) for o in internet), default=0),
            "home_count": sum(1 for o in outages if o["kind"] == "home"),
            "watched_seconds": watched, "uptime": (100 * (1 - min(down, watched) / watched)) if watched else None}


def report_data(log, since, until=None, plan=None):
    """Everything the ISP report shows, from the outage log and History."""
    until = until or time.time()
    # Minute averages are stamped at the middle of their minute, so the latest can be up to 30 s ahead.
    lat = history_db.rows("latency", since, until + 60, LATENCY_KEY)
    loss = history_db.rows("loss", since, until + 60, LATENCY_KEY)
    outages = log.between(since, until)
    days = {}
    for ts, _k, v in lat:
        days.setdefault(datetime.date.fromtimestamp(ts), []).append(v)
    loss_days = {}
    for ts, _k, v in loss:
        loss_days.setdefault(datetime.date.fromtimestamp(ts), []).append(v)
    daily = []
    for day in sorted(set(days) | set(loss_days)):
        v = sorted(days.get(day, []))
        lo = loss_days.get(day, [])
        daily.append({"day": day.isoformat(), "median": statistics.median(v) if v else None,
                      "p95": v[min(len(v) - 1, int(len(v) * 0.95))] if v else None,
                      "loss": statistics.mean(lo) if lo else None, "minutes": len(lo)})
    downs = history_db.rows("down", since, until)
    ups = {round(ts): v for ts, _k, v in history_db.rows("up", since, until)}
    speeds = [{"when": ts, "down": v, "up": ups.get(round(ts))} for ts, _k, v in downs]
    return {"since": since, "until": until, "outages": outages, "summary": summarize(outages, len(loss), since, until),
            "daily": daily, "speeds": speeds, "plan": plan}


def build_isp_report(d, where=""):
    """A self-contained HTML report of outages, latency and speed: evidence to send to an internet provider."""
    e = html.escape
    fmt_t = lambda ts: datetime.datetime.fromtimestamp(ts).strftime("%a %d %b %H:%M")
    s, plan = d["summary"], d.get("plan") or {}
    speeds = d["speeds"]
    downs = [x["down"] for x in speeds]
    below = [x for x in speeds if plan.get("down") and x["down"] < 0.5 * plan["down"]]
    tiles = [
        (f"{s['uptime']:.2f}%" if s["uptime"] is not None else "—", "internet uptime while watched",
         s["uptime"] is not None and s["uptime"] < 99.5),
        (str(s["count"]), "internet outages", s["count"] > 0),
        (_fmt_duration(s["down_seconds"]), "total downtime", s["down_seconds"] > 0),
        (_fmt_duration(s["longest"]), "longest outage", s["longest"] > 600),
        (f"{statistics.median(downs):.0f} Mbit/s" if downs else "—", "median download"
         + (f" (plan {plan['down']})" if plan.get("down") else ""), bool(below)),
        (_fmt_duration(s["watched_seconds"]), "time watched", False),
    ]
    tile_html = "".join(f'<div class="tile{" warn" if warn else ""}"><b>{e(v)}</b><span>{e(label)}</span></div>'
                        for v, label, warn in tiles)
    ms = lambda v: "" if v is None else f"{v:.0f} ms"

    def lasted(o):
        if o.get("ongoing"):
            return "still down"
        if o.get("unknown_end"):
            return "unknown (NetScan was closed)"
        return _fmt_duration(o["end"] - o["start"])

    def outage_row(o):
        internet = o["kind"] == "internet"
        what = "Internet down (router fine)" if internet else "Home network / this computer offline"
        return (f"<tr><td class='mono'>{e(fmt_t(o['start']))}</td><td>{e(lasted(o))}</td>"
                f"<td class='{'warn' if internet else 'muted'}'>{what}</td></tr>")

    def day_row(x):
        loss = "" if x["loss"] is None else f"{x['loss']:.1f}%"
        watched = f"{x['minutes'] // 60} h {x['minutes'] % 60} min"
        return (f"<tr><td class='mono'>{e(x['day'])}</td><td>{ms(x['median'])}</td><td>{ms(x['p95'])}</td>"
                f"<td class='{'warn' if (x['loss'] or 0) >= 1 else ''}'>{loss}</td><td>{watched}</td></tr>")

    def speed_row(x):
        pct = f" ({100 * x['down'] / plan['down']:.0f}% of plan)" if plan.get("down") else ""
        up = "" if x["up"] is None else f"{x['up']:.0f}"
        return (f"<tr><td class='mono'>{e(fmt_t(x['when']))}</td>"
                f"<td class='{'warn' if x in below else ''}'>{x['down']:.0f}{pct}</td><td>{up}</td></tr>")

    rows = "".join(outage_row(o) for o in d["outages"])
    daily = "".join(day_row(x) for x in d["daily"])
    speed_rows = "".join(speed_row(x) for x in speeds)
    period = f"{fmt_t(d['since'])} – {fmt_t(d['until'])}"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connection report</title><style>{REPORT_CSS}</style></head><body><main>
<h1>Internet connection report</h1>
<p class="sub">{e(period)}{f" · measured from {e(where)}" if where else ""} · NetScan</p>
<div class="tiles">{tile_html}</div>
<h2>Outages</h2>
{('<div class="card"><table><tr><th>Started</th><th>Lasted</th><th>What</th></tr>' + rows + '</table></div>') if rows
 else '<p class="good">No outages recorded in this period.</p>'}
<h2>Latency and packet loss per day</h2>
{('<div class="card"><table><tr><th>Day</th><th>Typical latency</th><th>Worst 5%</th><th>Packet loss</th><th>Watched</th></tr>'
  + daily + '</table></div>') if daily else '<p class="muted">No measurements in this period.</p>'}
<h2>Speed tests</h2>
{('<div class="card"><table><tr><th>When</th><th>Download (Mbit/s)</th><th>Upload (Mbit/s)</th></tr>' + speed_rows
  + '</table></div>') if speed_rows else '<p class="muted">No speed tests in this period.</p>'}
{f'<p class="warn">{len(below)} of {len(speeds)} speed tests were under half of the {plan["down"]} Mbit/s plan.</p>' if below else ''}
<footer>How this was measured: NetScan pinged the home router and two public servers (Cloudflare 1.1.1.1 and Google
8.8.8.8) every {WATCH_SECONDS} seconds while it was running. An internet outage means the router answered but neither
public server did for at least a minute. Times when the router itself didn't answer (home network or this computer
offline) are listed but not counted against the provider. Uptime covers only the time NetScan was watching.</footer>
</main></body></html>
"""
