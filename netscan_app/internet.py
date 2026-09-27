"""Internet checks: public IP, DNS servers, latency, speed test (Cloudflare / LibreSpeed) and bufferbloat."""

import concurrent.futures
import datetime
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .system import IS_MAC, IS_WIN, as_list, ping_once, powershell_json, run_text


def latency_stats(samples):
    """{last, avg, min, max, jitter, loss, count} over (time, ms-or-None) samples."""
    values = [ms for _t, ms in samples if ms is not None]
    lost = sum(1 for _t, ms in samples if ms is None)
    jitter = (sum(abs(a - b) for a, b in zip(values, values[1:])) / (len(values) - 1)) if len(values) > 1 else None
    return {"last": samples[-1][1] if samples else None,
            "avg": sum(values) / len(values) if values else None,
            "min": min(values) if values else None, "max": max(values) if values else None,
            "jitter": jitter, "loss": 100 * lost / len(samples) if samples else None, "count": len(samples)}


# ---- internet check ------------------------------------------------------------
# Only runs when you press a button on the Internet tab; talks to Cloudflare (1.1.1.1).
SPEED_DOWN_BYTES, SPEED_UP_BYTES = 125_000_000, 40_000_000  # caps; usually less is used


def cloudflare_trace():
    """What Cloudflare sees: {"ip", "loc" (country), "colo" (data centre airport code), ...}."""
    req = urllib.request.Request("https://1.1.1.1/cdn-cgi/trace", headers={"User-Agent": "NetScan"})
    body = urllib.request.urlopen(req, timeout=6).read(4096).decode()
    return dict(line.split("=", 1) for line in body.splitlines() if "=" in line)


def dns_servers():
    """The DNS servers this computer asks."""
    if IS_WIN:
        rows = powershell_json("Get-DnsClientServerAddress -AddressFamily IPv4 | "
                               "Select-Object -ExpandProperty ServerAddresses | ConvertTo-Json -Compress")
        found = as_list(rows)
    elif IS_MAC:
        found = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", run_text("/usr/sbin/scutil", "--dns"))
    else:
        found = re.findall(r"(?:\s|^)(\d+\.\d+\.\d+\.\d+|[0-9a-f:]+:[0-9a-f:]+)",
                           run_text("resolvectl", "dns").split(":", 1)[-1]) if shutil.which("resolvectl") else []
        if not found:
            try:
                with open("/etc/resolv.conf") as f:
                    found = re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)
            except OSError:
                found = []
    return list(dict.fromkeys(str(x) for x in found if x))


def dns_lookup_ms(tries=3):
    """Median time for lookups the DNS server can't have cached (random names that don't exist)."""
    times = []
    for _ in range(tries):
        name = f"netscan-{os.urandom(6).hex()}.example.com"
        t = time.perf_counter()
        try:
            socket.getaddrinfo(name, None)
        except OSError:
            pass  # "no such name" is the expected answer; the round trip is what we time
        times.append((time.perf_counter() - t) * 1000)
    return sorted(times)[len(times) // 2]


def ping_summary(ip, count=5):
    """(median ms or None, loss %) over a few pings."""
    results = [ping_once(ip) for _ in range(count)]
    ok = sorted(r for r in results if r is not None)
    return (ok[len(ok) // 2] if ok else None), 100 * (count - len(ok)) / count


def internet_check(gateway):
    out = {"when": datetime.datetime.now().strftime("%H:%M:%S")}
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {"trace": ex.submit(cloudflare_trace), "dns": ex.submit(dns_servers),
                "dns_ms": ex.submit(dns_lookup_ms), "cf": ex.submit(ping_summary, "1.1.1.1"),
                "google": ex.submit(ping_summary, "8.8.8.8")}
        if gateway:
            futs["router"] = ex.submit(ping_summary, gateway)
        for key, fut in futs.items():
            try:
                out[key] = fut.result()
            except Exception as e:  # noqa: BLE001 - show what failed, keep the rest
                out[key] = None
                out.setdefault("errors", []).append(f"{key}: {e}")
    return out


def _speed_phase(one_request, streams=4, seconds=6.0, cap=None, warmup=0.5):
    """Run one_request(add_bytes) on several connections until time or data runs out; Mbit/s.

    Bytes from the first `warmup` seconds are ignored: a connection starts slow and ramps up.
    """
    lock, state = threading.Lock(), {"total": 0, "counted": 0, "last": None, "last_any": None}
    start = time.perf_counter()
    deadline = start + seconds

    def add(n):
        with lock:
            now = time.perf_counter()
            state["total"] += n
            state["last_any"] = now
            if now - start >= warmup:
                state["counted"] += n
                state["last"] = now  # time is measured to the last byte, not to when connections close
            return now < deadline and (cap is None or state["total"] < cap)

    def stream():
        while time.perf_counter() < deadline and (cap is None or state["total"] < cap):
            try:
                if not one_request(add):
                    break
            except (OSError, http.client.HTTPException):
                if state["total"]:
                    break  # a stalled/reset connection mid-test just ends this stream
                raise      # nothing got through at all (e.g. rate limited): a real failure

    with ThreadPoolExecutor(max_workers=streams) as ex:
        for f in [ex.submit(stream) for _ in range(streams)]:
            f.result()
    if state["counted"] >= state["total"] * 0.25 and state["last"]:
        elapsed = state["last"] - start - warmup
        return state["counted"] * 8 / max(elapsed, 0.05) / 1e6, state["total"]
    # Fast links can finish most of the data inside the warm-up; then measure the whole run.
    elapsed = (state["last_any"] or time.perf_counter()) - start
    return state["total"] * 8 / max(elapsed, 0.05) / 1e6, state["total"]


SPEED_BASE = "https://speed.cloudflare.com"
# Bufferbloat grades by how much latency rises while the connection is busy (ms), as speed-test sites use.
BLOAT_GRADES = [(5, "A+"), (30, "A"), (60, "B"), (200, "C"), (400, "D")]


def bloat_grade(added_ms):
    return next((g for limit, g in BLOAT_GRADES if added_ms < limit), "F")


def _median(values):
    values = sorted(v for v in values if v is not None)
    return values[len(values) // 2] if values else None


def _latency_while(fn, target="1.1.1.1"):
    """Run fn() while pinging target every ~0.25 s; returns (fn's result, [ms…])."""
    samples, stop = [], threading.Event()

    def loop():
        while not stop.is_set():
            samples.append(ping_once(target))
            stop.wait(0.25)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        return fn(), samples
    finally:
        stop.set()
        t.join(2)


LIBRESPEED_LIST = "https://librespeed.org/backend-servers/servers.php"
SPEED_PROVIDERS = [("auto", "Automatic"), ("cloudflare", "Cloudflare"), ("librespeed", "LibreSpeed (nearest)")]
_LIBRESPEED = {"list": None, "best": None}


def librespeed_nearest():
    """The public LibreSpeed server that answers fastest from here: {"name", "down", "up"} URLs.

    The choice is remembered for the session and only re-checked, not searched for again.
    """
    best = _LIBRESPEED["best"]
    if best:
        try:  # by IP: this network's DNS can be slow, and the name was already resolved
            socket.create_connection(best["addr"], timeout=1.5).close()
            return best
        except OSError:
            _LIBRESPEED["best"] = None  # gone: search again
    if _LIBRESPEED["list"] is None:
        req = urllib.request.Request(LIBRESPEED_LIST, headers={"User-Agent": "NetScan"})
        _LIBRESPEED["list"] = json.loads(urllib.request.urlopen(req, timeout=8).read(500_000))
    servers = [s for s in _LIBRESPEED["list"] if s.get("server", "").startswith("https://")]

    def rtt(s):
        """Best of 3 TCP connects (≈ one round trip), with the name resolved once."""
        u = urllib.parse.urlparse(s["server"])
        try:
            addr = socket.getaddrinfo(u.hostname, u.port or 443, type=socket.SOCK_STREAM)[0][4]
        except OSError:
            return None
        best = None
        for _ in range(3):
            t = time.perf_counter()
            try:
                socket.create_connection(addr[:2], timeout=1.0).close()
            except OSError:
                return None
            ms = (time.perf_counter() - t) * 1000
            best = ms if best is None else min(best, ms)
        return best, addr[:2]

    # Some servers' names take ~10 s to fail to resolve on some networks; don't wait for those.
    ex = ThreadPoolExecutor(max_workers=len(servers) or 1)
    futures = {ex.submit(rtt, srv): srv for srv in servers}
    done, _pending = concurrent.futures.wait(futures, timeout=6.0)  # returns early once all have answered
    ex.shutdown(wait=False, cancel_futures=True)
    timed = [(f.result()[0], f.result()[1], futures[f]) for f in done if f.result() is not None]
    if not timed:
        raise OSError("no LibreSpeed server answered")
    ms, addr, s = min(timed, key=lambda x: x[0])
    base = s["server"].rstrip("/") + "/"
    _LIBRESPEED["best"] = {"name": f"{s['name']} (LibreSpeed)", "ms": ms, "addr": addr,
                           "down": urllib.parse.urljoin(base, s["dlURL"]) + "?ckSize=25",  # 25 MB per request
                           "up": urllib.parse.urljoin(base, s["ulURL"])}
    return _LIBRESPEED["best"]


def speed_test(base=SPEED_BASE, download_phase=True, provider="auto"):
    """Download then upload, 4 / 2 connections for ~6 s each; Mbit/s plus a bufferbloat grade.

    provider: 'cloudflare', 'librespeed' (nearest public server), or 'auto' = Cloudflare, falling back to
    LibreSpeed if Cloudflare refuses (it rate-limits connections that test a lot) or can't be reached.
    """
    if provider == "librespeed":
        return _speed_run(librespeed_nearest(), download_phase)
    cloudflare = {"name": "Cloudflare", "down": f"{base}/__down?bytes=25000000", "up": f"{base}/__up"}
    if provider == "cloudflare":
        return _speed_run(cloudflare, download_phase)
    try:
        return _speed_run(cloudflare, download_phase)
    except (OSError, http.client.HTTPException) as e:
        why = "rate-limited" if isinstance(e, urllib.error.HTTPError) and e.code == 429 else "unreachable"
        result = _speed_run(librespeed_nearest(), download_phase)
        result["note"] = f"Cloudflare was {why}, so this used the nearest LibreSpeed server."
        return result


def _speed_run(server, download_phase=True):
    ctx = ssl.create_default_context()
    agent = {"User-Agent": "NetScan"}  # Cloudflare's speed test refuses Python's default user agent

    def download(add):
        req = urllib.request.Request(server["down"], headers=agent)
        with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
            while chunk := r.read(65536):
                if not add(len(chunk)):
                    return False
        return True

    block = os.urandom(1_000_000)  # random, so nothing along the way can compress it
    size = 8_000_000
    phase = {"deadline": 0.0}

    class Stop(Exception):
        """Raised from inside an upload to abort it once the phase is over."""

    class Body:
        """Upload body; stops mid-way when the phase's time is up."""

        def __init__(self):
            self.sent = 0

        def read(self, n=65536):
            if time.perf_counter() > phase["deadline"]:
                raise Stop
            if self.sent >= size:
                return b""
            start = self.sent % len(block)
            piece = block[start:start + min(n, size - self.sent, len(block) - start)]
            self.sent += len(piece)
            return piece

    def upload(add):
        req = urllib.request.Request(server["up"], data=Body(), method="POST",
                                     headers={"Content-Type": "application/octet-stream",
                                              "Content-Length": str(size), **agent})
        try:
            with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
                r.read()
        except Stop:
            return False
        # Counted only once the server says it has everything: bytes handed to the network sit in
        # local buffers for a while, so counting them as they're written overstates upload speed.
        return add(size)

    idle = _median([ping_once("1.1.1.1") for _ in range(5)])
    (down, down_bytes), down_pings = (_latency_while(lambda: _speed_phase(download, cap=SPEED_DOWN_BYTES))
                                      if download_phase else ((0.0, 0), []))
    phase["deadline"] = time.perf_counter() + 6
    (up, up_bytes), up_pings = _latency_while(lambda: _speed_phase(upload, streams=2, cap=SPEED_UP_BYTES,
                                                                   warmup=0))
    loaded = {"down": _median(down_pings), "up": _median(up_pings)}
    worst = max((v for v in loaded.values() if v is not None), default=None)
    added = max(0.0, worst - idle) if worst is not None and idle is not None else None
    return {"server": server["name"], "down": down, "up": up, "used_mb": (down_bytes + up_bytes) / 1e6,
            "idle_ms": idle, "loaded_ms": loaded, "added_ms": added,
            "grade": bloat_grade(added) if added is not None else None,
            "when": datetime.datetime.now().strftime("%H:%M:%S")}
