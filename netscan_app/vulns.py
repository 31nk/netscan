"""Known-vulnerability lookup (opt-in): software versions from nmap's version detection, checked against
NIST's National Vulnerability Database. Only product names and versions are sent, never addresses."""

import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request

from .devices import data_dir

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SPACING = 6.5  # the public API allows 5 requests per 30 s without a key
CACHE_DAYS = 7
_LOCK = threading.Lock()
_LAST = {"t": 0.0}


def cpe23(cpe):
    """nmap's 'cpe:/a:openbsd:openssh:10.0p2' -> 'cpe:2.3:a:openbsd:openssh:10.0:*:...' or None.

    Only applications with a version can be looked up. The version is cut to its numeric part
    (NVD keeps OpenSSH's 'p2' etc. separately), which can also match advisories fixed in a later
    patch release of the same version: results are 'may affect', not 'affects'.
    """
    if not cpe.startswith("cpe:/a:"):
        return None
    parts = cpe[len("cpe:/"):].split(":")
    if len(parts) < 4:
        return None
    m = re.match(r"\d+(?:\.\d+)*", parts[3])
    if not m:
        return None
    vendor, product = (urllib.parse.unquote(x) for x in parts[1:3])
    return f"cpe:2.3:a:{vendor}:{product}:{m.group(0)}:*:*:*:*:*:*:*"


def _cache_path():
    return os.path.join(data_dir(), "nvd_cache.json")


def _load_cache():
    try:
        with open(_cache_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _severity(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]
            cvss = data.get("cvssData", {})
            return cvss.get("baseScore"), cvss.get("baseSeverity") or data.get("baseSeverity", "")
    return None, ""


def _nvd_get(url):
    """One rate-limited request to the NVD API (call with _LOCK held)."""
    wait = NVD_SPACING - (time.time() - _LAST["t"])
    if wait > 0:
        time.sleep(wait)
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "NetScan"}), timeout=30) as r:
            return json.loads(r.read(20_000_000))
    finally:
        _LAST["t"] = time.time()


def nvd_knows(cpe_name):
    """Is this vendor:product in NVD's dictionary at all? (If not, zero results mean "can't check".)"""
    vendor_product = ":".join(cpe_name.split(":")[:5])
    d = _nvd_get(f"https://services.nvd.nist.gov/rest/json/cpes/2.0?"
                 f"{urllib.parse.urlencode({'cpeMatchString': vendor_product, 'resultsPerPage': 1})}")
    return bool(d.get("totalResults"))


def nvd_lookup(cpe_name):
    """Known vulnerabilities recorded for this CPE: [{id, score, severity, summary, published}], highest first;
    None if NVD doesn't know the product at all."""
    with _LOCK:
        cache = _load_cache()
        hit = cache.get(cpe_name)
        if hit and time.time() - hit[0] < CACHE_DAYS * 86400:
            return hit[1]
        d = _nvd_get(f"{NVD_API}?{urllib.parse.urlencode({'virtualMatchString': cpe_name, 'resultsPerPage': 200})}")
        vulns = []
        for item in d.get("vulnerabilities", []):
            c = item.get("cve", {})
            score, severity = _severity(c.get("metrics", {}))
            summary = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
            vulns.append({"id": c.get("id", ""), "score": score, "severity": (severity or "").upper(),
                          "summary": summary, "published": (c.get("published") or "")[:10]})
        vulns.sort(key=lambda v: (-(v["score"] or 0), v["id"]))
        if not vulns and not nvd_knows(cpe_name):
            vulns = None  # NVD doesn't know this product name: can't check, not "no issues"
        cache[cpe_name] = [time.time(), vulns]
        try:
            with open(_cache_path(), "w", encoding="utf-8") as f:
                json.dump(cache, f)
        except OSError:
            pass
        return vulns


def host_vulnerabilities(ports):
    """{service label: {"cpe", "product", "vulns"}} for a host's ports that carry versioned CPEs."""
    seen, out = {}, {}
    for p in ports or []:
        for cpe in p.get("cpe") or []:
            name = cpe23(cpe)
            if not name or name in seen:
                continue
            seen[name] = True
            product = f"{p.get('version') or cpe.split(':')[3]}"
            out[f"{p['port']}/{p.get('service') or p['proto']}"] = {"cpe": name, "product": product,
                                                                    "vulns": nvd_lookup(name)}
    return out


def versioned_cpes(ports):
    return [c for p in ports or [] for c in p.get("cpe") or [] if cpe23(c)]
