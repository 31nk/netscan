"""The site audit: a self-contained HTML document of a client network (for the client, or to paste into
documentation), with your company's name and logo."""

import base64
import html
import mimetypes

from .devices import port_risk
from .report import REPORT_CSS
from .scanning import port_label

AUDIT_CSS = REPORT_CSS + """
header.brand { display: flex; align-items: center; gap: 16px; margin-bottom: 18px; }
header.brand img { max-height: 56px; max-width: 220px; }
header.brand .who { color: var(--muted); font-size: 13px; }
.grade { font-size: 44px; font-weight: 700; }
.finding { padding: 8px 0; border-bottom: 1px solid var(--line); } .finding:last-child { border-bottom: none; }
.finding b { display: block; } .finding span { color: var(--muted); }
.pad { padding: 4px 16px; }
.bad { color: #c2410c; } @media (prefers-color-scheme: dark) { .bad { color: #fb923c; } }
"""

MARK = {"critical": "✗", "high": "✗", "bad": "✗", "medium": "⚠", "warn": "⚠", "low": "·", "info": "·", "good": "✓"}
CLASS = {"critical": "bad", "high": "bad", "bad": "bad", "medium": "warn", "warn": "warn", "good": "good"}


def logo_data_uri(path):
    """The logo file as a data: URI, so the report stays a single file. '' if it can't be read."""
    if not path:
        return ""
    try:
        with open(path, "rb") as f:
            raw = f.read(2_000_000)
    except OSError:
        return ""
    kind = mimetypes.guess_type(path)[0] or "image/png"
    return f"data:{kind};base64,{base64.b64encode(raw).decode()}"


def _findings(items):
    e = html.escape
    return "".join(f'<div class="finding"><b class="{CLASS.get(lvl, "muted")}">{MARK.get(lvl, "·")} {e(title)}</b>'
                   + (f"<span>{e(detail)}</span>" if detail else "") + "</div>" for lvl, title, detail in items)


def _table(headers, rows):
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="card"><table>{f"<tr>{head}</tr>" if any(headers) else ""}{body}</table></div>'


def build_audit(d):
    """d: {client, company, technician, logo, when, network (report_data()), security, networks, dns, public,
    wifi, speed, firewall, services, notes}. Missing sections are left out."""
    e = lambda x: html.escape(str(x if x is not None else ""))
    net = d["network"]
    hosts = net["hosts"]
    sec = d.get("security")
    speed = d.get("speed")
    tiles = [(str(len(hosts)), "devices")]
    if sec:
        tiles.append((f"{sec['grade']} ({sec['score']})" if sec["complete"] else "—", "security grade"))
    tiles.append((str(sum(len(h["risky"]) for h in hosts)), "risky services"))
    tiles.append((str(len([m for m in (net.get("upnp") or {}).get("mappings", []) if m.get("enabled", True)])),
                  "ports opened to the internet"))
    if speed:
        tiles.append((f"{speed['down']:.0f} / {speed['up']:.0f}", "Mbit/s down / up"))
    tile_html = "".join(f'<div class="tile"><b>{e(v)}</b><span>{e(k)}</span></div>' for v, k in tiles)

    info = [("Networks", ", ".join(f"{n['network']} via {n['gateway'] or '?'} ({n['iface']})"
                                   for n in d.get("networks", []))),
            ("Router", d.get("router", "")),
            ("DNS servers", ", ".join(d.get("dns") or [])),
            ("DHCP servers", ", ".join(d.get("dhcp") or []) or "not checked"),
            ("Public address", d.get("public", "")),
            ("Internet speed", f"{speed['down']:.0f} Mbit/s down, {speed['up']:.0f} up"
             + (f", bufferbloat {speed['grade']}" if speed.get("grade") else "") if speed else "not tested")]
    wifi = d.get("wifi") or []
    sections = ["<h2>Network</h2>" + _table([], [(f"<b>{e(k)}</b>", e(v)) for k, v in info if v])]
    if sec:
        sections.append("<h2>Security</h2>" + f'<div class="card pad">{_findings(sec["findings"])}</div>')
    if d.get("firewall"):
        rows = [(e(cat), f"<span class='mono'>{port}</span>", e(what),
                 f"<span class='{'good' if st == 'open' else 'warn'}'>{e(st)}</span>")
                for cat, port, what, st in d["firewall"]["tcp"]]
        sections.append("<h2>Outbound firewall</h2>" + f'<div class="card pad">{_findings(d["firewall_findings"])}</div>'
                        + "<p></p>" + _table(["Category", "Port", "Used by", "Outbound"], rows))
    if wifi:
        rows = [(e(n["ssid"]) + (" <span class='tag'>this computer</span>" if n.get("active") else ""), e(n["band"]),
                 e(n["channel"]), e(f"{n['signal']}%" if n.get("signal") is not None else ""), e(n.get("security", "")))
                for n in wifi[:30]]
        sections.append("<h2>Wi-Fi networks in range</h2>" + _table(["Network", "Band", "Channel", "Signal", "Security"], rows))

    def ports(h):
        if h["ports"] is None:
            return '<span class="muted">not scanned</span>'
        return ", ".join(f'<span class="warn">⚠ {e(port_label(p))}</span>' if port_risk(p) else e(port_label(p))
                         for p in h["ports"]) or '<span class="muted">none open</span>'

    rows = [(f"<span class='mono'>{e(h['ip'])}</span>", f"<b>{e(h['nickname'] or h['hostname'])}</b>", e(h["type"]),
             f"<span class='mono'>{e(h['mac'])}</span>", e(h["vendor"]), e(h["identified"] or h["os"]), ports(h))
            for h in hosts]
    sections.append("<h2>Devices</h2>" + _table(["IP address", "Name", "Type", "MAC", "Maker", "Identified as",
                                                  "Open ports"], rows))
    if d.get("services"):
        rows = [(f"<span class='mono'>{e(s['ip'])}</span>", e(s["kind"]), e(s["name"]),
                 f"<a href='{e(s['url'])}'>{e(s['url'])}</a>" if s["url"] else "", e(s["detail"]))
                for s in d["services"]]
        sections.append("<h2>Services and web pages</h2>" + _table(["Device", "Service", "Name", "Address", "Details"], rows))
    if d.get("notes"):
        sections.append(f'<h2>Notes</h2><div class="card pad"><p>{e(d["notes"]).replace(chr(10), "<br>")}</p></div>')

    logo = f'<img src="{d["logo"]}" alt="">' if d.get("logo") else ""
    by = " · ".join(x for x in (e(d.get("company")), e(d.get("technician"))) if x)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network audit: {e(d['client'])}</title><style>{AUDIT_CSS}</style></head><body><main>
<header class="brand">{logo}<div><h1>Network audit: {e(d['client'])}</h1>
<div class="who">{e(d['when'])}{' · prepared by ' + by if by else ''}</div></div></header>
<div class="tiles">{tile_html}</div>
{''.join(sections)}
<footer>Findings reflect what could be seen from this network at the time of the visit, without logging in to any
device. Open ports and risky services are worth reviewing, not proof of a problem. Generated with NetScan.</footer>
</main></body></html>
"""
