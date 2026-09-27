"""The self-contained HTML network report."""

import html

from .devices import port_risk
from .discovery import cert_note
from .scanning import port_label


REPORT_CSS = """
:root { color-scheme: light; --bg:#f3f4f8; --card:#ffffff; --line:#e1e4ec; --text:#1a1d26; --muted:#667086;
  --accent:#3b6ef0; --warn:#b45309; --warn-bg:#fef3c7; --good:#0c9467; }
@media (prefers-color-scheme: dark) { :root { color-scheme: dark; --bg:#0e1016; --card:#151823; --line:#262b3b;
  --text:#e5e7ee; --muted:#8a90a6; --accent:#7aa2ff; --warn:#fbbf24; --warn-bg:#3a2e0b; --good:#34d399; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1200px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 26px; margin: 0; } h2 { font-size: 13px; letter-spacing: .06em; text-transform: uppercase;
  color: var(--muted); margin: 32px 0 10px; }
.sub { color: var(--muted); margin: 4px 0 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 24px; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; }
.tile b { display: block; font-size: 26px; } .tile span { color: var(--muted); font-size: 13px; }
.tile.warn b { color: var(--warn); }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 12px; color: var(--muted); font-weight: 600; padding: 10px 12px;
  border-bottom: 1px solid var(--line); white-space: nowrap; }
td { padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: none; }
.mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 13px; white-space: nowrap; }
.muted { color: var(--muted); } .warn { color: var(--warn); } .good { color: var(--good); }
ul.attention { list-style: none; margin: 0; padding: 0; }
ul.attention li { background: var(--warn-bg); border-radius: 10px; padding: 10px 14px; margin-bottom: 8px; }
.tag { display: inline-block; border: 1px solid var(--line); border-radius: 10px; padding: 0 8px; font-size: 12px;
  color: var(--muted); margin-left: 6px; }
footer { color: var(--muted); font-size: 12px; margin-top: 40px; }
@media print { body { background: #fff; } .card, .tile { break-inside: avoid; } }
"""


def build_report(data):
    """Self-contained HTML network report from plain data (see MainWindow.report_data)."""
    e = lambda x: html.escape(str(x or ""))
    hosts = data["hosts"]
    attention = []
    for h in hosts:
        who = e(h["label"])
        for m in h["upnp"]:
            attention.append(f"⚠ <b>{who}</b> opened internet port {m['external_port']}/{e(m['protocol'])} "
                             f"to its port {e(m['internal_port'])} via UPnP"
                             + (f" ({e(m['description'])})" if m["description"] else "") + ".")
        for p in h["risky"]:
            attention.append(f"⚠ <b>{who}</b> has {e(port_label(p))} open: {e(port_risk(p))}.")
        for p in h["ports"] or []:
            if p.get("cert") and cert_note(p["cert"])[1]:
                attention.append(f"⚠ <b>{who}</b> port {p['port']}: {e(cert_note(p['cert'])[1])}.")
        if h["untrusted"]:
            attention.append(f"<b>{who}</b> isn't marked as trusted.")
        if h["new"]:
            attention.append(f"<b>{who}</b> was seen for the first time in this scan.")
    for severity, text in data.get("spoof", []):
        attention.insert(0, ("⚠ " if severity == "high" else "") + e(text))
    tiles = [(len(hosts), "devices", False),
             (sum(len(h["ports"] or []) for h in hosts if not h["this"]), "open ports on other devices", False),
             (sum(len(h["risky"]) for h in hosts), "risky ports", True),
             (sum(len(h["upnp"]) for h in hosts), "ports opened to the internet", True),
             (sum(1 for h in hosts if h["new"]), "new devices", True),
             (sum(1 for h in hosts if ":" in h["ip"]), "found over IPv6 only", False)]
    tile_html = "".join(f'<div class="tile{" warn" if warn and n else ""}"><b>{n}</b><span>{label}</span></div>'
                        for n, label, warn in tiles)

    def ports_cell(h):
        if h["ports"] is None:
            return '<span class="muted">not scanned</span>'
        if not h["ports"]:
            return '<span class="muted">none open</span>'
        return ", ".join(f'<span class="warn">⚠ {e(port_label(p))}</span>' if port_risk(p) else
                         e(port_label(p)) + (f' <span class="muted">“{e(p["title"])}”</span>' if p.get("title") else "")
                         for p in h["ports"])

    rows = "".join(
        f"<tr><td class='mono'>{e(h['ip'])}</td><td><b>{e(h['nickname'])}</b>"
        f"{'<span class=tag>this computer</span>' if h['this'] else ''}"
        f"{'<span class=tag>new</span>' if h['new'] else ''}</td>"
        f"<td>{e(h['hostname'])}</td><td>{e(h['type'])}</td><td class='mono'>{e(h['mac'])}</td>"
        f"<td>{e(h['vendor'])}</td><td>{e(h['identified'])}</td><td>{e(h['os'])}</td><td>{ports_cell(h)}</td></tr>"
        for h in hosts)
    me = next((h for h in hosts if h["this"]), None)
    mine = ""
    if me and me["all_ports"]:
        mine = "<h2>This computer's open ports</h2><div class='card'><table><tr><th>Port</th><th>Program</th>" \
               "<th>Reachable from</th></tr>" + "".join(
                   f"<tr><td class='mono'>{p['port']}/{e(p['proto'])}</td><td>{e(p.get('program') or p['service'])}</td>"
                   f"<td class='{'muted' if p.get('local_only') else ''}'>"
                   f"{'this computer only' if p.get('local_only') else 'your network'}</td></tr>"
                   for p in me["all_ports"] if not p.get("temporary")) + "</table></div>"
    notes = "".join(f"<tr><td><b>{e(h['label'])}</b></td><td>{e(h['notes'])}</td></tr>" for h in hosts if h["notes"])
    upnp = data["upnp"]
    upnp_line = ("Router UPnP: not checked." if upnp is None else
                 f"Router UPnP: {len([m for m in upnp['mappings'] if m['enabled']])} port forward(s)"
                 + (f"; public IP {e(upnp['public_ip'])}." if upnp.get("public_ip") else "."))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network report</title><style>{REPORT_CSS}</style></head><body><main>
<h1>Network report: {e(data['network'])}</h1>
<p class="sub">Scanned {e(data['when'])} from {e(data['scanner'])} · NetScan · {e(upnp_line)}</p>
<div class="tiles">{tile_html}</div>
<h2>Needs attention</h2>
{('<ul class="attention">' + "".join(f"<li>{a}</li>" for a in attention) + "</ul>") if attention
 else '<p class="good">Nothing flagged: no risky ports, no UPnP internet openings, no new or untrusted devices.</p>'}
<h2>Devices</h2>
<div class="card"><table><tr><th>IP address</th><th>Name</th><th>Hostname</th><th>Type</th><th>MAC</th><th>Vendor</th>
<th>Identified as</th><th>OS</th><th>Open ports</th></tr>{rows}</table></div>
{mine}
{('<h2>Notes</h2><div class="card"><table>' + notes + '</table></div>') if notes else ''}
<footer>Generated by NetScan. Risky-port notes are general guidance: an open port is worth a look, not proof of a problem.</footer>
</main></body></html>
"""
