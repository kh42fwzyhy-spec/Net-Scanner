"""Write a Topology as JSON, CSV, Graphviz DOT and a self-contained HTML report."""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .model import Topology
from .util import norm_hostname, norm_ifname

FORMATS = ("json", "csv", "dot", "html")


def write_reports(topo: Topology, out_dir: Path, formats=FORMATS) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        p = out_dir / "topology.json"
        p.write_text(json.dumps(topo.to_dict(), indent=2), encoding="utf-8")
        written.append(p)
    if "csv" in formats:
        written += _write_csvs(topo, out_dir)
    if "dot" in formats:
        p = out_dir / "topology.dot"
        p.write_text(to_dot(topo), encoding="utf-8")
        written.append(p)
    if "html" in formats:
        p = out_dir / "topology.html"
        p.write_text(to_html(topo), encoding="utf-8")
        written.append(p)
    return written


def _write_csv(path: Path, header: list[str], rows) -> Path:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    return path


def port_summary(device) -> list[dict]:
    """One row per interface: status, VLAN, neighbor and learned MACs."""
    macs = Counter(m.port for m in device.mac_table)
    ips: dict[str, list[str]] = {}
    for m in device.mac_table:
        if m.ip:
            ips.setdefault(m.port, []).append(m.ip)
    neigh: dict[str, dict[str, str]] = {}
    for n in device.neighbors:
        name = n.remote_name or n.remote_chassis_id
        label = f"{name} ({n.remote_port})" if n.remote_port else name
        # LLDP and CDP often report the same neighbor (one with a domain suffix)
        neigh.setdefault(n.local_port, {}).setdefault(norm_hostname(name) + "|" + norm_ifname(n.remote_port), label)
    rows = []
    for i in device.interfaces:
        rows.append({
            "port": i.name, "description": i.alias, "type": i.type,
            "admin": i.admin_status, "oper": i.oper_status, "speed_mbps": i.speed_mbps,
            "vlan": i.vlan, "neighbors": "; ".join(neigh.get(i.name, {}).values()),
            "mac_count": macs.get(i.name, 0), "ips": ", ".join(ips.get(i.name, [])[:5]),
        })
    return rows


def _write_csvs(topo: Topology, out_dir: Path) -> list[Path]:
    return [
        _write_csv(out_dir / "links.csv", ["device_a", "port_a", "device_b", "port_b", "protocols"],
                   ([l.a, l.a_port, l.b, l.b_port, "+".join(l.protocols)] for l in topo.links)),
        _write_csv(out_dir / "neighbors.csv",
                   ["device", "protocol", "local_port", "remote_name", "remote_port", "remote_mgmt_ip",
                    "remote_chassis_id", "remote_platform", "capabilities"],
                   ([d.id, n.protocol, n.local_port, n.remote_name, n.remote_port, n.remote_mgmt_ip,
                     n.remote_chassis_id, n.remote_platform, ",".join(n.capabilities)]
                    for d in topo.devices for n in d.neighbors)),
        _write_csv(out_dir / "mac_table.csv", ["device", "port", "vlan", "mac", "ip", "status"],
                   ([d.id, m.port, m.vlan, m.mac, m.ip, m.status] for d in topo.devices for m in d.mac_table)),
        _write_csv(out_dir / "endpoints.csv", ["mac", "ip", "vlan", "switch", "port", "edge_port", "behind"],
                   ([e.mac, e.ip, e.vlan, e.switch, e.port, "yes" if e.edge else "no", e.neighbor]
                    for e in topo.endpoints)),
        _write_csv(out_dir / "arp.csv", ["device", "ip", "mac", "interface"],
                   ([d.id, a.ip, a.mac, a.interface] for d in topo.devices for a in d.arp)),
        _write_csv(out_dir / "ports.csv",
                   ["device", "port", "description", "type", "admin", "oper", "speed_mbps", "vlan",
                    "neighbors", "mac_count", "ips"],
                   ([d.id, *r.values()] for d in topo.devices for r in port_summary(d))),
    ]


_WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                     *(f"lpt{i}" for i in range(1, 10))}


def safe_name(name: str, fallback: str = "topology") -> str:
    """Turn a topology or switch name into a folder name that is valid on Windows, macOS and Linux."""
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", name.strip())
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .")
    if not cleaned:
        return fallback
    if cleaned.split(".")[0].lower() in _WINDOWS_RESERVED:
        cleaned += "_"
    return cleaned[:100]


def run_folder(base: Path, topology_name: str, when: datetime | None = None) -> Path:
    """``base/<name>/<YYYY-MM-DD_HH-MM-SS>``; a numeric suffix keeps two runs in one second apart."""
    stamp = (when or datetime.now()).strftime("%Y-%m-%d_%H-%M-%S")
    parent = base / safe_name(topology_name)
    path, n = parent / stamp, 2
    while path.exists():
        path, n = parent / f"{stamp}_{n}", n + 1
    return path


def switch_folder_names(topo: Topology) -> list[str]:
    """One folder name per scanned switch (its name), made unique if two switches share one."""
    names: list[str] = []
    for d in topo.devices:
        name = safe_name(d.id, fallback=safe_name(d.host, "switch"))
        if name.lower() in (n.lower() for n in names):
            name = safe_name(f"{name} ({d.host})")
        names.append(name)
    return names


def write_switch_folders(topo: Topology, out_dir: Path) -> list[Path]:
    """Save everything collected from each switch in ``out_dir/<switch name>/``."""
    written: list[Path] = []
    for d, folder in zip(topo.devices, switch_folder_names(topo)):
        sw = out_dir / folder
        sw.mkdir(parents=True, exist_ok=True)
        data = asdict(d)
        data.pop("raw_output", None)
        p = sw / "device.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        written.append(p)
        written += [
            _write_csv(sw / "ports.csv",
                       ["port", "description", "type", "admin", "oper", "speed_mbps", "vlan",
                        "neighbors", "mac_count", "ips"],
                       (r.values() for r in port_summary(d))),
            _write_csv(sw / "interfaces.csv",
                       ["ifindex", "name", "description", "alias", "type", "speed_mbps", "admin", "oper",
                        "mac", "vlan"],
                       ([i.index, i.name, i.description, i.alias, i.type, i.speed_mbps, i.admin_status,
                         i.oper_status, i.mac, i.vlan] for i in d.interfaces)),
            _write_csv(sw / "neighbors.csv",
                       ["protocol", "local_port", "remote_name", "remote_port", "remote_port_description",
                        "remote_mgmt_ip", "remote_chassis_id", "remote_platform", "capabilities"],
                       ([n.protocol, n.local_port, n.remote_name, n.remote_port, n.remote_port_description,
                         n.remote_mgmt_ip, n.remote_chassis_id, n.remote_platform, ",".join(n.capabilities)]
                        for n in d.neighbors)),
            _write_csv(sw / "mac_table.csv", ["port", "vlan", "mac", "ip", "status"],
                       ([m.port, m.vlan, m.mac, m.ip, m.status] for m in d.mac_table)),
            _write_csv(sw / "arp.csv", ["ip", "mac", "interface"],
                       ([a.ip, a.mac, a.interface] for a in d.arp)),
            _write_csv(sw / "vlans.csv", ["vlan", "name"], ([v.id, v.name] for v in d.vlans)),
        ]
        if d.raw_output:  # SSH: keep the switch's own command output too
            cli = sw / "cli"
            cli.mkdir(exist_ok=True)
            for command, text in d.raw_output.items():
                p = cli / f"{safe_name(command.replace(' ', '_'), 'output')}.txt"
                p.write_text(text, encoding="utf-8")
                written.append(p)
    return written


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(topo: Topology) -> str:
    lines = ["graph topology {", "  graph [overlap=false, splines=true];",
             '  node [shape=box, style="rounded,filled", fontname="Helvetica"];']
    for n in topo.nodes:
        color = "#cfe2ff" if n.kind == "scanned" else "#eeeeee"
        label = n.label + (f"\\n{n.mgmt_ip}" if n.mgmt_ip else "")
        lines.append(f'  "{_dot_escape(n.id)}" [label="{_dot_escape(label)}", fillcolor="{color}"];')
    for l in topo.links:
        lines.append(f'  "{_dot_escape(l.a)}" -- "{_dot_escape(l.b)}" '
                     f'[taillabel="{_dot_escape(l.a_port)}", headlabel="{_dot_escape(l.b_port)}", fontsize=9];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_html(topo: Topology) -> str:
    data = topo.to_dict()
    for d, dev in zip(data["devices"], topo.devices):
        d["ports"] = port_summary(dev)
    payload = json.dumps(data).replace("</", "<\\/")
    return _HTML.replace("/*__DATA__*/null", payload)


_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Switch Topology</title>
<style>
:root {
  --bg: #f6f7f9; --panel: #ffffff; --text: #1d2330; --muted: #5c6577; --line: #d9dde5;
  --accent: #2f6fde; --scanned: #2f6fde; --neighbor: #8a94a6; --phone: #2e9e6a; --ap: #b06ad8;
  --router: #d9822b; --host: #7a8699; --row: #f1f3f7; --bad: #c63d3d; --good: #2e9e6a;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12151b; --panel: #1b2029; --text: #e3e7ee; --muted: #98a2b3; --line: #2d3442;
    --accent: #6c9cf0; --scanned: #6c9cf0; --neighbor: #7d8799; --row: #222835;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
header { padding: 20px 24px 8px; }
h1 { margin: 0 0 4px; font-size: 22px; }
h2 { font-size: 16px; margin: 0 0 10px; }
.muted { color: var(--muted); }
main { padding: 8px 24px 40px; display: grid; gap: 16px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; min-width: 0; }
.stats { display: flex; flex-wrap: wrap; gap: 10px; }
.stat { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 10px 16px; min-width: 120px; }
.stat b { display: block; font-size: 22px; }
#graph-wrap { position: relative; }
svg#graph { width: 100%; height: 560px; display: block; touch-action: none; cursor: grab; }
svg#graph .link { stroke: var(--line); stroke-width: 2; }
svg#graph .link.multi { stroke-width: 3.5; }
svg#graph text { paint-order: stroke; stroke: var(--panel); stroke-width: 3px; stroke-linejoin: round; }
svg#graph .portlabel { font-size: 10px; fill: var(--muted); pointer-events: none; }
svg#graph .nodelabel { font-size: 12px; fill: var(--text); pointer-events: none; font-weight: 600; }
svg#graph .nodesub { font-size: 10px; fill: var(--muted); pointer-events: none; }
svg#graph circle { stroke: var(--panel); stroke-width: 3; cursor: pointer; }
svg#graph circle.sel { stroke: var(--text); }
.legend { display: flex; flex-wrap: wrap; gap: 14px; font-size: 12px; color: var(--muted); margin-top: 8px; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; vertical-align: -1px; }
#detail { font-size: 13px; }
#detail dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 0; }
#detail dt { color: var(--muted); }
#detail dd { margin: 0; word-break: break-word; }
.tabs { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.tabs button, select, input { font: inherit; color: var(--text); background: var(--panel);
  border: 1px solid var(--line); border-radius: 6px; padding: 6px 10px; }
.tabs button.on { background: var(--accent); border-color: var(--accent); color: #fff; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; align-items: center; }
.toolbar input { flex: 1; min-width: 160px; }
.tablewrap { overflow-x: auto; max-height: 520px; overflow-y: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }
th { position: sticky; top: 0; background: var(--panel); cursor: pointer; user-select: none; }
tbody tr:nth-child(even) { background: var(--row); }
td.mono, .mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.up { color: var(--good); } .down { color: var(--bad); }
.warn { border-left: 4px solid var(--bad); }
@media (min-width: 1100px) { .top { display: grid; grid-template-columns: 1fr 320px; gap: 16px; } }
@media (max-width: 600px) { header, main { padding-left: 16px; padding-right: 16px; } svg#graph { height: 420px; } }
</style>
</head>
<body>
<header>
  <h1>Switch Topology</h1>
  <div class="muted" id="subtitle"></div>
</header>
<main>
  <div class="stats" id="stats"></div>
  <div class="panel warn" id="failures" hidden></div>
  <div class="top">
    <section class="panel" id="graph-wrap">
      <h2>Topology</h2>
      <svg id="graph" aria-label="Topology diagram"></svg>
      <div class="legend">
        <span><i style="background:var(--scanned)"></i>Scanned switch</span>
        <span><i style="background:var(--router)"></i>Router / switch (not scanned)</span>
        <span><i style="background:var(--ap)"></i>Wireless AP</span>
        <span><i style="background:var(--phone)"></i>Phone</span>
        <span><i style="background:var(--host)"></i>Host / other</span>
        <span>Drag nodes to rearrange. Click a node for details.</span>
      </div>
    </section>
    <aside class="panel" id="detail"><h2>Details</h2><p class="muted">Select a node in the diagram.</p></aside>
  </div>
  <section class="panel">
    <div class="toolbar">
      <label>Device <select id="device"></select></label>
      <input id="filter" type="search" placeholder="Filter rows (port, MAC, IP, name...)">
    </div>
    <div class="tabs" id="tabs"></div>
    <div class="tablewrap"><table id="table"></table></div>
  </section>
</main>
<script>
const DATA = /*__DATA__*/null;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

function fmtUptime(s) {
  if (s == null) return "";
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return `${d}d ${h}h ${m}m`;
}

// ---- header + stats ---------------------------------------------------
$("#subtitle").textContent = `Scanned ${new Date(DATA.scanned_at).toLocaleString()} · ` +
  DATA.devices.map(d => `${d.sys_name || d.host} (${d.host})`).join(", ");
const totals = [
  ["Scanned switches", DATA.devices.length],
  ["Nodes", DATA.nodes.length],
  ["Links", DATA.links.length],
  ["Neighbors", DATA.devices.reduce((a, d) => a + d.neighbors.length, 0)],
  ["Endpoints located", DATA.endpoints.filter(e => e.edge).length],
  ["VLANs", new Set(DATA.devices.flatMap(d => d.vlans.map(v => v.id))).size],
];
$("#stats").innerHTML = totals.map(([k, v]) => `<div class="stat"><b>${v}</b><span class="muted">${k}</span></div>`).join("");
if (DATA.failures.length) {
  const f = $("#failures");
  f.hidden = false;
  f.innerHTML = "<h2>Could not scan</h2><ul>" +
    DATA.failures.map(x => `<li><b>${esc(x.host)}</b>: ${esc(x.error)}</li>`).join("") + "</ul>";
}

// ---- graph -----------------------------------------------------------
const css = getComputedStyle(document.documentElement);
function nodeColor(n) {
  const v = name => css.getPropertyValue(name).trim();
  if (n.kind === "scanned") return v("--scanned");
  const c = n.capabilities || [];
  if (c.includes("telephone") || c.includes("phone")) return v("--phone");
  if (c.includes("wlan-ap")) return v("--ap");
  if (c.some(x => ["router", "bridge", "switch"].includes(x))) return v("--router");
  return v("--host");
}

const svg = $("#graph");
const NS = "http://www.w3.org/2000/svg";
const nodes = DATA.nodes.map(n => ({...n}));
const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
const links = DATA.links.filter(l => byId[l.a] && byId[l.b]).map(l => ({...l, s: byId[l.a], t: byId[l.b]}));
let W = svg.clientWidth || 800, H = svg.clientHeight || 560;

// initial placement: scanned switches on an inner ring, neighbors around their switch
const scanned = nodes.filter(n => n.kind === "scanned");
scanned.forEach((n, i) => {
  const a = 2 * Math.PI * i / Math.max(1, scanned.length);
  const r = scanned.length > 1 ? Math.min(W, H) * 0.18 : 0;
  n.x = W / 2 + r * Math.cos(a); n.y = H / 2 + r * Math.sin(a);
});
nodes.filter(n => n.kind !== "scanned").forEach((n, i) => {
  const l = links.find(l => l.s === n || l.t === n);
  const p = l ? (l.s === n ? l.t : l.s) : {x: W / 2, y: H / 2};
  const a = i * 2.39996;
  n.x = (p.x ?? W / 2) + 120 * Math.cos(a); n.y = (p.y ?? H / 2) + 120 * Math.sin(a);
});

const gLinks = document.createElementNS(NS, "g"), gNodes = document.createElementNS(NS, "g");
svg.append(gLinks, gNodes);
for (const l of links) {
  l.el = document.createElementNS(NS, "line");
  l.el.setAttribute("class", "link" + (l.protocols.length > 1 ? " multi" : ""));
  l.la = document.createElementNS(NS, "text"); l.la.setAttribute("class", "portlabel"); l.la.textContent = l.a_port;
  l.lb = document.createElementNS(NS, "text"); l.lb.setAttribute("class", "portlabel"); l.lb.textContent = l.b_port;
  const title = document.createElementNS(NS, "title");
  title.textContent = `${l.a} ${l.a_port} ↔ ${l.b} ${l.b_port} (${l.protocols.join("+")})`;
  l.el.append(title);
  gLinks.append(l.el, l.la, l.lb);
}
for (const n of nodes) {
  const g = document.createElementNS(NS, "g");
  const c = document.createElementNS(NS, "circle");
  c.setAttribute("r", n.kind === "scanned" ? 16 : 10);
  c.setAttribute("fill", nodeColor(n));
  const t = document.createElementNS(NS, "text");
  t.setAttribute("class", "nodelabel"); t.setAttribute("text-anchor", "middle"); t.setAttribute("dy", n.kind === "scanned" ? 32 : 24);
  t.textContent = n.label;
  const s = document.createElementNS(NS, "text");
  s.setAttribute("class", "nodesub"); s.setAttribute("text-anchor", "middle"); s.setAttribute("dy", n.kind === "scanned" ? 45 : 36);
  s.textContent = n.mgmt_ip || "";
  g.append(c, t, s);
  gNodes.append(g);
  n.g = g; n.c = c;
  c.addEventListener("pointerdown", e => startDrag(e, n));
  c.addEventListener("click", () => select(n));
}

// small force simulation (repulsion + springs + gentle centering), computed
// up front so the layout doesn't depend on animation frames
const scale = Math.max(0.6, Math.min(1.4, Math.sqrt(W * H / (900 * 560))));
function tick(alpha) {
  for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
    const a = nodes[i], b = nodes[j];
    let dx = b.x - a.x, dy = b.y - a.y;
    if (!dx && !dy) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; }
    const d = Math.max(Math.hypot(dx, dy), 20);
    const f = Math.min(30, 18000 * scale * scale / (d * d)) * alpha;
    dx /= d; dy /= d;
    if (!a.fixed) { a.x -= dx * f; a.y -= dy * f; }
    if (!b.fixed) { b.x += dx * f; b.y += dy * f; }
  }
  for (const l of links) {
    const want = ((l.s.kind === "scanned" && l.t.kind === "scanned") ? 230 : 130) * scale;
    let dx = l.t.x - l.s.x, dy = l.t.y - l.s.y, d = Math.hypot(dx, dy) || 0.01;
    const f = (d - want) * 0.08 * alpha;
    dx /= d; dy /= d;
    if (!l.s.fixed) { l.s.x += dx * f; l.s.y += dy * f; }
    if (!l.t.fixed) { l.t.x -= dx * f; l.t.y -= dy * f; }
  }
  for (const n of nodes) if (!n.fixed) {
    n.x += (W / 2 - n.x) * 0.004 * alpha; n.y += (H / 2 - n.y) * 0.006 * alpha;
  }
}
function fit() {
  // scale the finished layout into the viewport, keeping room for labels
  const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y);
  const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
  const padX = 70, padTop = 30, padBottom = 55;
  const k = Math.min((W - 2 * padX) / Math.max(1, x1 - x0), (H - padTop - padBottom) / Math.max(1, y1 - y0), 1.2);
  for (const n of nodes) {
    n.x = W / 2 + (n.x - (x0 + x1) / 2) * k;
    n.y = padTop + (H - padTop - padBottom) / 2 + (n.y - (y0 + y1) / 2) * k;
  }
}
for (let i = 0, alpha = 1; i < 600; i++, alpha *= 0.993) tick(alpha);
fit();
function draw() {
  for (const l of links) {
    l.el.setAttribute("x1", l.s.x); l.el.setAttribute("y1", l.s.y);
    l.el.setAttribute("x2", l.t.x); l.el.setAttribute("y2", l.t.y);
    // port labels sit a fixed distance out from each node (or mid-way on short links)
    const len = Math.hypot(l.t.x - l.s.x, l.t.y - l.s.y) || 1;
    const p = (n, m) => { const k = Math.min(0.4, 48 / len); return [n.x + (m.x - n.x) * k, n.y + (m.y - n.y) * k]; };
    const [ax, ay] = p(l.s, l.t), [bx, by] = p(l.t, l.s);
    l.la.setAttribute("text-anchor", "middle"); l.lb.setAttribute("text-anchor", "middle");
    l.la.setAttribute("x", ax); l.la.setAttribute("y", ay);
    l.lb.setAttribute("x", bx); l.lb.setAttribute("y", by);
  }
  for (const n of nodes) n.g.setAttribute("transform", `translate(${n.x},${n.y})`);
}
draw();
new ResizeObserver(() => {
  const w = svg.clientWidth, h = svg.clientHeight;
  if (!w || !h || (w === W && h === H)) return;
  W = w; H = h; fit(); draw();
}).observe(svg);

function svgPoint(e) {
  const r = svg.getBoundingClientRect();
  return [e.clientX - r.left, e.clientY - r.top];
}
function startDrag(e, n) {
  e.preventDefault();
  n.fixed = true; svg.setPointerCapture(e.pointerId);
  const move = ev => { [n.x, n.y] = svgPoint(ev); draw(); };
  const up = () => { svg.removeEventListener("pointermove", move); svg.removeEventListener("pointerup", up); };
  svg.addEventListener("pointermove", move); svg.addEventListener("pointerup", up);
}

function select(n) {
  nodes.forEach(m => m.c.classList.toggle("sel", m === n));
  const dev = DATA.devices.find(d => (d.sys_name || d.host) === n.id || d.host === n.mgmt_ip && n.kind === "scanned");
  const conns = links.filter(l => l.s === n || l.t === n).map(l => l.s === n
    ? `${esc(l.a_port)} → ${esc(l.b)} ${esc(l.b_port)}` : `${esc(l.b_port)} → ${esc(l.a)} ${esc(l.a_port)}`);
  const rows = [["Name", n.label], ["Mgmt IP", n.mgmt_ip], ["Platform", n.platform],
                ["Capabilities", (n.capabilities || []).join(", ")]];
  if (dev) rows.push(["Location", dev.location], ["Uptime", fmtUptime(dev.uptime_seconds)],
                     ["Chassis ID", dev.chassis_id], ["Interfaces", dev.interfaces.length],
                     ["MACs learned", dev.mac_table.length], ["Collected via", dev.collected_via]);
  $("#detail").innerHTML = `<h2>${esc(n.label)}</h2><dl>` +
    rows.filter(r => r[1] !== "" && r[1] != null).map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("") +
    `</dl><h2 style="margin-top:14px">Links</h2>` + (conns.length ? "<ul>" + conns.map(c => `<li class="mono">${c}</li>`).join("") + "</ul>" : "<p class='muted'>None</p>") +
    (dev && dev.errors.length ? `<h2>Warnings</h2><ul>${dev.errors.map(e => `<li>${esc(e)}</li>`).join("")}</ul>` : "");
  if (dev) { $("#device").value = DATA.devices.indexOf(dev); renderTable(); }
}

// ---- tables ----------------------------------------------------------
const TABS = {
  Ports: d => [["Port", "Description", "Status", "Speed", "VLAN", "Neighbor", "MACs", "IPs"],
    d.ports.map(p => [p.port, p.description,
      {html: `<span class="${p.oper === "up" ? "up" : "down"}">${esc(p.admin === "down" ? "disabled" : p.oper)}</span>`, v: p.oper},
      p.speed_mbps ? (p.speed_mbps >= 1000 ? p.speed_mbps / 1000 + "G" : p.speed_mbps + "M") : "",
      p.vlan, p.neighbors, p.mac_count, p.ips])],
  Neighbors: d => [["Local port", "Protocol", "Remote name", "Remote port", "Mgmt IP", "Chassis ID", "Platform", "Capabilities"],
    d.neighbors.map(n => [n.local_port, n.protocol, n.remote_name, n.remote_port, n.remote_mgmt_ip,
      {mono: n.remote_chassis_id}, n.remote_platform || (n.remote_description || "").split("\n")[0].slice(0, 60), n.capabilities.join(", ")])],
  "MAC table": d => [["Port", "VLAN", "MAC", "IP", "Status"],
    d.mac_table.map(m => [m.port, m.vlan, {mono: m.mac}, m.ip, m.status])],
  ARP: d => [["IP", "MAC", "Interface"], d.arp.map(a => [a.ip, {mono: a.mac}, a.interface])],
  VLANs: d => [["VLAN", "Name", "Access ports"], d.vlans.map(v => [v.id, v.name,
    d.interfaces.filter(i => i.vlan === v.id).map(i => i.name).join(", ")])],
  Endpoints: () => [["Switch", "Port", "VLAN", "MAC", "IP", "Behind", "Location"],
    DATA.endpoints.map(e => [e.switch, e.port, e.vlan, {mono: e.mac}, e.ip, e.neighbor,
      e.edge ? "access port" : "uplink only (beyond scan)"])],
  Links: () => [["Device A", "Port A", "Device B", "Port B", "Learned via"],
    DATA.links.map(l => [l.a, l.a_port, l.b, l.b_port, l.protocols.join(" + ")])],
};
let tab = "Ports", sortCol = null, sortDir = 1;
$("#device").innerHTML = DATA.devices.map((d, i) => `<option value="${i}">${esc(d.sys_name || d.host)}</option>`).join("");
$("#tabs").innerHTML = Object.keys(TABS).map(t => `<button data-t="${t}">${t}</button>`).join("");
$("#tabs").addEventListener("click", e => { if (e.target.dataset.t) { tab = e.target.dataset.t; sortCol = null; renderTable(); } });
$("#device").addEventListener("change", renderTable);
$("#filter").addEventListener("input", renderTable);
const cellVal = c => (c && typeof c === "object") ? (c.v ?? c.mono ?? "") : c;
const cellHtml = c => (c && typeof c === "object") ? (c.html ?? `<span class="mono">${esc(c.mono)}</span>`) : esc(c);

function renderTable() {
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.t === tab));
  const d = DATA.devices[+$("#device").value || 0];
  if (!d) { $("#table").innerHTML = "<tr><td>No devices were scanned.</td></tr>"; return; }
  let [head, rows] = TABS[tab](d);
  const q = $("#filter").value.trim().toLowerCase();
  if (q) rows = rows.filter(r => r.some(c => String(cellVal(c) ?? "").toLowerCase().includes(q)));
  if (sortCol != null) rows = [...rows].sort((a, b) => {
    const x = cellVal(a[sortCol]), y = cellVal(b[sortCol]);
    const nx = Number(x), ny = Number(y);
    const r = (x !== "" && y !== "" && !isNaN(nx) && !isNaN(ny)) ? nx - ny
      : String(x ?? "").localeCompare(String(y ?? ""), undefined, {numeric: true});
    return r * sortDir;
  });
  $("#table").innerHTML = "<thead><tr>" + head.map((h, i) =>
      `<th data-i="${i}">${h}${sortCol === i ? (sortDir > 0 ? " ▲" : " ▼") : ""}</th>`).join("") + "</tr></thead><tbody>" +
    (rows.length ? rows.map(r => "<tr>" + r.map(c => `<td>${cellHtml(c)}</td>`).join("") + "</tr>").join("")
      : `<tr><td colspan="${head.length}" class="muted">No rows</td></tr>`) + "</tbody>";
}
$("#table").addEventListener("click", e => {
  const th = e.target.closest("th"); if (!th) return;
  const i = +th.dataset.i; sortDir = sortCol === i ? -sortDir : 1; sortCol = i; renderTable();
});
renderTable();
const first = nodes.find(n => n.kind === "scanned"); if (first) select(first);
</script>
</body>
</html>
"""
