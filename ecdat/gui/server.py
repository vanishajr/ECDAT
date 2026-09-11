"""Localhost GUI HTTP layer (stdlib only).

Routing + self-contained static HTML only. All use-case logic lives
in ecdat.gui.service.GuiService; this module never touches CoreClient
or SQLite directly except through the attached service instance.

Security: bind to a loopback host only (127.0.0.1 default). Refuses
non-loopback hosts such as 0.0.0.0 instead of exposing the dashboard
to the network. Port 0 lets the OS pick an ephemeral port (tests).
"""

from __future__ import annotations

import html
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ecdat.gui.service import GuiService

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def check_host(host: str) -> str:
    """Allow loopback hosts only; reject anything else (e.g. 0.0.0.0)."""
    if host not in LOOPBACK_HOSTS:
        raise ValueError(
            f"refusing non-loopback GUI host {host!r}: "
            "bind to 127.0.0.1 only (allowed: "
            + ", ".join(LOOPBACK_HOSTS)
            + ")"
        )
    return host


def esc(value: object) -> str:
    """HTML-escape server-injected text."""
    return html.escape(str(value), quote=True)


def index_page(prefill_target: str = "") -> str:
    """Self-contained dashboard page. No CDN, no JS framework.

    Dynamic scan data is rendered client-side with textContent (never
    innerHTML), so canonical text cannot break out of the page. Only
    the optional prefill value is server-injected, via esc().

    NOTE: this is a raw string so JS "\\n" escapes survive intact.
    """
    page = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<title>ECDAT Local GUI (mock)</title>
<style>
:root{color-scheme:light}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:62em;margin:0 auto;padding:1.5em 1em 3em;color:#1a1a1a}
header{display:flex;align-items:center;gap:.6em;flex-wrap:wrap}
.badge{display:inline-block;font-size:.75em;font-weight:700;padding:.2em .6em;border-radius:999px;background:#fff3cd;border:1px solid #d9a900;color:#6b4e00}
.card{border:1px solid #d7d7d7;border-radius:.6em;padding:1em 1.2em;margin:1em 0;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.04)}
h1{font-size:1.4em;margin:.2em 0}
h2{font-size:1.05em;margin:.2em 0 .6em}
label{font-weight:600;display:block;margin-bottom:.3em}
input[type=text]{width:100%;max-width:34em;padding:.5em .6em;border:1px solid #999;border-radius:.4em;font-size:1em}
.row{display:flex;gap:.6em;margin-top:.7em;flex-wrap:wrap}
button{padding:.5em 1em;border-radius:.4em;border:1px solid #2456a6;background:#2456a6;color:#fff;font-size:.95em;cursor:pointer}
button.secondary{background:#fff;color:#2456a6}
button:disabled{opacity:.55;cursor:default}
.note{font-size:.85em;color:#555}
.preview{background:#f7f7f7;border-radius:.4em;padding:.7em .9em;white-space:pre-wrap;font-size:.9em}
.progress{height:1.1em;background:#eee;border-radius:999px;overflow:hidden;margin:.5em 0}
.progress>div{height:100%;width:0%;background:#2456a6;transition:width .25s}
table{border-collapse:collapse;width:100%;font-size:.9em}
th,td{border:1px solid #bbb;padding:.35em .55em;text-align:left;vertical-align:top}
th{background:#f0f3f8}
.sev{display:inline-block;min-width:4.2em;text-align:center;font-weight:700;font-size:.8em;border-radius:.35em;padding:.1em .5em}
.sev-critical{background:#f8d7da;color:#7a1f26}
.sev-high{background:#ffe0cc;color:#8a3d00}
.sev-medium{background:#fff3cd;color:#6b4e00}
.sev-low{background:#d9ecff;color:#14467c}
.sev-info{background:#e2e3e5;color:#383d41}
details{margin-top:.3em}
summary{cursor:pointer;color:#2456a6;font-size:.85em}
code{font-size:.85em;background:#f4f4f4;padding:.1em .3em;border-radius:.3em}
#error{color:#7a1f26;font-weight:600}
.chips{display:flex;gap:.5em;flex-wrap:wrap;margin:.4em 0}
.chip{background:#eef2f9;border:1px solid #c4d2e8;border-radius:999px;padding:.15em .7em;font-size:.85em}
#graph{display:block;cursor:grab;touch-action:none}
#graph text{font-family:inherit;pointer-events:none}
.gnode{cursor:pointer}
.gnode rect{stroke:#5b6478;stroke-width:1.5}
.gnode.risky rect{stroke:#c00;stroke-width:2.5}
.gnode.selected rect{stroke:#2456a6;stroke-width:3}
.gnode.dim,.gedge.dim,.glabel.dim{opacity:.1}
.gedge{stroke:#8a93a6;stroke-width:1.5;cursor:pointer}
.gedge.risky{stroke:#c00}
.gedge.trace{stroke:#2456a6;stroke-width:3}
.gedge.selected{stroke:#2456a6;stroke-width:3}
.gedge-hit{stroke:rgba(0,0,0,0);stroke-width:12;cursor:pointer}
.glabel{font-size:9px;fill:#555}
.gtrace-on{outline:2px solid #2456a6}
.tiles{display:flex;gap:.5em;flex-wrap:wrap;margin:.5em 0}
.tile{border:1px solid #bbb;background:#fff;border-radius:.5em;padding:.4em .8em;cursor:pointer;font-size:.9em;color:#1a1a1a}
.tile b{display:block;font-size:1.2em}
.tile.active{outline:2px solid #2456a6;background:#eef2f9}
tr.clickable{cursor:pointer}
tr.clickable:hover td{background:#f0f5ff}
.kv{display:grid;grid-template-columns:11em 1fr;gap:.2em .8em;font-size:.9em;margin:.4em 0}
.kv dt{font-weight:600;color:#444}
.kv dd{margin:0;overflow-wrap:anywhere}
.avail{font-size:.85em;color:#555}
</style>
</head>
<body>
<header>
<h1>ECDAT Local GUI</h1>
<span class="badge">MOCK / SIMULATED</span>
</header>
<p class="note">Mock-first vertical slice: target selection &rarr; scan-plan preview &rarr;
simulated progress &rarr; basic inventory. No real detection. Localhost only.</p>

<div class="card">
<h2>1. Select target</h2>
<label for="target">Target path or label</label>
<input type="text" id="target" value="__PREFILL__" placeholder="e.g. samples/rsa_small.py">
<div class="row">
<button id="previewBtn" class="secondary" type="button">Show scan-plan preview</button>
<button id="scanBtn" type="button">Start mock scan</button>
</div>
</div>

<div class="card">
<h2>2. Scan-plan preview (read-only, mock)</h2>
<div class="preview" id="preview">No preview yet. Enter a target and choose preview.</div>
</div>

<div class="card">
<h2>3. Live scan monitor (simulated)</h2>
<div class="note">Simulated progress (mock): queued &rarr; scanning &rarr; completed.
Staged for UI purposes only &mdash; the mock scan itself is instantaneous.</div>
<div class="progress"><div id="bar"></div></div>
<div class="preview" id="job">No job yet.</div>
</div>

<div class="card">
<h2>4. Crypto inventory / results</h2>
<div class="note">Click a finding row to open its detail below. Click risk tiles or rule buttons to drill down.</div>
<div class="chips" id="chips"></div>
<div class="row" id="filterRow" style="display:none">
<button id="clearFilters" class="secondary" type="button">Clear filters</button>
</div>
<div id="inventory"><p class="note">No completed scan yet.</p></div>
<div id="error" role="alert"></div>
</div>

<div class="card">
<h2>5. Risk dashboard (mock/placeholder)</h2>
<div class="note">Mock scoring — see model note below. Click a severity tile or rule to drill down to findings.</div>
<div class="tiles" id="riskTiles"></div>
<div class="preview" id="risk">No completed scan yet.</div>
<div id="riskRules"></div>
</div>

<div class="card">
<h2>6. Finding detail</h2>
<div id="detail"><p class="note">Select a finding row in the inventory to see its evidence, confidence, and provenance.</p></div>
</div>

<div class="card">
<h2>7. Crypto asset inventory + finding grouping</h2>
<div class="note">Flat asset inventory &mdash; relationships not available yet.
Co-occurrence grouping &mdash; not a dependency graph.</div>
<div id="assets"><p class="note">No completed scan yet.</p></div>
<div class="preview" id="graphState">Dependency edges: awaiting Person 1 edge data.</div>
</div>

<div class="card">
<h2>8. Crypto Knowledge Graph <span class="badge">MOCK DATASET</span></h2>
<div class="note">Deterministic mock graph for UI development — not scan data and not Person 1 CIR.
Drag to pan, scroll to zoom, click nodes and edges. Risky nodes/paths are ringed red.</div>
<div class="row">
<input type="text" id="gsearch" placeholder="filter: e.g. RSA, tls, aws" style="max-width:22em">
<label class="note"><input type="checkbox" id="grisky"> risky only</label>
<button id="greset" class="secondary" type="button">Reset view</button>
<button id="gtrace" type="button">Trace: internet → risk</button>
</div>
<div class="chips" id="gtypes"></div>
<div id="gwrap" style="border:1px solid #d7d7d7;border-radius:.5em;overflow:hidden;background:#fafbfe">
<svg id="graph" width="100%" height="520" role="img" aria-label="crypto knowledge graph"></svg>
</div>
<div class="row">
<div id="gdetail" style="flex:1;min-width:16em"><p class="note">Select a node or edge.</p></div>
</div>
</div>

<div class="card">
<h2>9. Migration Planner <span class="badge">MOCK / PLACEHOLDER</span></h2>
<div class="note">Severity triage of existing mock recommendations — heaviest first.
This is triage by current finding severity, NOT a migration sequence.</div>
<div id="migration"><p class="note">No completed scan yet.</p></div>
<div class="preview" id="migration-missing">Not included yet: PQC target selection; migration timelines;
effort estimates; phased sequencing; migration confidence; real migration state.
All await Person 1 migration intelligence.</div>
</div>

<script>
"use strict";
function $(id){return document.getElementById(id);}
function showError(msg){$("error").textContent = msg || "";}
function setBar(pct){$("bar").style.width = Math.round(pct*100) + "%";}
async function api(path, opts){
  const res = await fetch(path, opts);
  const data = await res.json();
  if(!res.ok){ throw new Error(data.error || ("request failed: " + res.status)); }
  return data;
}
$("previewBtn").addEventListener("click", async function(){
  showError("");
  const t = $("target").value.trim();
  try{
    const p = await api("/api/preview?target=" + encodeURIComponent(t));
    $("preview").textContent =
      "target: " + p.target + "\nmode: " + p.mode + " (" + p.client + ")\n" +
      "stages: " + p.stages.join(" -> ") + "\nstore: " + p.stores_through +
      "\nread-back: " + p.reads_back_through + "\nnote: " + p.note;
  }catch(e){ showError(String(e.message || e)); }
});
let timer = null;
let currentScanId = null;
let filterSev = null;
let filterRule = null;
$("scanBtn").addEventListener("click", async function(){
  showError("");
  const t = $("target").value.trim();
  if(timer){ clearInterval(timer); timer = null; }
  try{
    const job = await api("/api/scans", {method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({target:t})});
    poll(job.job_id);
    timer = setInterval(function(){ poll(job.job_id); }, 300);
  }catch(e){ showError(String(e.message || e)); }
});
async function poll(jobId){
  try{
    const j = await api("/api/jobs?id=" + encodeURIComponent(jobId));
    setBar(j.progress);
    $("job").textContent =
      "job: " + j.job_id + "\ntarget: " + j.target + "\nstatus: " + j.status +
      " (" + Math.round(j.progress*100) + "%)\n" + j.simulated_note +
      (j.scan_id ? "\nscan_id: " + j.scan_id : "") + (j.error ? "\nerror: " + j.error : "");
    if(j.status === "completed"){
      if(timer){ clearInterval(timer); timer = null; }
      currentScanId = j.scan_id;
      filterSev = null;
      filterRule = null;
      loadInventory(j.scan_id);
      loadRisk(j.scan_id);
      loadAssets(j.scan_id);
      loadMigration(j.scan_id);
    }else if(j.status === "failed"){
      if(timer){ clearInterval(timer); timer = null; }
      showError(j.error || "scan failed");
    }
  }catch(e){ if(timer){ clearInterval(timer); timer = null; } showError(String(e.message || e)); }
}
async function loadInventory(scanId){
  let path = "/api/inventory?scan_id=" + encodeURIComponent(scanId);
  if(filterSev){ path += "&severity=" + encodeURIComponent(filterSev); }
  if(filterRule){ path += "&rule=" + encodeURIComponent(filterRule); }
  const inv = await api(path);
  const chips = $("chips");
  while(chips.firstChild){ chips.removeChild(chips.firstChild); }
  let countLabel = String(inv.finding_count);
  if(inv.filters && (inv.filters.severity || inv.filters.rule)){
    countLabel += " of " + inv.total_findings + " (filtered)";
  }
  [["scan", inv.scan_id], ["target", inv.target],
   ["findings", countLabel],
   ["files scanned", String(inv.files_scanned)]].forEach(function(pair){
    const s = document.createElement("span");
    s.className = "chip";
    s.textContent = pair[0] + ": " + pair[1];
    chips.appendChild(s);
  });
  Object.keys(inv.severity_counts).sort().forEach(function(sev){
    const s = document.createElement("span");
    s.className = "chip";
    s.textContent = sev + ": " + inv.severity_counts[sev];
    chips.appendChild(s);
  });
  $("filterRow").style.display =
    (inv.filters && (inv.filters.severity || inv.filters.rule)) ? "flex" : "none";
  const host = $("inventory");
  while(host.firstChild){ host.removeChild(host.firstChild); }
  if(!inv.findings.length){
    const p = document.createElement("p");
    p.className = "note";
    p.textContent = "No findings for this scan.";
    host.appendChild(p);
    return;
  }
  const table = document.createElement("table");
  const head = document.createElement("tr");
  ["Severity","Rule","File","Line","Title","Confidence"].forEach(function(h){
    const th = document.createElement("th");
    th.textContent = h;
    head.appendChild(th);
  });
  table.appendChild(head);
  inv.findings.forEach(function(f){
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.addEventListener("click", function(){ loadFinding(currentScanId, f.index); });
    const sev = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev sev-" + String(f.severity);
    badge.textContent = String(f.severity);
    sev.appendChild(badge);
    tr.appendChild(sev);
    [["rule_id"],["file"],["line"],["title"]].forEach(function(k){
      const td = document.createElement("td");
      td.textContent = String(f[k[0]]);
      tr.appendChild(td);
    });
    const conf = document.createElement("td");
    conf.textContent = (f.confidence === undefined || f.confidence === null)
      ? "-" : String(f.confidence);
    tr.appendChild(conf);
    table.appendChild(tr);
    if(f.snippet){
      const srow = document.createElement("tr");
      const std = document.createElement("td");
      std.setAttribute("colspan", "6");
      const det = document.createElement("details");
      const sum = document.createElement("summary");
      sum.textContent = "snippet";
      const code = document.createElement("code");
      code.textContent = String(f.snippet);
      det.appendChild(sum);
      det.appendChild(code);
      std.appendChild(det);
      srow.appendChild(std);
      table.appendChild(srow);
    }
  });
  host.appendChild(table);
}
async function loadRisk(scanId){
  const r = await api("/api/risk?scan_id=" + encodeURIComponent(scanId));
  const tiles = $("riskTiles");
  while(tiles.firstChild){ tiles.removeChild(tiles.firstChild); }
  Object.keys(r.severity_counts).forEach(function(sev){
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tile" + ((filterSev === sev) ? " active" : "");
    const n = document.createElement("b");
    n.textContent = String(r.severity_counts[sev]);
    const l = document.createElement("span");
    l.textContent = sev;
    b.appendChild(n);
    b.appendChild(l);
    b.addEventListener("click", function(){
      filterSev = (filterSev === sev) ? null : sev;
      loadInventory(scanId);
      loadRisk(scanId);
      document.getElementById("inventory").scrollIntoView();
    });
    tiles.appendChild(b);
  });
  $("risk").textContent =
    "score: " + r.score + " / level: " + r.level + " (mock/placeholder)\n" +
    "findings: " + r.finding_count + "\nbreakdown: " +
    Object.keys(r.breakdown).sort().map(function(k){return k + "=" + r.breakdown[k];}).join(" ") +
    "\nmodel: " + r.model;
  const rules = $("riskRules");
  while(rules.firstChild){ rules.removeChild(rules.firstChild); }
  if(!r.by_rule.length){ return; }
  const note = document.createElement("p");
  note.className = "note";
  note.textContent = "Rules (click to drill down):";
  rules.appendChild(note);
  const wrap = document.createElement("div");
  wrap.className = "chips";
  r.by_rule.forEach(function(row){
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tile" + ((filterRule === row.rule_id) ? " active" : "");
    b.textContent = row.rule_id + " [" + row.severity + "] x" + row.count;
    b.addEventListener("click", function(){
      filterRule = (filterRule === row.rule_id) ? null : row.rule_id;
      loadInventory(scanId);
      loadRisk(scanId);
      document.getElementById("inventory").scrollIntoView();
    });
    wrap.appendChild(b);
  });
  rules.appendChild(wrap);
}
async function loadFinding(scanId, idx){
  showError("");
  try{
    const d = await api("/api/finding?scan_id=" + encodeURIComponent(scanId) +
      "&index=" + encodeURIComponent(String(idx)));
    const host = $("detail");
    while(host.firstChild){ host.removeChild(host.firstChild); }
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = d.provenance.status;
    host.appendChild(badge);
    const title = document.createElement("h3");
    title.textContent = d.finding.rule_id + ": " + d.finding.title;
    host.appendChild(title);
    const dl = document.createElement("dl");
    dl.className = "kv";
    [["Severity", String(d.finding.severity)],
     ["File", String(d.finding.file)],
     ["Line", String(d.finding.line)],
     ["Confidence", (d.finding.confidence === undefined || d.finding.confidence === null)
       ? "not provided (v1 optional)" : String(d.finding.confidence)],
     ["Snippet", (d.finding.snippet === undefined || d.finding.snippet === null)
       ? "not provided (v1 optional)" : String(d.finding.snippet)],
     ["Metadata", d.metadata_keys.length ? d.metadata_keys.join(", ") : "none in v1 doc"],
     ["Evidence available",
       Object.keys(d.evidence_available).map(function(k){return k + ": " + (d.evidence_available[k] ? "yes" : "no");}).join("; ")],
     ["Missing evidence", d.missing_evidence.length ? d.missing_evidence.join(", ") : "none"],
     ["Redaction", "applied: no. " + d.redaction.reason + " " + d.redaction.capability]
    ].forEach(function(pair){
      const dt = document.createElement("dt");
      dt.textContent = pair[0];
      const dd = document.createElement("dd");
      dd.textContent = pair[1];
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    host.appendChild(dl);
    const prov = document.createElement("p");
    prov.className = "note";
    prov.textContent = "Provenance: " + d.provenance.note;
    host.appendChild(prov);
    const strip = document.createElement("p");
    strip.className = "note";
    strip.textContent = d.scan_provenance.started_at + " -> " +
      d.scan_provenance.finished_at + ". " + d.scan_provenance.label;
    host.appendChild(strip);
    host.scrollIntoView();
  }catch(e){ showError(String(e.message || e)); }
}
async function loadAssets(scanId){
  try{
    const a = await api("/api/assets?scan_id=" + encodeURIComponent(scanId));
    const host = $("assets");
    while(host.firstChild){ host.removeChild(host.firstChild); }
    const lab = document.createElement("p");
    lab.className = "note";
    lab.textContent = a.asset_label + " Assets: " + a.asset_count + ".";
    host.appendChild(lab);
    if(a.assets.length){
      const table = document.createElement("table");
      const head = document.createElement("tr");
      ["Asset (bom-ref)","Name","Type","Evidence location"].forEach(function(h){
        const th = document.createElement("th");
        th.textContent = h;
        head.appendChild(th);
      });
      table.appendChild(head);
      a.assets.forEach(function(c){
        const tr = document.createElement("tr");
        const ref = document.createElement("td");
        ref.textContent = String(c["bom-ref"]);
        tr.appendChild(ref);
        const nm = document.createElement("td");
        nm.textContent = String(c.name) + " (" + String(c.cryptoProperties.assetType) + ")";
        tr.appendChild(nm);
        const ty = document.createElement("td");
        ty.textContent = String(c.type);
        tr.appendChild(ty);
        const loc = document.createElement("td");
        loc.textContent = String(c.evidence.occurrences[0].location);
        tr.appendChild(loc);
        table.appendChild(tr);
      });
      host.appendChild(table);
    }else{
      const p = document.createElement("p");
      p.className = "note";
      p.textContent = "No crypto assets in this scan.";
      host.appendChild(p);
    }
    const glab = document.createElement("p");
    glab.className = "note";
    glab.textContent = a.groupings.label;
    host.appendChild(glab);
    a.groupings.by_file.forEach(function(g){
      const h = document.createElement("h4");
      h.textContent = g.file + " x" + g.count;
      host.appendChild(h);
      const ul = document.createElement("ul");
      g.findings.forEach(function(f){
        const li = document.createElement("li");
        li.textContent = "[" + f.severity + "] " + f.rule_id + " line " + f.line + ": " + f.title;
        ul.appendChild(li);
      });
      host.appendChild(ul);
    });
    const rl = document.createElement("h4");
    rl.textContent = "Rules across files";
    host.appendChild(rl);
    const rul = document.createElement("ul");
    a.groupings.by_rule.forEach(function(r){
      const li = document.createElement("li");
      li.textContent = r.rule_id + " [" + r.severity + "] x" + r.count + ": " + r.files.join(", ");
      rul.appendChild(li);
    });
    host.appendChild(rul);
    $("graphState").textContent = a.graph.message + " " + a.graph.detail;
  }catch(e){ showError(String(e.message || e)); }
}
async function loadMigration(scanId){
  try{
    const m = await api("/api/migration?scan_id=" + encodeURIComponent(scanId));
    const host = $("migration");
    while(host.firstChild){ host.removeChild(host.firstChild); }
    const tri = document.createElement("p");
    tri.className = "note";
    tri.textContent = m.triage_label;
    host.appendChild(tri);
    if(!m.items.length){
      const p = document.createElement("p");
      p.className = "note";
      p.textContent = "No findings to plan for in this scan.";
      host.appendChild(p);
      return;
    }
    m.items.forEach(function(it){
      const h = document.createElement("h4");
      h.textContent = it.rule_id + " [" + it.severity + "] x" + it.count;
      host.appendChild(h);
      const dl = document.createElement("dl");
      dl.className = "kv";
      [["Title", it.title],
       ["Action", it.action],
       ["Refs", it.refs.length ? it.refs.join(", ") : "none"],
       ["Affected files", it.affected_files.length ? it.affected_files.join(", ") : "none"],
       ["Graph nodes", it.graph_node_ids.length ? it.graph_node_ids.join(", ") : "none"],
       ["Status", it.status]
      ].forEach(function(pair){
        const dt = document.createElement("dt");
        dt.textContent = pair[0];
        const dd = document.createElement("dd");
        dd.textContent = pair[1];
        dl.appendChild(dt);
        dl.appendChild(dd);
      });
      host.appendChild(dl);
      if(it.graph_node_ids.length){
        const b = document.createElement("button");
        b.type = "button";
        b.className = "secondary";
        b.textContent = "Show " + it.graph_node_ids[0] + " in graph";
        b.addEventListener("click", function(){
          selectNode(it.graph_node_ids[0]);
          document.getElementById("gwrap").scrollIntoView();
        });
        host.appendChild(b);
      }
      const ib = document.createElement("button");
      ib.type = "button";
      ib.className = "secondary";
      ib.style.marginLeft = ".5em";
      ib.textContent = "Show findings in inventory";
      ib.addEventListener("click", function(){
        if(!currentScanId){ showError("run a mock scan first to cross-link inventory"); return; }
        filterSev = null;
        filterRule = it.rule_id;
        loadInventory(currentScanId);
        document.getElementById("inventory").scrollIntoView();
      });
      host.appendChild(ib);
    });
  }catch(e){ showError(String(e.message || e)); }
}
$("clearFilters").addEventListener("click", function(){
  filterSev = null;
  filterRule = null;
  if(currentScanId){ loadInventory(currentScanId); loadRisk(currentScanId); }
});
$("clearFilters").addEventListener("click", function(){
  filterSev = null;
  filterRule = null;
  if(currentScanId){ loadInventory(currentScanId); loadRisk(currentScanId); }
});
const SVGNS = document.getElementById("graph").namespaceURI;
const GTCOLORS = {"Endpoint":"#e8eaf6","Service":"#dbeafe","Container":"#e0e7ff","Library":"#fef3c7","CryptoOperation":"#ede9fe","CryptoAsset":"#dcfce7","CertificateKey":"#ffedd5","CloudResource":"#f3f4f6"};
const GRISKY = {"high":true,"critical":true};
let GDATA = null;
let gView = {x:0,y:0,k:1};
let gHiddenTypes = {};
let gTraceOn = null;
function gEl(name, attrs, parent){
  const el = document.createElementNS(SVGNS, name);
  for(const k in attrs){ el.setAttribute(k, attrs[k]); }
  if(parent){ parent.appendChild(el); }
  return el;
}
function gText(parent, x, y, s, size, bold, fill){
  const t = gEl("text", {x:x, y:y, "font-size":size, "text-anchor":"middle"}, parent);
  if(bold){ t.setAttribute("font-weight","700"); }
  if(fill){ t.setAttribute("fill", fill); }
  t.textContent = s;
  return t;
}
function gApply(){
  const root = document.getElementById("groot");
  if(root){ root.setAttribute("transform", "translate(" + gView.x + "," + gView.y + ") scale(" + gView.k + ")"); }
}
function gNodeById(id){
  for(const n of GDATA.nodes){ if(n.id === id){ return n; } }
  return null;
}
function gVisible(n, q){
  if(gHiddenTypes[n.type]){ return false; }
  if(document.getElementById("grisky").checked && !GRISKY[n.risk]){ return false; }
  if(q && (n.id + " " + n.label + " " + n.type).toLowerCase().indexOf(q) < 0){ return false; }
  return true;
}
async function loadGraph(){
  try{
    GDATA = await api("/api/graph");
    buildTypeChips();
    renderGraph();
  }catch(e){ showError(String(e.message || e)); }
}
function buildTypeChips(){
  const host = $("gtypes");
  while(host.firstChild){ host.removeChild(host.firstChild); }
  GDATA.node_types.forEach(function(t){
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tile";
    b.textContent = t;
    b.style.background = GTCOLORS[t] || "#fff";
    b.addEventListener("click", function(){
      gHiddenTypes[t] = !gHiddenTypes[t];
      b.classList.toggle("gtrace-hl", false);
      b.style.opacity = gHiddenTypes[t] ? ".4" : "1";
      renderGraph();
    });
    host.appendChild(b);
  });
}
function renderGraph(){
  const svg = $("graph");
  while(svg.firstChild){ svg.removeChild(svg.firstChild); }
  const W = GDATA.canvas.width, H = GDATA.canvas.height;
  svg.setAttribute("viewBox", "0 0 " + W + " " + H);
  const defs = gEl("defs", {}, svg);
  [["garr","#8a93a6"],["garrR","#c00"],["garrB","#2456a6"]].forEach(function(m){
    const mk = gEl("marker", {id:m[0], viewBox:"0 0 10 10", refX:"9", refY:"5",
      markerWidth:"7", markerHeight:"7", orient:"auto-start-reverse"}, defs);
    gEl("path", {d:"M 0 1 L 9 5 L 0 9 z", fill:m[1]}, mk);
  });
  const root = gEl("g", {id:"groot"}, svg);
  const q = $("gsearch").value.trim().toLowerCase();
  const vis = {};
  GDATA.nodes.forEach(function(n){ vis[n.id] = gVisible(n, q); });
  const eLayer = gEl("g", {}, root);
  const nLayer = gEl("g", {}, root);
  GDATA.edges.forEach(function(e){
    const a = gNodeById(e.source), b = gNodeById(e.target);
    const shown = vis[e.source] && vis[e.target];
    const traced = gTraceOn && gTraceOn.edgeIds.indexOf(e.id) >= 0;
    const risky = GRISKY[a.risk] || GRISKY[b.risk];
    const x1 = a.x + 75, y1 = a.y + 28, x2 = b.x + 75, y2 = b.y + 28;
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    const ln = gEl("line", {x1:x1, y1:y1, x2:x2, y2:y2,
      "class":"gedge" + (risky ? " risky" : "") + (traced ? " trace" : "") + (shown ? "" : " dim"),
      "marker-end": traced ? "url(#garrB)" : (risky ? "url(#garrR)" : "url(#garr)")}, eLayer);
    ln.addEventListener("click", function(ev){ ev.stopPropagation(); selectEdge(e.id); });
    gEl("line", {x1:x1, y1:y1, x2:x2, y2:y2, "class":"gedge-hit" + (shown ? "" : " dim")}, eLayer)
      .addEventListener("click", function(ev){ ev.stopPropagation(); selectEdge(e.id); });
    const lb = gEl("text", {x:mx, y:my - 4, "class":"glabel" + (shown ? "" : " dim"), "text-anchor":"middle"}, eLayer);
    lb.textContent = e.type;
  });
  GDATA.nodes.forEach(function(n){
    const g = gEl("g", {"class":"gnode" + (GRISKY[n.risk] ? " risky" : "") + (vis[n.id] ? "" : " dim"),
      transform:"translate(" + n.x + "," + n.y + ")", "data-nid":n.id}, nLayer);
    gEl("rect", {width:150, height:56, rx:8, fill:GTCOLORS[n.type] || "#fff"}, g);
    const title = gEl("title", {}, g);
    title.textContent = n.label + " (" + n.type + ", risk " + n.risk + ")";
    gText(g, 75, 18, n.label.slice(0, 22), 11, true);
    gText(g, 75, 32, n.type, 9, false, "#555");
    gText(g, 75, 46, "risk: " + n.risk, 9, true, GRISKY[n.risk] ? "#c00" : "#444");
    g.addEventListener("click", function(ev){ ev.stopPropagation(); selectNode(n.id); });
  });
  gApply();
}
function gDetailBox(){
  const host = $("gdetail");
  while(host.firstChild){ host.removeChild(host.firstChild); }
  return host;
}
function gKv(host, k, v){
  const p = document.createElement("p");
  p.className = "note";
  p.style.margin = ".2em 0";
  const b = document.createElement("b");
  b.textContent = k + ": ";
  p.appendChild(b);
  p.appendChild(document.createTextNode(v));
  host.appendChild(p);
}
function selectNode(id){
  renderGraph();
  const hit = document.querySelector('.gnode[data-nid="' + id + '"]');
  if(hit){ hit.classList.add("selected"); }
  const n = gNodeById(id);
  const host = gDetailBox();
  const h = document.createElement("h4");
  h.textContent = n.label;
  host.appendChild(h);
  gKv(host, "Type", n.type);
  gKv(host, "Risk", n.risk + (GRISKY[n.risk] ? " (risky path)" : ""));
  gKv(host, "Confidence", String(n.confidence) + " (mock dataset value)");
  Object.keys(n.metadata).sort().forEach(function(k){ gKv(host, k, n.metadata[k]); });
  const rel = GDATA.edges.filter(function(e){ return e.source === id || e.target === id; });
  const rh = document.createElement("h4");
  rh.textContent = "Relationships (" + rel.length + ")";
  host.appendChild(rh);
  const ul = document.createElement("ul");
  rel.forEach(function(e){
    const other = e.source === id ? e.target : e.source;
    const dir = e.source === id ? "out" : "in";
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tile";
    b.textContent = dir + " " + e.type + " → " + other;
    b.addEventListener("click", function(){ selectNode(other); });
    li.appendChild(b);
    if(e.detail){
      const sp = document.createElement("span");
      sp.className = "note";
      sp.textContent = " " + e.detail;
      li.appendChild(sp);
    }
    ul.appendChild(li);
  });
  host.appendChild(ul);
  if(n.rule_id){
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = "Show in inventory (" + n.rule_id + ")";
    b.addEventListener("click", function(){
      if(!currentScanId){ showError("run a mock scan first to cross-link inventory"); return; }
      filterSev = null;
      filterRule = n.rule_id;
      loadInventory(currentScanId);
      document.getElementById("inventory").scrollIntoView();
    });
    host.appendChild(b);
  }
  const rb = document.createElement("button");
  rb.type = "button";
  rb.className = "secondary";
  rb.textContent = "Open risk dashboard";
  rb.style.marginLeft = ".5em";
  rb.addEventListener("click", function(){
    document.getElementById("riskTiles").scrollIntoView();
  });
  host.appendChild(rb);
}
function selectEdge(id){
  document.querySelectorAll(".gedge.selected").forEach(function(el){ el.classList.remove("selected"); });
  renderGraph();
  const host = gDetailBox();
  let found = null;
  for(const e of GDATA.edges){ if(e.id === id){ found = e; break; } }
  if(!found){ return; }
  const h = document.createElement("h4");
  h.textContent = found.type + ": " + found.source + " → " + found.target;
  host.appendChild(h);
  gKv(host, "Relationship", found.type);
  gKv(host, "Source", found.source + " (" + gNodeById(found.source).type + ")");
  gKv(host, "Target", found.target + " (" + gNodeById(found.target).type + ")");
  if(found.detail){ gKv(host, "Detail", found.detail); }
  [["source", found.source], ["target", found.target]].forEach(function(p){
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tile";
    b.textContent = "Select " + p[0] + ": " + p[1];
    b.style.marginRight = ".4em";
    b.addEventListener("click", function(){ selectNode(p[1]); });
    host.appendChild(b);
  });
}
function tracePath(pid){
  let t = null;
  for(const c of GDATA.trace_paths){ if(c.id === pid){ t = c; break; } }
  if(!t){ return; }
  const edgeIds = [];
  for(let i = 0; i + 1 < t.node_ids.length; i++){
    const a = t.node_ids[i], b = t.node_ids[i + 1];
    for(const e of GDATA.edges){
      if((e.source === a && e.target === b) || (e.source === b && e.target === a)){
        edgeIds.push(e.id);
        break;
      }
    }
  }
  gTraceOn = {id: pid, edgeIds: edgeIds};
  renderGraph();
  const host = gDetailBox();
  const h = document.createElement("h4");
  h.textContent = "Trace: " + t.label;
  host.appendChild(h);
  const ol = document.createElement("ol");
  t.node_ids.forEach(function(nid){
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tile";
    b.textContent = nid;
    b.addEventListener("click", function(){ selectNode(nid); });
    li.appendChild(b);
    ol.appendChild(li);
  });
  host.appendChild(ol);
  const p = document.createElement("p");
  p.className = "note";
  p.textContent = t.note;
  host.appendChild(p);
  const rb = document.createElement("button");
  rb.type = "button";
  rb.textContent = "Open risk dashboard";
  rb.addEventListener("click", function(){
    document.getElementById("riskTiles").scrollIntoView();
  });
  host.appendChild(rb);
}
$("greset").addEventListener("click", function(){
  gView = {x:0,y:0,k:1};
  gHiddenTypes = {};
  gTraceOn = null;
  $("gsearch").value = "";
  document.querySelectorAll("#gtypes .tile").forEach(function(b){ b.style.opacity = "1"; });
  renderGraph();
});
$("gtrace").addEventListener("click", function(){ tracePath("internet-to-risk"); });
$("gsearch").addEventListener("input", function(){ renderGraph(); });
$("grisky").addEventListener("change", function(){ renderGraph(); });
(function(){
  const svg = $("graph");
  let pan = null;
  svg.addEventListener("pointerdown", function(ev){
    pan = {x:ev.clientX, y:ev.clientY, vx:gView.x, vy:gView.y};
    svg.setPointerCapture(ev.pointerId);
    svg.style.cursor = "grabbing";
  });
  svg.addEventListener("pointermove", function(ev){
    if(!pan){ return; }
    const r = svg.getBoundingClientRect();
    const sx = GDATA ? GDATA.canvas.width / r.width : 1;
    gView.x = pan.vx + (ev.clientX - pan.x) * sx;
    gView.y = pan.vy + (ev.clientY - pan.y) * sx;
    gApply();
  });
  svg.addEventListener("pointerup", function(){ pan = null; svg.style.cursor = "grab"; });
  svg.addEventListener("wheel", function(ev){
    ev.preventDefault();
    const r = svg.getBoundingClientRect();
    const sx = GDATA.canvas.width / r.width;
    const px = (ev.clientX - r.left) * sx, py = (ev.clientY - r.top) * sx;
    const k2 = Math.min(3, Math.max(.3, gView.k * Math.exp(-ev.deltaY * .0012)));
    gView.x = px - (px - gView.x) * (k2 / gView.k);
    gView.y = py - (py - gView.y) * (k2 / gView.k);
    gView.k = k2;
    gApply();
  }, {passive:false});
})();
loadGraph().catch(function(e){ showError(String(e && e.message || e)); });
</script>
</body>
</html>
"""
    return page.replace("__PREFILL__", esc(prefill_target))


class _Handler(BaseHTTPRequestHandler):
    server_version = "ECDAT-GUI"

    @property
    def service(self) -> GuiService:
        return self.server.gui_service  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:  # keep test output clean
        pass

    # -- helpers ---------------------------------------------------------

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            obj = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            raise ValueError("invalid JSON body")
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    # -- routes ----------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/":
            self._html(index_page())
        elif parsed.path == "/api/preview":
            target = query.get("target", [""])[0]
            try:
                self._json(200, self.service.preview(target))
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
        elif parsed.path == "/api/jobs":
            snap = self.service.status(query.get("id", [""])[0])
            if snap is None:
                self._json(404, {"error": "unknown job"})
            else:
                self._json(200, snap)
        elif parsed.path == "/api/inventory":
            inv = self.service.inventory(
                query.get("scan_id", [""])[0],
                severity=query.get("severity", [None])[0] or None,
                rule=query.get("rule", [None])[0] or None,
            )
            if inv is None:
                self._json(404, {"error": "scan not found"})
            else:
                self._json(200, inv)
        elif parsed.path == "/api/risk":
            risk = self.service.risk_summary(query.get("scan_id", [""])[0])
            if risk is None:
                self._json(404, {"error": "scan not found"})
            else:
                self._json(200, risk)
        elif parsed.path == "/api/finding":
            try:
                index = int(query.get("index", [""])[0])
            except (ValueError, TypeError):
                self._json(400, {"error": "index must be an integer"})
                return
            detail = self.service.finding_detail(query.get("scan_id", [""])[0], index)
            if detail is None:
                self._json(404, {"error": "finding not found"})
            else:
                self._json(200, detail)
        elif parsed.path == "/api/assets":
            assets = self.service.assets(query.get("scan_id", [""])[0])
            if assets is None:
                self._json(404, {"error": "scan not found"})
            else:
                self._json(200, assets)
        elif parsed.path == "/api/graph":
            self._json(200, self.service.graph())
        elif parsed.path == "/api/migration":
            plan = self.service.migration_plan(query.get("scan_id", [""])[0])
            if plan is None:
                self._json(404, {"error": "scan not found"})
            else:
                self._json(200, plan)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/scans":
            self._json(404, {"error": "not found"})
            return
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        try:
            snap = self.service.submit(str(body.get("target", "")))
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, snap)


def make_server(
    db_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 0,
    client=None,
) -> ThreadingHTTPServer:
    """Build (not start) the loopback-only GUI server. Port 0 = ephemeral."""
    check_host(host)
    service = GuiService(db_path, client=client)
    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    server.gui_service = service  # type: ignore[attr-defined]
    return server
