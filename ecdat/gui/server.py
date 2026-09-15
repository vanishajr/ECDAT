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


FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect x="2" y="2" width="28" height="28" rx="6" fill="#1D4ED8"/>'
    '<text x="16" y="22.5" font-family="system-ui,sans-serif" '
    'font-size="17" font-weight="700" fill="#ffffff" '
    'text-anchor="middle">E</text></svg>'
)


def _legal_page(title: str, heading: str, paragraphs: list[str]) -> str:
    """Minimal standalone page (privacy/terms). Same light theme, no assets."""
    body = "".join(f"<p>{esc(p)}</p>" for p in paragraphs)
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">'
        f"<title>{esc(title)} — ECDAT Local GUI</title>"
        "<style>body{background:#F2F4F7;color:#101828;"
        "font-family:system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;"
        "font-size:14px;line-height:1.6;margin:0}"
        ".wrap{max-width:720px;margin:0 auto;padding:32px 20px}"
        ".card{background:#fff;border:1px solid #DDE1E7;border-radius:6px;"
        "padding:24px 28px}h1{font-size:20px;margin:0 0 8px}"
        ".meta{color:#667085;font-size:12px;margin:0 0 16px}"
        "a{color:#1849A9}.back{display:inline-block;margin-top:16px}</style>"
        "</head><body><main class=\"wrap\"><div class=\"card\">"
        f"<h1>{esc(heading)}</h1>"
        "<p class=\"meta\">ECDAT Local GUI · mock-first evaluation build</p>"
        f"{body}"
        "<a class=\"back\" href=\"/\">Back to dashboard</a>"
        "</div></main></body></html>"
    )


PRIVACY_PARAGRAPHS = [
    "ECDAT is a local evaluation tool. The dashboard binds to a loopback "
    "address only (127.0.0.1) and makes no external network requests.",
    "What stays on this machine: scan targets you enter, scan results in "
    "the local SQLite database you choose, and reports you generate. "
    "Demo mode seeds a fresh temporary workspace on each run.",
    "There is no analytics, no telemetry, no advertising, no cookies, "
    "and no account system. Nothing is uploaded anywhere.",
    "To remove scan data, delete the database file or temporary "
    "workspace printed in the terminal when the demo starts.",
]

TERMS_PARAGRAPHS = [
    "ECDAT is a mock-first evaluation build. Detection, risk scoring, "
    "graph, and migration outputs are deterministic placeholders, "
    "labeled mock, until the real engines are integrated. Do not rely "
    "on them for production security decisions.",
    "The software is provided as-is, without warranty of any kind. It "
    "runs locally only and must not be exposed to a network.",
    "Reports and exports are generated locally from stored mock scans. "
    "You are responsible for how you store and share them.",
]


def index_page(prefill_target: str = "") -> str:
    """Self-contained dashboard page. No external assets, no framework.

    Dynamic scan data is rendered client-side with textContent (never
    with direct markup sinks), so canonical text cannot break out of
    the page. Only the optional prefill value is server-injected,
    via esc().

    NOTE: this is a raw string so JS "\\n" escapes survive intact.
    """
    page = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<title>ECDAT Local GUI — Cryptographic Discovery and Analysis</title>
<style>
:root{
color-scheme:light;
--bg:#F2F4F7; --surface:#FFFFFF; --raised:#F8FAFC; --border:#DDE1E7; --border-strong:#C4CCD6;
--text:#101828; --muted:#475467; --faint:#667085;
--accent:#1D4ED8; --accent-dark:#1849A9; --accent-tint:#EFF4FF; --accent-border:#B2CCFF;
--crit:#B42318; --crit-bg:#FEF3F2; --crit-border:#FECDCA;
--high:#B54708; --high-bg:#FFF6ED; --high-border:#F9DBAF;
--med:#A16207; --med-bg:#FFFAEB; --med-border:#FEDF89;
--low:#027A48; --low-bg:#ECFDF3; --low-border:#ABEFC6;
--info:#475467; --info-bg:#F2F4F7; --info-border:#DDE1E7;
--r-lg:6px; --r-md:4px; --r-sm:3px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:13px;line-height:1.5;overflow-x:hidden}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}
.skip{position:absolute;left:-9999px;top:0;background:var(--accent);color:#fff;padding:.5em 1em;font-weight:700;z-index:99}
.skip:focus{left:0}
.app{display:flex;min-height:100vh}
/* ---- sidebar ---- */
.side{width:232px;flex:0 0 232px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.brand{padding:18px 16px 14px;border-bottom:1px solid var(--border)}
.brandmark{display:flex;align-items:center;gap:.6em;font-weight:700;font-size:15px;letter-spacing:.02em}
.brandmark .gem{width:28px;height:28px;border-radius:var(--r-md);background:var(--accent);display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:14px;font-weight:700}
.brandsub{font-size:11px;color:var(--muted);margin-top:6px;line-height:1.45}
.nav{display:flex;flex-direction:column;gap:2px;padding:12px 8px}
.nav a{display:flex;align-items:center;gap:.7em;padding:.55em .8em;border-radius:var(--r-md);color:var(--muted);text-decoration:none;font-size:13px;border-left:3px solid transparent;min-height:36px}
.nav a:hover{background:var(--raised);color:var(--text)}
.nav a.active{background:var(--accent-tint);color:var(--accent-dark);font-weight:600;border-left-color:var(--accent)}
.sidefoot{margin-top:auto;padding:14px 16px;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}
.dotlive{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--low);margin-right:.5em}
.mockline{color:var(--med);font-size:11px;margin-top:2px}
/* ---- main column ---- */
.maincol{flex:1;min-width:0;display:flex;flex-direction:column}
.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:12px;padding:10px 24px;background:var(--surface);border-bottom:1px solid var(--border)}
.top input[type=text]{flex:1;max-width:34em;background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--r-md);color:var(--text);padding:.55em .9em;font-size:13px}
.top input::placeholder{color:var(--faint)}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:.2em .6em;border-radius:var(--r-sm);background:var(--med-bg);border:1px solid var(--med-border);color:#93370D;white-space:nowrap}
.badge.blue{background:var(--accent-tint);border-color:var(--accent-border);color:var(--accent-dark)}
.badge.violet{background:var(--info-bg);border-color:var(--info-border);color:var(--info)}
.topsp{flex:1}
.loopnote{font-size:12px;color:var(--faint);white-space:nowrap}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:16px;padding:24px;max-width:1200px;width:100%;margin:0 auto}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:18px 20px;min-width:0}
.card h2{font-size:14px;margin:0 0 4px;letter-spacing:.01em;font-weight:700}
.card h3{font-size:13px;margin:14px 0 6px}
.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);margin:0 0 8px;font-weight:600}
.note{font-size:12px;color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.span12{grid-column:span 12}.span8{grid-column:span 8}.span6{grid-column:span 6}.span4{grid-column:span 4}.span3{grid-column:span 3}
section[id],details[id]{scroll-margin-top:76px}
/* ---- scan ---- */
.scanbar{grid-column:span 12}
.scanrow{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;margin-top:12px}
.field{display:flex;flex-direction:column;gap:6px;flex:1;min-width:200px}
.field label{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--faint);font-weight:700}
.field input[type=text],.field select{background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--r-md);color:var(--text);padding:.6em .8em;font-size:13px;width:100%}
.btnrow{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button{font-size:13px;border-radius:var(--r-md);cursor:pointer;padding:.6em 1.1em}
button.primary{background:var(--accent);border:1px solid var(--accent);color:#fff;font-weight:600}
button.primary:hover{background:var(--accent-dark);border-color:var(--accent-dark)}
button.ghost{background:var(--surface);border:1px solid var(--border-strong);color:var(--text)}
button.ghost:hover{border-color:var(--accent);color:var(--accent-dark)}
button:disabled{opacity:.55;cursor:default}
button.small{padding:.35em .8em;font-size:12px}
.monitor{margin-top:14px;border-top:1px solid var(--border);padding-top:12px}
.ptrack{height:8px;background:var(--info-bg);border:1px solid var(--border);border-radius:var(--r-sm);overflow:hidden;margin:.5em 0}
.pfill{height:100%;background:var(--accent);border-radius:0;transform:scaleX(0);transform-origin:left center;transition:transform .25s ease}
.preview{background:var(--raised);border:1px solid var(--border);border-radius:var(--r-md);padding:.7em .9em;white-space:pre-wrap;font-size:12px;color:var(--muted)}
details.disc{margin-top:12px;border:1px solid var(--border);border-radius:var(--r-md);background:var(--surface)}
details.disc>summary{cursor:pointer;padding:.6em .9em;color:var(--accent-dark);font-size:12px;list-style:none}
details.disc>summary::-webkit-details-marker{display:none}
details.disc>summary:before{content:"+ ";color:var(--faint)}
details.disc[open]>summary:before{content:"- "}
details.disc .discbody{padding:0 12px 12px}
/* ---- KPIs ---- */
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:14px 16px;min-width:0}
.kpi .kl{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--faint);font-weight:600}
.kpi .kv2{font-size:28px;font-weight:700;margin:2px 0 4px;font-variant-numeric:tabular-nums}
.kpi .ksub{font-size:11px;color:var(--muted)}
.kpi svg{display:block;margin-top:6px}
.kpi .krow{display:flex;align-items:center;gap:.7em}
.kpi .kico{width:32px;height:32px;flex:0 0 32px;border-radius:var(--r-md);display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;border:1px solid var(--border);background:var(--raised);color:var(--muted)}
/* ---- risk ---- */
.riskwrap{display:grid;grid-template-columns:220px 1fr;gap:16px;align-items:start}
.donutcenter{font-size:22px;font-weight:700;fill:var(--text);font-variant-numeric:tabular-nums}
.donutsub{font-size:11px;fill:var(--muted)}
.risklegend{display:flex;flex-direction:column;gap:6px;margin-top:4px}
.risklegend button{display:flex;align-items:center;gap:.6em;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);color:var(--text);padding:.45em .7em;font-size:12px;text-align:left}
.risklegend button.active{border-color:var(--accent);background:var(--accent-tint)}
.rdot{width:9px;height:9px;border-radius:50%;flex:0 0 9px}
/* ---- tables ---- */
.tblwrap{overflow-x:auto;margin:8px -4px;padding:0 4px}
table.tbl{border-collapse:collapse;width:100%;font-size:13px;min-width:560px}
table.tbl th{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--faint);font-weight:700;text-align:left;padding:.5em .6em;border-bottom:1px solid var(--border-strong);white-space:nowrap}
table.tbl td{padding:.55em .6em;border-bottom:1px solid var(--border);vertical-align:middle}
table.tbl tr:last-child td{border-bottom:none}
tr.clickable{cursor:pointer}
tr.clickable:hover td{background:var(--raised)}
tr.clickable:focus-visible{outline:2px solid var(--accent)}
.sev{display:inline-flex;align-items:center;gap:.45em;font-weight:700;font-size:12px;border-radius:var(--r-sm);padding:.15em .6em;white-space:nowrap;border:1px solid transparent}
.sev:before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor}
.sev-critical{background:var(--crit-bg);color:var(--crit);border-color:var(--crit-border)}
.sev-high{background:var(--high-bg);color:var(--high);border-color:var(--high-border)}
.sev-medium{background:var(--med-bg);color:var(--med);border-color:var(--med-border)}
.sev-low{background:var(--low-bg);color:var(--low);border-color:var(--low-border)}
.sev-info,.sev-none{background:var(--info-bg);color:var(--info);border-color:var(--info-border)}
.conf{display:inline-flex;align-items:center;gap:.5em}
.confbar{width:40px;height:5px;border-radius:var(--r-sm);background:#EAECF0;overflow:hidden;flex:0 0 40px}
.confbar>i{display:block;height:100%;background:var(--accent);transform-origin:left center}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:.5em 0}
.chip{background:var(--raised);border:1px solid var(--border);border-radius:var(--r-sm);padding:.2em .7em;font-size:12px;color:var(--muted)}
.tiles{display:flex;gap:8px;flex-wrap:wrap;margin:.5em 0}
.tile{border:1px solid var(--border-strong);background:var(--surface);border-radius:var(--r-md);padding:.45em .9em;cursor:pointer;font-size:12px;color:var(--text)}
.tile b{display:block;font-size:16px;font-variant-numeric:tabular-nums}
.tile:hover{border-color:var(--accent)}
.tile.active{border-color:var(--accent);background:var(--accent-tint)}
.row{display:flex;gap:.6em;margin-top:.7em;flex-wrap:wrap;align-items:center}
#error{color:var(--crit);font-weight:600}
.kv{display:grid;grid-template-columns:11em 1fr;gap:.25em .8em;font-size:12px;margin:.5em 0}
.kv dt{font-weight:600;color:var(--muted)}
.kv dd{margin:0;overflow-wrap:anywhere}
.avail{font-size:12px;color:var(--muted)}
.empty{border:1px dashed var(--border-strong);border-radius:var(--r-lg);padding:26px 18px;text-align:center;color:var(--muted);font-size:12px;background:var(--surface)}
.empty .cta{margin-top:8px}
.empty h4{margin:.2em 0 .3em;font-size:14px;color:var(--text)}
.empty .esteps{list-style:none;display:flex;gap:8px;justify-content:center;margin:12px 0 0;padding:0;flex-wrap:wrap}
.empty .esteps li{font-size:11px;color:var(--faint);border:1px solid var(--border);border-radius:var(--r-sm);padding:.25em .7em}
.empty .esteps b{color:var(--accent-dark);font-weight:700;margin-right:.4em}
code{font-size:12px;background:var(--raised);border:1px solid var(--border);padding:.1em .35em;border-radius:var(--r-sm)}
/* ---- graph ---- */
#gwrap{position:relative;border:1px solid var(--border);border-radius:var(--r-md);overflow:hidden;background:#fff}
#graph{display:block;cursor:grab;touch-action:none;width:100%;height:520px}
#graph text{font-family:inherit;pointer-events:none}
.govlay{position:absolute;left:10px;bottom:8px;font-size:11px;color:var(--muted);background:#fff;border:1px solid var(--border);border-radius:var(--r-sm);padding:.15em .7em;pointer-events:none}
.gnode{cursor:pointer}
.gnode circle.core{fill:#fff;stroke-width:2}
.gnode circle.selring{fill:none;stroke:var(--accent);stroke-width:2}
.gnode circle.tracering{fill:none;stroke:var(--accent);stroke-width:1.5}
.gnode text.nlabel{font-size:12px;fill:#101828;paint-order:stroke;stroke:#fff;stroke-width:3px;font-weight:600}
.gnode:focus{outline:none}
.gnode:focus-visible circle.core{stroke:var(--accent);stroke-width:2.5}
.gnode.dim,.gedge.dim,.glabel.dim{opacity:.15}
.gedge{stroke:#B6BFCB;stroke-width:1.25;opacity:.9;cursor:pointer}
.gedge.risky{stroke:var(--crit);stroke-width:1.75;opacity:.95}
.gedge.trace{stroke:var(--accent);stroke-width:2.75;opacity:1}
.gedge.selected{stroke:var(--accent);stroke-width:2.5}
.gedge.dim{stroke:#B6BFCB;stroke-width:1.25;opacity:.45}
.gedge-hit{stroke:rgba(0,0,0,0);stroke-width:14;cursor:pointer}
.glabel{font-size:10px;fill:#667085}
#graph[data-z="out"] .eldetail{display:none}
.glegend{display:flex;flex-direction:column;gap:8px;font-size:12px;color:var(--muted)}
.glegend .cap{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--faint);font-weight:600}
.glegend .li{display:flex;align-items:center;gap:.55em}
.glegend .sw{width:10px;height:10px;border-radius:50%;flex:0 0 10px}
.glegend .ln{width:16px;height:0;border-top:2px solid var(--accent);flex:0 0 16px}
.glegend .rg{width:10px;height:10px;border-radius:50%;border:2px solid var(--accent);flex:0 0 10px;background:transparent}
.gcontrols{display:flex;gap:6px;flex-wrap:wrap}
label.chk{display:inline-flex;align-items:center;gap:.45em;font-size:12px;color:var(--muted);font-weight:400}
input[type=checkbox]{accent-color:var(--accent)}
/* cross-link buttons */
button.xlink{background:var(--surface);border:1px solid var(--accent);color:var(--accent-dark)}
details.graphdisc{margin-top:0}
/* ---- overview header ---- */
.kicker{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--faint);margin:0 0 6px;font-weight:600}
.display{font-size:20px;line-height:1.3;margin:.1em 0 .3em;letter-spacing:0;font-weight:700}
.hero{grid-column:span 12;border:1px solid var(--border);border-radius:var(--r-lg);padding:20px 22px 18px;background:var(--surface)}
.hero .hsub{color:var(--muted);font-size:13px;max-width:70em;margin:0 0 12px}
.hstats{display:flex;gap:0;flex-wrap:wrap;align-items:stretch;margin-top:12px;border:1px solid var(--border);border-radius:var(--r-md);background:var(--surface)}
.hstat{flex:1;min-width:150px;padding:.7em 1em;border-left:1px solid var(--border)}
.hstat:first-child{border-left:none}
.hstat .hk{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--faint);font-weight:600}
.hstat .hv{font-size:15px;font-weight:700;margin-top:2px;overflow-wrap:anywhere}
.hstat .hv.mono{font-size:13px;font-weight:600}
.hero .hcta{margin-top:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
/* scan pipeline */
.pipe{list-style:none;display:flex;gap:0;margin:14px 0 2px;padding:0;flex-wrap:wrap}
.pipe li{flex:1;min-width:130px;display:flex;align-items:center;gap:.55em;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);padding:.4em .2em;border-top:2px solid var(--border);font-weight:600}
.pipe li .pd{width:9px;height:9px;border-radius:50%;border:2px solid var(--faint);flex:0 0 9px}
.pipe li.done{color:var(--muted);border-top-color:var(--accent)}
.pipe li.done .pd{background:var(--accent);border-color:var(--accent)}
.pipe li.live{color:var(--text);border-top-color:var(--accent)}
.pipe li.live .pd{border-color:var(--accent);background:var(--accent-tint)}
/* risk bars */
.rbars{display:flex;flex-direction:column;gap:6px;margin:.6em 0}
.rbar{display:flex;align-items:center;gap:.6em;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);color:var(--text);padding:.35em .6em;font-size:12px;text-align:left;width:100%}
.rbar:hover{border-color:var(--accent)}
.rbar.on{border-color:var(--accent);background:var(--accent-tint)}
.rbar .rl{flex:0 0 64px;color:var(--muted);text-transform:capitalize}
.rbar .rt{flex:1;height:6px;border-radius:var(--r-sm);background:#EAECF0;overflow:hidden}
.rbar .rt>i{display:block;height:100%;transform-origin:left center}
.rbar .rn{flex:0 0 30px;text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
/* graph stage */
.stage{border-radius:var(--r-lg)}
.stage h2{font-size:14px}
/* motion: subtle, usability only */
button{transition:border-color .12s ease,background .12s ease,color .12s ease}
.nav a{transition:background .12s ease,color .12s ease}
@media (max-width:900px){
#graph{height:440px}
.display{font-size:18px}
.hero{padding:16px}
.hstat{min-width:44%}
.hstat:nth-child(3){border-left:none}
}
/* ---- scan form layout ---- */
.scanrow>.field.f-target{flex:2 1 260px}
.scanrow>.field.f-opt{flex:1 1 130px;min-width:0}
/* session activity feed */
.feed{list-style:none;margin:.6em 0 0;padding:0;display:flex;flex-direction:column}
.feed li{display:flex;gap:.7em;align-items:flex-start;padding:.55em 0;border-bottom:1px solid var(--border)}
.feed li:last-child{border-bottom:none}
.feed .fico{width:28px;height:28px;flex:0 0 28px;border-radius:var(--r-md);border:1px solid var(--border);background:var(--raised);display:inline-flex;align-items:center;justify-content:center;font-size:13px;color:var(--muted)}
.feed .ft{flex:1;min-width:0;font-size:12px}
.feed .ft b{display:block;font-weight:600}
.feed .ft span{color:var(--muted);font-size:11px;overflow-wrap:anywhere}
.feed .ftime{flex:0 0 auto;font-size:11px;color:var(--faint)}
.feed .fpill{flex:0 0 auto;font-size:10px;font-weight:700;border:1px solid var(--border);border-radius:var(--r-sm);padding:.1em .6em;color:var(--muted)}
/* risk rail */
#sec-risk .riskwrap{grid-template-columns:1fr;justify-items:center}
#sec-risk .riskwrap>div{width:100%;max-width:300px}
#sec-risk .risklegend{width:100%}
/* ---- workflow rail ---- */
.wflow{grid-column:span 12;display:flex;gap:8px;flex-wrap:wrap;align-items:stretch;margin:0;padding:0;list-style:none}
.wflow a{flex:1;min-width:140px;display:flex;gap:.6em;align-items:center;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);padding:.55em .8em;color:var(--muted);text-decoration:none;font-size:12px}
.wflow a:hover{border-color:var(--accent);color:var(--text)}
.wflow a .wn{flex:0 0 22px;width:22px;height:22px;border-radius:var(--r-sm);border:1px solid var(--border-strong);display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--faint);background:var(--raised)}
.wflow a.done{border-color:var(--accent-border)}
.wflow a.done .wn{background:var(--accent);border-color:var(--accent);color:#fff}
.wflow a .wt b{display:block;font-size:12px;color:var(--text);font-weight:700}
.wflow a .wt span{font-size:11px;color:var(--faint)}
.nextsteps{margin-top:12px;border:1px solid var(--accent-border);border-radius:var(--r-md);padding:.7em .9em;background:var(--accent-tint)}
.nextsteps p{margin:.2em 0 .6em;font-size:12px;color:var(--muted)}
.nextsteps .row{margin-top:0}
.bridge{margin:.6em 0 0;border:1px solid var(--border);border-radius:var(--r-md);padding:.6em .8em;background:var(--raised)}
.bridge p{margin:.2em 0 .5em;font-size:12px;color:var(--muted)}
.ctxnote{font-size:11px;color:var(--faint)}
.fsec{margin:.7em 0 0}
.fsec>h4{margin:.6em 0 .3em;font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--faint)}
.fsec code{display:block;white-space:pre-wrap;margin-top:.4em}
@media (max-width:900px){
.wflow a{min-width:44%}
}
/* ---- footer note ---- */
.foot{grid-column:span 12;color:var(--faint);font-size:12px;padding:12px 2px;border-top:1px solid var(--border)}
.foot a{color:var(--accent-dark)}
.foot .fsep{margin:0 .6em}
@media (max-width:1100px){.span8,.span4{grid-column:span 12}.riskwrap{grid-template-columns:1fr}.span3{grid-column:span 6}}
@media (max-width:900px){
.side{width:64px;flex-basis:64px}
.brandsub,.nav a span.lbl,.sidefoot .txt,.loopnote{display:none}
.nav a{justify-content:center;border-left:none}
.brandmark span.t{display:none}
.grid{padding:16px}
.span3,.span6{grid-column:span 12}
.top{padding:10px 12px}
}
</style>
</head>
<body id="top">
<a class="skip" href="#main">Skip to main content</a>
<div class="app">
<aside class="side" aria-label="Primary">
<div class="brand">
<div class="brandmark"><span class="gem">E</span><span class="t">ECDAT</span></div>
<div class="brandsub">Enterprise Cryptographic<br>Discovery &amp; Analysis Tool</div>
</div>
<nav class="nav" id="mainnav">
<a href="#top" class="active"><span class="lbl">Overview</span></a>
<a href="#sec-scan"><span class="lbl">Scans</span></a>
<a href="#sec-inventory"><span class="lbl">Inventory</span></a>
<a href="#sec-risk"><span class="lbl">Risk</span></a>
<a href="#sec-graph"><span class="lbl">Graph</span></a>
<a href="#sec-migration"><span class="lbl">Migration</span></a>
<a href="#sec-reports"><span class="lbl">Reports</span></a>
</nav>
<div class="sidefoot"><span class="dotlive"></span><span class="txt">Loopback only<br></span><span class="mockline">Mock data</span></div>
</aside>
<div class="maincol">
<header class="top">
<input type="text" id="globalSearch" placeholder="Search targets, findings, assets..." aria-label="Search targets, findings, assets">
<span class="badge">MOCK / SIMULATED</span>
<span class="topsp"></span>
<span class="loopnote mono">127.0.0.1 · loopback only</span>
</header>
<main class="grid" id="main">
<section class="hero" aria-label="Overview">
<p class="kicker">ECDAT · local evaluation · mock data</p>
<h1 class="display">Overview</h1>
<p class="hsub">Discover cryptographic usage across source code, binaries, containers, certificates, and services. Run a scan to populate inventory, risk, and migration below. Nothing here is real detection until Person 1 / Person 2 integrate.</p>
<div class="hstats">
<div class="hstat" id="hero-scan-box"><div class="hk">Active target</div><div class="hv mono" id="hero-scan">No analysis yet</div></div>
<div class="hstat" id="hero-risk-box"><div class="hk">Risk posture</div><div class="hv" id="hero-risk">—</div></div>
<div class="hstat"><div class="hk">Findings</div><div class="hv" id="hero-find">—</div></div>
</div>
<div class="hcta">
<button class="primary" type="button" onclick="document.getElementById('sec-scan').scrollIntoView()">Start a scan</button>
<span class="note">Results are stored locally and feed the sections below.</span>
</div>
</section>
<nav class="wflow" aria-label="Analysis workflow">
<a href="#sec-scan" data-wf="scan"><span class="wn" aria-hidden="true">1</span><span class="wt"><b>Scan</b><span>mock target + plan</span></span></a>
<a href="#sec-inventory" data-wf="discovery"><span class="wn" aria-hidden="true">2</span><span class="wt"><b>Discovery</b><span>inventory + findings</span></span></a>
<a href="#sec-risk" data-wf="risk"><span class="wn" aria-hidden="true">3</span><span class="wt"><b>Risk</b><span>mock scoring</span></span></a>
<a href="#sec-graph" data-wf="graph"><span class="wn" aria-hidden="true">4</span><span class="wt"><b>Graph</b><span>mock topology</span></span></a>
<a href="#sec-migration" data-wf="migration"><span class="wn" aria-hidden="true">5</span><span class="wt"><b>Migration</b><span>mock triage</span></span></a>
<a href="#sec-reports" data-wf="report"><span class="wn" aria-hidden="true">6</span><span class="wt"><b>Report</b><span>export output</span></span></a>
</nav>
<section class="kpi span3"><p class="kl">Crypto Assets</p><div class="krow"><div class="kv2" id="kpi-assets">—</div></div><div class="ksub" id="kpi-assets-sub">Run a mock scan to populate</div><svg id="spark-assets" width="120" height="28" aria-hidden="true"></svg></section>
<section class="kpi span3"><p class="kl">Findings</p><div class="krow"><div class="kv2" id="kpi-findings">—</div></div><div class="ksub" id="kpi-findings-sub">Run a mock scan to populate</div><svg id="spark-findings" width="120" height="28" aria-hidden="true"></svg></section>
<section class="kpi span3"><p class="kl">High Risk</p><div class="krow"><div class="kv2" id="kpi-high">—</div></div><div class="ksub" id="kpi-high-sub">critical + high (mock)</div><svg id="spark-high" width="120" height="28" aria-hidden="true"></svg></section>
<section class="kpi span3"><p class="kl">Legacy Algorithms</p><div class="krow"><div class="kv2" id="kpi-legacy">—</div></div><div class="ksub" id="kpi-legacy-sub">distinct rules (mock)</div><svg id="spark-legacy" width="120" height="28" aria-hidden="true"></svg></section>
<section class="card span4" id="sec-risk" aria-label="Risk">
<p class="eyebrow">Risk · mock scoring</p>
<h2>Risk dashboard <span class="badge">MOCK SCORING MODEL</span></h2>
<p class="note">Severity-weighted mock score for the stored scan. Click a severity bar or rule to drill down to findings.</p>
<div class="riskwrap">
<div>
<svg id="riskDonut" width="200" height="170" role="img" aria-label="Risk distribution donut"></svg>
<div class="risklegend" id="riskTiles"></div>
</div>
<div>
<div class="preview" id="risk">No completed scan yet.</div>
<div class="rbars" id="riskBars"></div>
<div id="riskRules"></div>
<div class="bridge" id="riskGraphBridge">
<p class="note">Risk shows what is risky in this scan. The graph shows where similar primitives live in the scan-independent mock topology — rules marked ◈ have mock nodes.</p>
<div class="row">
<button id="riskGraphBtn" class="ghost small" type="button">Open dependency graph</button>
<button id="riskMigBtn" class="ghost small" type="button">Open migration triage</button>
</div>
</div>
</div>
</div>
</section>
<section class="card span4" id="sec-activity" aria-label="Activity">
<p class="eyebrow">Session</p>
<h2>Session activity</h2>
<p class="note">This session only — actions taken in this browser tab. No history is stored.</p>
<ul class="feed" id="activityFeed"><li><div class="ft"><b>No session activity yet</b><span>Generate a plan or start a scan to begin.</span></div></li></ul>
</section>
<section class="card span4" id="sec-scan" aria-label="Scans">
<p class="eyebrow">Scan · mock-first</p>
<h2>Scans</h2>
<p class="note">Pick a target, preview the scan plan, then run the mock scan. No real detection is performed. Localhost only.</p>
<div class="scanrow">
<div class="field f-target">
<label for="target">Select target</label>
<input type="text" id="target" value="__PREFILL__" placeholder="e.g. samples/rsa_small.py" class="mono">
<button id="sampleTarget" class="ghost small" type="button" style="align-self:flex-start;margin-top:.4em">Use sample target</button>
</div>
<div class="field f-opt">
<label for="scanProfile">Scan Profile</label>
<select id="scanProfile"><option>Standard</option><option>Deep</option><option>Quick</option></select>
</div>
<div class="field f-opt">
<label for="scanDepth">Scan Depth</label>
<select id="scanDepth"><option>Normal</option><option>Shallow</option><option>Full</option></select>
</div>
<div class="btnrow">
<button id="previewBtn" class="primary" type="button">Generate scan plan</button>
<button id="scanBtn" class="ghost" type="button">Start mock scan</button>
</div>
</div>
<ol class="pipe" id="scanPipe" aria-label="Scan pipeline">
<li id="st-target" class="live"><span class="pd"></span>Target</li>
<li id="st-plan"><span class="pd"></span>Scan plan</li>
<li id="st-analysis"><span class="pd"></span>Analysis</li>
<li id="st-results"><span class="pd"></span>Results</li>
</ol>
<div class="monitor">
<p class="eyebrow">Live scan monitor (simulated)</p>
<p class="note">Simulated progress (mock): queued &rarr; scanning &rarr; completed. Staged for UI purposes only &mdash; the mock scan itself is instantaneous.</p>
<div class="ptrack" role="progressbar" aria-label="Scan progress"><div class="pfill" id="bar"></div></div>
<div class="preview" id="job">No job yet.</div>
<div class="nextsteps" id="scanDone" hidden>
<p class="note" id="scanDoneText">Results feed the inventory below.</p>
<div class="row">
<button id="scanDoneInv" class="primary small" type="button">View crypto inventory</button>
<button id="scanDoneRisk" class="ghost small" type="button">Open risk dashboard</button>
</div>
</div>
<details class="disc"><summary>Scan-plan preview (read-only, mock)</summary><div class="discbody"><div class="preview" id="preview">No preview yet. Enter a target and choose preview.</div></div></details>
</div>
</section>
<section class="card span8" id="sec-inventory" aria-label="Inventory">
<p class="eyebrow">Findings</p>
<h2>Crypto inventory</h2>
<p class="note">Findings for the stored scan, with algorithm, location, confidence, and evidence. Click a finding row to open its detail below. Click risk tiles or rule buttons to drill down.</p>
<div class="row">
<button id="invRiskBtn" class="ghost small" type="button">Open risk dashboard</button>
<span class="ctxnote" id="invCtx">Risk reflects this inventory.</span>
</div>
<div class="chips" id="chips"></div>
<div class="row" id="filterRow" style="display:none">
<button id="clearFilters" class="ghost small" type="button">Clear filters</button>
</div>
<div class="tblwrap" id="inventory"><div class="empty"><h4>No scan data available</h4>Select a target to begin cryptographic discovery.<ul class="esteps"><li><b>01</b>Target</li><li><b>02</b>Generate plan</li><li><b>03</b>Start scan</li></ul></div></div>
<div id="error" role="alert"></div>
<h3>Finding detail</h3>
<div id="detail"><p class="note">Select a finding row in the inventory to see its evidence, confidence, and provenance.</p></div>
</section>
<section class="card span12 stage" id="sec-graph" aria-label="Graph">
<p class="eyebrow">Dependencies · scan-independent mock topology</p>
<h2>Crypto Knowledge Graph <span class="badge">MOCK DATASET</span></h2>
<p class="note">Deterministic mock graph for UI development — not scan data and not Person 1 CIR. Drag to pan, scroll to zoom, click nodes and edges. Node rings use severity colors.</p>
<p class="note ctxnote" id="graphCtx">Graph is scan-independent mock topology; inventory filters do not alter it.</p>
<div class="row">
<input type="text" id="gsearch" placeholder="filter: e.g. RSA, tls, aws" style="max-width:22em;background:var(--surface);border:1px solid var(--border-strong);border-radius:4px;color:var(--text);padding:.5em .7em" aria-label="Filter graph">
<label class="chk"><input type="checkbox" id="grisky"> risky only</label>
<button id="greset" class="ghost small" type="button">Reset view</button>
<button id="gtrace" type="button" class="small" style="background:var(--surface);border:1px solid var(--accent);color:var(--accent-dark)">Trace: internet → risk</button>
<span class="gcontrols">
<button id="gzin" class="ghost small" type="button" aria-label="Zoom in">+</button>
<button id="gzout" class="ghost small" type="button" aria-label="Zoom out">−</button>
<button id="gfit" class="ghost small" type="button">Fit</button>
</span>
</div>
<div class="chips" id="gtypes"></div>
<div id="gwrap">
<svg id="graph" role="img" aria-label="crypto knowledge graph"></svg>
<div class="govlay mono" id="govlay">mock graph</div>
</div>
<div class="row">
<div id="gdetail" style="flex:1;min-width:16em"><p class="note">Select a node or edge.</p></div>
<div class="glegend" id="glegend" aria-label="Graph legend"></div>
</div>
</section>
<section class="card span4" id="sec-side" aria-label="Context">
<p class="eyebrow">Assets</p>
<h2>Asset summary</h2>
<div id="assets"><div class="empty"><h4>No scan data available</h4>Asset inventory appears after the first mock scan.</div></div>
<div class="preview" id="graphState">Dependency edges: awaiting Person 1 edge data.</div>
</section>
<details class="card span12 disc" id="sec-assets">
<summary style="cursor:pointer;color:var(--accent-dark);font-size:13px">Crypto asset inventory + finding grouping (details)</summary>
<div class="note" style="margin:.4em 0">Flat asset inventory &mdash; relationships not available yet. Co-occurrence grouping &mdash; not a dependency graph.</div>
<div id="assetsFull"><p class="note">Open a scan to expand grouped assets here.</p></div>
</details>
<section class="card span6" id="sec-migration">
<p class="eyebrow">Migration</p>
<h2>Migration Planner <span class="badge">MOCK / PLACEHOLDER</span></h2>
<div class="note" style="margin:.4em 0">Severity triage of existing mock recommendations — heaviest first. This is triage by current finding severity, NOT a migration sequence.</div>
<p class="note ctxnote" id="migrationRisk">Migration triage follows the current risk level once a scan completes.</p>
<div id="migration"><div class="empty"><h4>No migration recommendations yet</h4>Migration triage appears after the first mock scan.</div></div>
<div class="row">
<button id="migRepBtn" class="ghost small" type="button">Export via Reports</button>
</div>
<div class="preview" id="migration-missing">Not included yet: PQC target selection; migration timelines; effort estimates; phased sequencing; migration confidence; real migration state. All await Person 1 migration intelligence.</div>
</section>
<section class="card span6" id="sec-reports">
<p class="eyebrow">Output</p>
<h2>Reports</h2>
<div class="note" style="margin:.4em 0">Final output of the workflow: scan &rarr; discovery &rarr; risk &rarr; dependencies &rarr; migration &rarr; export. Card 10. Reports render the stored mock scan through the existing report/export renderers. Nothing new is calculated here; risk and migration stay mock-labeled.</div>
<div id="reports"><div class="empty"><h4>No scan data available</h4>Reports unlock after the first mock scan.</div></div>
<div class="row">
<button id="repMigBtn" class="ghost small" type="button">Review migration triage</button>
<button id="repGraphBtn" class="ghost small" type="button">Open dependency graph</button>
</div>
</section>
<div class="foot">Local-only mock platform. No new analysis is performed in the GUI; all intelligence labels stay mock until Person 1 / Person 2 integrate.<span class="fsep">·</span><a href="/privacy">Privacy Policy</a><span class="fsep">·</span><a href="/terms">Terms and Conditions</a></div>
</main>
</div>
</div>
<script>
"use strict";
function $(id){return document.getElementById(id);}
function showError(msg){$("error").textContent = msg || "";}
function setBar(pct){var b=$("bar");if(b){b.style.transform="scaleX("+Math.max(0,Math.min(1,pct))+")";}}
async function api(path, opts){
  const res = await fetch(path, opts);
  const data = await res.json();
  if(!res.ok){ throw new Error(data.error || ("request failed: " + res.status)); }
  return data;
}
/* nav active + open closed detail targets */
(function(){
  var nav=$("mainnav");
  if(!nav){return;}
  var links=nav.querySelectorAll("a");
  function openFor(hash){
    if(!hash){return;}
    var t=document.querySelector(hash);
    if(t && t.tagName==="DETAILS" && !t.open){t.open=true;}
  }
  links.forEach(function(a){
    a.addEventListener("click",function(){
      links.forEach(function(x){x.classList.remove("active");});
      a.classList.add("active");
      openFor(a.getAttribute("href"));
    });
  });
})();
function profDepthSuffix(){
  try{
    var p=$("scanProfile")?$("scanProfile").value:"Standard";
    var d=$("scanDepth")?$("scanDepth").value:"Normal";
    return "\nprofile: "+p+"\ndepth: "+d+" (display only; mock scan ignores profile/depth)";
  }catch(e){return "";}
}
try{$("sampleTarget").addEventListener("click", function(){
  $("target").value = "samples/rsa_small.py";
  $("target").focus();
  setPipe("target");
});}catch(e){}
function go(id){ try{ document.getElementById(id).scrollIntoView(); }catch(e){} }
try{$("scanDoneInv").addEventListener("click", function(){ go("sec-inventory"); });}catch(e){}
try{$("scanDoneRisk").addEventListener("click", function(){ go("sec-risk"); });}catch(e){}
try{$("invRiskBtn").addEventListener("click", function(){ go("sec-risk"); });}catch(e){}
try{$("riskGraphBtn").addEventListener("click", function(){ go("sec-graph"); });}catch(e){}
try{$("riskMigBtn").addEventListener("click", function(){ go("sec-migration"); });}catch(e){}
try{$("migRepBtn").addEventListener("click", function(){ go("sec-reports"); });}catch(e){}
try{$("repMigBtn").addEventListener("click", function(){ go("sec-migration"); });}catch(e){}
try{$("repGraphBtn").addEventListener("click", function(){ go("sec-graph"); });}catch(e){}
$("previewBtn").addEventListener("click", async function(){  showError("");
  const t = $("target").value.trim();
  try{
    const p = await api("/api/preview?target=" + encodeURIComponent(t));
    $("preview").textContent =
      "target: " + p.target + "\nmode: " + p.mode + " (" + p.client + ")\n" +
      "stages: " + p.stages.join(" -> ") + "\nstore: " + p.stores_through +
      "\nread-back: " + p.reads_back_through + "\nnote: " + p.note + profDepthSuffix();
    setPipe("plan");
    logAct("plan","Scan plan previewed",t);
    var det=$("preview").closest("details"); if(det){det.open=true;}
  }catch(e){ showError(String(e.message || e)); }
});
let timer = null;
let currentScanId = null;
let filterSev = null;
let filterRule = null;
let lastInv = null, lastRisk = null, lastAssets = null;
$("scanBtn").addEventListener("click", async function(){
  showError("");
  const t = $("target").value.trim();
  if(timer){ clearInterval(timer); timer = null; }
  try{
    const job = await api("/api/scans", {method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({target:t})});
    logAct("scan","Mock scan started",t);
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
      (j.scan_id ? "\nscan_id: " + j.scan_id : "") + (j.error ? "\nerror: " + j.error : "") + profDepthSuffix();
    if(j.status === "completed"){
      if(timer){ clearInterval(timer); timer = null; }
      currentScanId = j.scan_id;
      filterSev = null;
      filterRule = null;
      setPipe("results");
      logAct("done","Mock scan completed",j.target);
      showScanDone(j);
      loadInventory(j.scan_id);
      loadRisk(j.scan_id);
      loadAssets(j.scan_id);
      loadMigration(j.scan_id);
      loadReports(j.scan_id);
    }else if(j.status === "failed"){
      if(timer){ clearInterval(timer); timer = null; }
      setPipe("target");
      showError(j.error || "scan failed");
    }else{
      setPipe("analysis");
    }
  }catch(e){ if(timer){ clearInterval(timer); timer = null; } showError(String(e.message || e)); }
}
/* ---- KPI + donut (derived only from loaded scan payloads; no invented history) ---- */
var SEVC = {"critical":"#B42318","high":"#B54708","medium":"#A16207","low":"#027A48","info":"#667085"};
var SEVORDER = ["critical","high","medium","low","info"];
var PIPEIDS = ["st-target","st-plan","st-analysis","st-results"];
function setPipe(stage){
  var order = {"target":0,"plan":1,"analysis":2,"results":3};
  var idx = (stage in order) ? order[stage] : 0;
  PIPEIDS.forEach(function(id,i){
    var el = document.getElementById(id);
    if(!el){return;}
    el.classList.remove("live","done");
    if(i < idx){ el.classList.add("done"); }
    else if(i === idx){ el.classList.add("live"); }
  });
}
/* ---- Task 32 workflow cohesion (frontend-only, existing state) ---- */
function showScanDone(j){
  var box=$("scanDone"), txt=$("scanDoneText");
  if(!box||!txt){return;}
  txt.textContent = "Scan " + j.scan_id + " (" + j.target + ") completed. Results feed the inventory below — continue to discovery, then risk.";
  box.hidden = false;
}
function updateWorkflow(){
  var hasScan = !!currentScanId;
  var map = {"scan":hasScan,"discovery":!!lastInv,"risk":!!lastRisk,"graph":hasScan,"migration":hasScan,"report":hasScan};
  document.querySelectorAll(".wflow a").forEach(function(a){
    var k = a.getAttribute("data-wf");
    if(k && map[k]){ a.classList.add("done"); }
    else{ a.classList.remove("done"); }
  });
  var gc=$("graphCtx");
  if(gc){
    if(!hasScan){ gc.textContent = "Graph is scan-independent mock topology; inventory filters do not alter it."; }
    else{
      var parts = [];
      parts.push("Scan: " + (lastInv ? lastInv.target : "stored scan"));
      if(filterSev){ parts.push("inventory severity=" + filterSev); }
      if(filterRule){ parts.push("rule=" + filterRule); }
      parts.push("graph stays unfiltered mock topology.");
      gc.textContent = parts.join(" · ");
    }
  }
  var mr=$("migrationRisk");
  if(mr){
    if(lastRisk){ mr.textContent = "Current scan risk: " + lastRisk.level + " (" + lastRisk.score + ") over " + lastRisk.finding_count + " findings. Triage below follows severity weights — not a migration sequence."; }
    else if(hasScan){ mr.textContent = "Migration triage follows the current risk level once risk loads."; }
    else{ mr.textContent = "Migration triage follows the current risk level once a scan completes."; }
  }
  var ic=$("invCtx");
  if(ic){
    if(filterSev || filterRule){
      var bits = [];
      if(filterSev){ bits.push("severity=" + filterSev); }
      if(filterRule){ bits.push("rule=" + filterRule); }
      ic.textContent = "Filtered: " + bits.join(" + ") + ". Risk reflects the stored scan; inventory shows the subset.";
    }else{ ic.textContent = "Risk reflects this inventory."; }
  }
}
function graphRuleSet(){
  var s = {};
  try{
    if(GDATA && GDATA.nodes){ GDATA.nodes.forEach(function(n){ if(n.rule_id){ s[n.rule_id] = true; } }); }
  }catch(e){}
  return s;
}
function annotateRiskRules(scanId, host){
  var rules = graphRuleSet();
  if(!host){ host = $("riskRules"); }
  if(!host){ return; }
  var btns = host.querySelectorAll("button.tile");
  btns.forEach(function(b){
    var rid = b.getAttribute("data-rule");
    if(rid && rules[rid] && b.getAttribute("data-graphed") !== "1"){
      b.setAttribute("data-graphed","1");
      b.textContent = b.textContent + " ◈ graph";
      b.title = "Has mock topology nodes (scan-independent)";
    }
  });
}
function updateHero(){
  var hs=$("hero-scan"), hr=$("hero-risk"), hf=$("hero-find");
  if(!hs||!hr||!hf){return;}
  var sb=$("hero-scan-box"), rb=$("hero-risk-box");
  if(lastInv){
    hs.textContent = lastInv.target;
    sb.classList.add("hot"); sb.classList.remove("warn","crit");
  }else{ hs.textContent = "No analysis yet"; sb.classList.remove("hot","warn","crit"); }
  if(lastRisk){
    hr.textContent = lastRisk.level + " · " + lastRisk.score;
    rb.classList.remove("hot","warn","crit");
    if(lastRisk.level === "critical"){ rb.classList.add("crit"); }
    else if(lastRisk.level === "high"){ rb.classList.add("warn"); }
    else{ rb.classList.add("hot"); }
  }else{ hr.textContent = "—"; rb.classList.remove("hot","warn","crit"); }
  if(lastInv){ hf.textContent = String(lastInv.finding_count); }
  else if(lastRisk){ hf.textContent = String(lastRisk.finding_count); }
  else{ hf.textContent = "—"; }
}
function toggleSevFilter(scanId, sev){
  filterSev = (filterSev === sev) ? null : sev;
  loadInventory(scanId);
  loadRisk(scanId);
  document.getElementById("sec-inventory").scrollIntoView();
}
function renderRiskBars(r, scanId){
  var host=$("riskBars"); if(!host){return;}
  while(host.firstChild){host.removeChild(host.firstChild);}
  var max=1;
  SEVORDER.forEach(function(s){ max=Math.max(max, r.severity_counts[s]||0); });
  SEVORDER.forEach(function(sev){
    var v=r.severity_counts[sev]||0;
    var b=document.createElement("button");
    b.type="button";
    b.className="rbar"+((filterSev===sev)?" on":"");
    b.setAttribute("aria-pressed",(filterSev===sev)?"true":"false");
    var lab=document.createElement("span");lab.className="rl";lab.textContent=sev;
    var tr=document.createElement("span");tr.className="rt";
    var fill=document.createElement("i");
    fill.style.background=SEVC[sev];
    fill.style.transform="scaleX("+(v/max)+")";
    tr.appendChild(fill);
    var n=document.createElement("span");n.className="rn";n.textContent=String(v);
    b.appendChild(lab);b.appendChild(tr);b.appendChild(n);
    b.addEventListener("click",function(){ toggleSevFilter(scanId, sev); });
    host.appendChild(b);
  });
}
function spark(id, values, color){
  var svg=$(id); if(!svg){return;}
  while(svg.firstChild){svg.removeChild(svg.firstChild);}
  var ns=svg.namespaceURI;
  var vals=(values||[]).map(Number).filter(function(v){return isFinite(v);});
  if(!vals.length){vals=[0,0,0,0,0];}
  var max=Math.max.apply(null,vals.concat([1]));
  var pts=vals.map(function(v,i){
    var x=6+i*(108/Math.max(1,vals.length-1));
    var y=24-(v/max)*18;
    return x.toFixed(1)+","+y.toFixed(1);
  }).join(" ");
  var pl=document.createElementNS(ns,"polyline");
  pl.setAttribute("points",pts);
  pl.setAttribute("fill","none");
  pl.setAttribute("stroke",color);
  pl.setAttribute("stroke-width","1.6");
  svg.appendChild(pl);
}
function renderDonut(counts){
  var svg=$("riskDonut"); if(!svg){return;}
  while(svg.firstChild){svg.removeChild(svg.firstChild);}
  var ns=svg.namespaceURI;
  var total=SEVORDER.reduce(function(a,s){return a+(counts[s]||0);},0);
  var R=62,C=2*Math.PI*R,cx=80,cy=80,off=0;
  if(total===0){
    var bg=document.createElementNS(ns,"circle");
    bg.setAttribute("cx",cx);bg.setAttribute("cy",cy);bg.setAttribute("r",R);
    bg.setAttribute("fill","none");bg.setAttribute("stroke","#1E293B");bg.setAttribute("stroke-width","18");
    svg.appendChild(bg);
  }else{
    SEVORDER.forEach(function(sev){
      var v=counts[sev]||0; if(!v){return;}
      var frac=v/total;
      var c=document.createElementNS(ns,"circle");
      c.setAttribute("cx",cx);c.setAttribute("cy",cy);c.setAttribute("r",R);
      c.setAttribute("fill","none");c.setAttribute("stroke",SEVC[sev]);c.setAttribute("stroke-width","18");
      c.setAttribute("stroke-dasharray",(frac*C).toFixed(2)+" "+C.toFixed(2));
      c.setAttribute("stroke-dashoffset",(-off*C).toFixed(2));
      c.setAttribute("transform","rotate(-90 "+cx+" "+cy+")");
      svg.appendChild(c);
      off+=frac;
    });
  }
  var t1=document.createElementNS(ns,"text");
  t1.setAttribute("x",cx);t1.setAttribute("y",cy-2);t1.setAttribute("text-anchor","middle");
  t1.setAttribute("class","donutcenter");t1.textContent=String(total);
  var t2=document.createElementNS(ns,"text");
  t2.setAttribute("x",cx);t2.setAttribute("y",cy+16);t2.setAttribute("text-anchor","middle");
  t2.setAttribute("class","donutsub");t2.textContent="Findings";
  svg.appendChild(t1);svg.appendChild(t2);
}
function updateKpis(){
  var findings=lastInv?lastInv.finding_count:(lastRisk?lastRisk.finding_count:null);
  var assets=lastAssets?lastAssets.asset_count:null;
  var counts=lastRisk?lastRisk.severity_counts:(lastInv?lastInv.severity_counts:null);
  var highR=counts?((counts.critical||0)+(counts.high||0)):null;
  var legacy=(lastRisk&&lastRisk.by_rule)?lastRisk.by_rule.length:null;
  if(findings!==null&&findings!==undefined){$("kpi-findings").textContent=String(findings);$("kpi-findings-sub").textContent="mock findings in stored scan";}
  if(assets!==null&&assets!==undefined){$("kpi-assets").textContent=String(assets);$("kpi-assets-sub").textContent="flat CBOM-derived assets (mock)";}
  if(highR!==null&&highR!==undefined){$("kpi-high").textContent=String(highR);$("kpi-high-sub").textContent="critical + high (mock)";}
  if(legacy!==null&&legacy!==undefined){$("kpi-legacy").textContent=String(legacy);$("kpi-legacy-sub").textContent="distinct rules (mock)";}
  if(counts){spark("spark-findings",SEVORDER.map(function(s){return counts[s]||0;}),"#1D4ED8");}
  if(lastRisk&&lastRisk.by_rule){spark("spark-legacy",lastRisk.by_rule.map(function(r){return r.count;}),"#667085");}
  if(counts){spark("spark-high",[(counts.critical||0),(counts.high||0),(counts.medium||0),(counts.low||0)],"#B54708");}
  if(lastAssets&&lastAssets.groupings){spark("spark-assets",lastAssets.groupings.by_file.map(function(g){return g.count;}),"#1D4ED8");}
  updateHero();
  updateWorkflow();
}
function globalFilter(){
  var q="";
  try{q=$("globalSearch").value.trim().toLowerCase();}catch(e){q="";}
  var rows=document.querySelectorAll("#inventory tr[data-search]");
  rows.forEach(function(r){
    if(!q){r.style.display="";}
    else{r.style.display=(r.getAttribute("data-search").indexOf(q)>=0)?"":"none";}
  });
  try{if(document.activeElement===$("globalSearch")&&$("gsearch").value!==$("globalSearch").value){$("gsearch").value=$("globalSearch").value;renderGraph();}}catch(e){}
}
try{$("globalSearch").addEventListener("input",globalFilter);}catch(e){}
async function loadInventory(scanId){
  let path = "/api/inventory?scan_id=" + encodeURIComponent(scanId);
  if(filterSev){ path += "&severity=" + encodeURIComponent(filterSev); }
  if(filterRule){ path += "&rule=" + encodeURIComponent(filterRule); }
  const inv = await api(path);
  lastInv = inv;
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
    if(inv.filters && (inv.filters.severity || inv.filters.rule)){
      p.textContent = "No findings match the current filter. Clear filters to see the stored scan.";
    }else{
      p.textContent = "No findings for this scan. Risk scores 0 (none); migration has nothing to triage; reports render the empty scan.";
    }
    host.appendChild(p);
    updateKpis();globalFilter();
    return;
  }
  const table = document.createElement("table");
  table.className = "tbl";
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
    tr.setAttribute("tabindex","0");
    tr.setAttribute("data-search",(String(f.rule_id)+" "+String(f.file)+" "+String(f.title)+" "+String(f.severity)).toLowerCase());
    function open(){ loadFinding(currentScanId, f.index); }
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", function(ev){ if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();open();} });
    const sev = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev sev-" + String(f.severity);
    badge.textContent = String(f.severity);
    sev.appendChild(badge);
    tr.appendChild(sev);
    [["rule_id"],["file"],["line"],["title"]].forEach(function(k){
      const td = document.createElement("td");
      td.textContent = String(f[k[0]]);
      if(k[0]==="file"||k[0]==="rule_id"){td.className="mono";}
      tr.appendChild(td);
    });
    const conf = document.createElement("td");
    if(f.confidence === undefined || f.confidence === null){
      conf.textContent = "-";
    }else{
      const wrap=document.createElement("span");wrap.className="conf";
      const lab=document.createElement("span");lab.textContent=String(f.confidence);
      const bar=document.createElement("span");bar.className="confbar";
      const fill=document.createElement("i");
      var cv=Number(f.confidence); if(!isFinite(cv)){cv=0;} cv=Math.max(0,Math.min(1,cv));
      fill.style.transform="scaleX("+cv+")";
      bar.appendChild(fill);wrap.appendChild(lab);wrap.appendChild(bar);
      conf.appendChild(wrap);
    }
    tr.appendChild(conf);
    table.appendChild(tr);
    if(f.snippet){
      const srow = document.createElement("tr");
      const std = document.createElement("td");
      std.setAttribute("colspan", "6");
      const det = document.createElement("details");
      det.className="disc";
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
  updateKpis();globalFilter();
}
async function loadRisk(scanId){
  const r = await api("/api/risk?scan_id=" + encodeURIComponent(scanId));
  lastRisk = r;
  const tiles = $("riskTiles");
  while(tiles.firstChild){ tiles.removeChild(tiles.firstChild); }
  SEVORDER.forEach(function(sev){
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tile" + ((filterSev === sev) ? " active" : "");
    const n = document.createElement("b");
    n.textContent = String(r.severity_counts[sev]||0);
    const l = document.createElement("span");
    var dot=document.createElement("span");dot.className="rdot";dot.style.background=SEVC[sev];
    l.textContent = " " + sev;
    b.appendChild(n);
    var row=document.createElement("span");row.appendChild(dot);row.appendChild(l);
    b.appendChild(row);
    b.setAttribute("aria-pressed",(filterSev===sev)?"true":"false");
    b.addEventListener("click", function(){ toggleSevFilter(scanId, sev); });
    tiles.appendChild(b);
  });
  renderDonut(r.severity_counts);
  renderRiskBars(r, scanId);
  $("risk").textContent =
    "score: " + r.score + " / level: " + r.level + " (mock/placeholder)\n" +
    "findings: " + r.finding_count + "\nbreakdown: " +
    Object.keys(r.breakdown).sort().map(function(k){return k + "=" + r.breakdown[k];}).join(" ") +
    "\nmodel: " + r.model;
  const rules = $("riskRules");
  while(rules.firstChild){ rules.removeChild(rules.firstChild); }
  if(!r.by_rule.length){ updateKpis(); return; }
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
    b.setAttribute("data-rule", row.rule_id);
    b.setAttribute("aria-pressed", (filterRule === row.rule_id) ? "true" : "false");
    b.textContent = row.rule_id + " [" + row.severity + "] x" + row.count;
    b.addEventListener("click", function(){
      filterRule = (filterRule === row.rule_id) ? null : row.rule_id;
      loadInventory(scanId);
      loadRisk(scanId);
      document.getElementById("sec-inventory").scrollIntoView();
    });
    wrap.appendChild(b);
  });
  rules.appendChild(wrap);
  annotateRiskRules(scanId, rules);
  updateKpis();
}
async function loadFinding(scanId, idx){
  showError("");
  try{
    const d = await api("/api/finding?scan_id=" + encodeURIComponent(scanId) +
      "&index=" + encodeURIComponent(String(idx)));
    const host = $("detail");
    while(host.firstChild){ host.removeChild(host.firstChild); }
    const badge = document.createElement("span");
    badge.className = "badge blue";
    badge.textContent = d.provenance.status;
    host.appendChild(badge);
    const title = document.createElement("h3");
    title.textContent = d.finding.rule_id + ": " + d.finding.title;
    host.appendChild(title);
    function fsec(name){
      const s = document.createElement("div");
      s.className = "fsec";
      const h = document.createElement("h4");
      h.textContent = name;
      s.appendChild(h);
      host.appendChild(s);
      return s;
    }
    function fkv(scope, pairs){
      const dl = document.createElement("dl");
      dl.className = "kv";
      pairs.forEach(function(pair){
        const dt = document.createElement("dt");
        dt.textContent = pair[0];
        const dd = document.createElement("dd");
        dd.textContent = pair[1];
        if(pair[0]==="File"){dd.className="mono";}
        dl.appendChild(dt);
        dl.appendChild(dd);
      });
      scope.appendChild(dl);
      return dl;
    }
    const what = fsec("What");
    fkv(what, [["Rule", String(d.finding.rule_id)],
      ["Title", String(d.finding.title)],
      ["Severity", String(d.finding.severity) + " (mock severity; see risk dashboard)"]]);
    const where = fsec("Where");
    fkv(where, [["File", String(d.finding.file)],
      ["Line", String(d.finding.line)],
      ["Target", String(d.target)],
      ["Finding", "index " + d.index + " of " + d.finding_count + " in stored scan"]]);
    const why = fsec("Why it matters");
    fkv(why, [["Confidence", (d.finding.confidence === undefined || d.finding.confidence === null)
        ? "not provided (v1 optional)" : String(d.finding.confidence) + " (mock fixture value)"],
      ["Provenance", d.provenance.status + ". " + d.provenance.note]]);
    const ev = fsec("Evidence");
    if(d.finding.snippet === undefined || d.finding.snippet === null){
      fkv(ev, [["Snippet", "not provided (v1 optional)"]]);
    }else{
      const c = document.createElement("code");
      c.textContent = String(d.finding.snippet);
      ev.appendChild(c);
    }
    fkv(ev, [["Metadata", d.metadata_keys.length ? d.metadata_keys.join(", ") : "none in v1 doc"],
      ["Evidence available",
        Object.keys(d.evidence_available).map(function(k){return k + ": " + (d.evidence_available[k] ? "yes" : "no");}).join("; ")],
      ["Missing evidence", d.missing_evidence.length ? d.missing_evidence.join(", ") : "none"],
      ["Redaction", "applied: no. " + d.redaction.reason + " " + d.redaction.capability]
    ]);
    const nav = document.createElement("div");
    nav.className = "row";
    const rb = document.createElement("button");
    rb.type = "button";
    rb.className = "ghost small";
    rb.textContent = "Open risk dashboard (" + String(d.finding.severity) + ")";
    rb.addEventListener("click", function(){
      filterSev = String(d.finding.severity);
      if(currentScanId){ loadInventory(currentScanId); loadRisk(currentScanId); }
      document.getElementById("sec-risk").scrollIntoView();
    });
    nav.appendChild(rb);
    const ib = document.createElement("button");
    ib.type = "button";
    ib.className = "ghost small";
    ib.textContent = "Show rule in inventory";
    ib.addEventListener("click", function(){
      filterRule = String(d.finding.rule_id);
      if(currentScanId){ loadInventory(currentScanId); }
      document.getElementById("sec-inventory").scrollIntoView();
    });
    nav.appendChild(ib);
    host.appendChild(nav);
    const strip = document.createElement("p");
    strip.className = "note";
    strip.textContent = d.scan_provenance.started_at + " -> " +
      d.scan_provenance.finished_at + ". " + d.scan_provenance.label;
    host.appendChild(strip);
    document.getElementById("sec-inventory").scrollIntoView();
  }catch(e){ showError(String(e.message || e)); }
}
async function loadAssets(scanId){
  try{
    const a = await api("/api/assets?scan_id=" + encodeURIComponent(scanId));
    lastAssets = a;
    const host = $("assets");
    while(host.firstChild){ host.removeChild(host.firstChild); }
    const lab = document.createElement("p");
    lab.className = "note";
    lab.textContent = a.asset_label + " Assets: " + a.asset_count + ".";
    host.appendChild(lab);
    if(a.assets.length){
      const wrap=document.createElement("div");wrap.className="tblwrap";
      const table = document.createElement("table");
      table.className="tbl";
      const head = document.createElement("tr");
      ["Asset (bom-ref)","Name","Type","Evidence location"].forEach(function(h){
        const th = document.createElement("th");
        th.textContent = h;
        head.appendChild(th);
      });
      table.appendChild(head);
      a.assets.slice(0,5).forEach(function(c){
        const tr = document.createElement("tr");
        const ref = document.createElement("td");
        ref.textContent = String(c["bom-ref"]);ref.className="mono";
        tr.appendChild(ref);
        const nm = document.createElement("td");
        nm.textContent = String(c.name) + " (" + String(c.cryptoProperties.assetType) + ")";
        tr.appendChild(nm);
        const ty = document.createElement("td");
        ty.textContent = String(c.type);
        tr.appendChild(ty);
        const loc = document.createElement("td");
        loc.textContent = String(c.evidence.occurrences[0].location);loc.className="mono";
        tr.appendChild(loc);
        table.appendChild(tr);
      });
      wrap.appendChild(table);
      host.appendChild(wrap);
      if(a.assets.length>5){
        var more=document.createElement("p");more.className="note";
        more.textContent="Showing 5 of "+a.assets.length+". Open details below for grouping.";
        host.appendChild(more);
      }
    }else{
      const p = document.createElement("p");
      p.className = "note";
      p.textContent = "No crypto assets in this scan.";
      host.appendChild(p);
    }
    var full=$("assetsFull");
    if(full){
      while(full.firstChild){full.removeChild(full.firstChild);}
      const glab = document.createElement("p");
      glab.className = "note";
      glab.textContent = a.groupings.label;
      full.appendChild(glab);
      a.groupings.by_file.forEach(function(g){
        const h = document.createElement("h4");
        h.textContent = g.file + " x" + g.count;
        full.appendChild(h);
        const ul = document.createElement("ul");
        g.findings.forEach(function(f){
          const li = document.createElement("li");
          li.textContent = "[" + f.severity + "] " + f.rule_id + " line " + f.line + ": " + f.title;
          ul.appendChild(li);
        });
        full.appendChild(ul);
      });
      const rl = document.createElement("h4");
      rl.textContent = "Rules across files";
      full.appendChild(rl);
      const rul = document.createElement("ul");
      a.groupings.by_rule.forEach(function(r){
        const li = document.createElement("li");
        li.textContent = r.rule_id + " [" + r.severity + "] x" + r.count + ": " + r.files.join(", ");
        rul.appendChild(li);
      });
      full.appendChild(rul);
    }
    $("graphState").textContent = a.graph.message + " " + a.graph.detail;
    updateKpis();
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
        b.className = "ghost small";
        b.textContent = "Show " + it.graph_node_ids[0] + " in graph";
        b.addEventListener("click", function(){
          selectNode(it.graph_node_ids[0]);
          document.getElementById("sec-graph").scrollIntoView();
        });
        host.appendChild(b);
      }
      const ib = document.createElement("button");
      ib.type = "button";
      ib.className = "ghost small";
      ib.style.marginLeft = ".5em";
      ib.textContent = "Show findings in inventory";
      ib.addEventListener("click", function(){
        if(!currentScanId){ showError("run a mock scan first to cross-link inventory"); return; }
        filterRule = it.rule_id;
        loadInventory(currentScanId);
        loadRisk(currentScanId);
        document.getElementById("sec-inventory").scrollIntoView();
      });
      host.appendChild(ib);
    });
    updateWorkflow();
  }catch(e){ showError(String(e.message || e)); }
}
$("clearFilters").addEventListener("click", function(){
  filterSev = null;
  filterRule = null;
  if(currentScanId){ loadInventory(currentScanId); loadRisk(currentScanId); }
});
async function loadReports(scanId){
  try{
    const r = await api("/api/reports?scan_id=" + encodeURIComponent(scanId));
    const host = $("reports");
    while(host.firstChild){ host.removeChild(host.firstChild); }
    const sum = document.createElement("p");
    sum.className = "note";
    sum.textContent = "scan " + r.scan_id + " (" + r.target + "): " +
      r.finding_count + " findings, risk " + r.risk.level +
      " (" + r.risk.score + ") [mock scoring].";
    host.appendChild(sum);
    const mock = document.createElement("p");
    mock.className = "note";
    mock.textContent = "Mock reports: generated from the stored mock scan; " +
      "no new analysis is performed.";
    host.appendChild(mock);
    const row = document.createElement("div");
    row.className = "row";
    r.formats.forEach(function(fmt){
      const a = document.createElement("a");
      a.href = "/api/reports/download?scan_id=" + encodeURIComponent(scanId) +
        "&format=" + encodeURIComponent(fmt);
      if(fmt === "html"){ a.target = "_blank"; a.rel = "noopener"; }
      else{ a.setAttribute("download", ""); }
      a.addEventListener("click", function(){ logAct("export", fmt.toUpperCase()+" report opened", "scan "+scanId); });
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ghost small";
      btn.textContent = (fmt === "html" ? "View " : "Download ") + fmt.toUpperCase();
      a.appendChild(btn);
      row.appendChild(a);
    });
    host.appendChild(row);
  }catch(e){ showError(String(e.message || e)); }
}
var ACTLOG = [];
var ACTICON = {"plan":"○","scan":"◎","done":"●","export":"⎙","trace":"⁂"};
function actTime(ts){
  var s=Math.max(0,Math.round((Date.now()-ts)/1000));
  if(s<45){return "just now";}
  var m=Math.floor(s/60);
  if(m<60){return m+" min ago";}
  return Math.floor(m/60)+" h ago";
}
function logAct(kind, title, sub){
  ACTLOG.unshift({kind:kind,title:title,sub:sub||"",ts:Date.now()});
  if(ACTLOG.length>6){ACTLOG.length=6;}
  renderActivity();
}
function renderActivity(){
  var host=$("activityFeed"); if(!host){return;}
  while(host.firstChild){host.removeChild(host.firstChild);}
  if(!ACTLOG.length){
    var li=document.createElement("li");
    var d=document.createElement("div");d.className="ft";
    var b=document.createElement("b");b.textContent="No session activity yet";
    var s=document.createElement("span");s.textContent="Generate a plan or start a scan to begin.";
    d.appendChild(b);d.appendChild(s);li.appendChild(d);host.appendChild(li);
    return;
  }
  ACTLOG.forEach(function(ev){
    var li=document.createElement("li");
    li.className="fkind-"+ev.kind;
    var ic=document.createElement("span");ic.className="fico";ic.textContent=ACTICON[ev.kind]||"○";
    var d=document.createElement("div");d.className="ft";
    var b=document.createElement("b");b.textContent=ev.title;
    d.appendChild(b);
    if(ev.sub){var s=document.createElement("span");s.textContent=ev.sub;d.appendChild(s);}
    var t=document.createElement("span");t.className="ftime";t.textContent=actTime(ev.ts);
    var p=document.createElement("span");p.className="fpill";p.textContent="Mock";
    li.appendChild(ic);li.appendChild(d);li.appendChild(t);li.appendChild(p);
    host.appendChild(li);
  });
}
const SVGNS = document.getElementById("graph").namespaceURI;
const GTCOLORS = {"Endpoint":"#1D4ED8","Service":"#2E90FA","Container":"#667085","Library":"#98A2B3","CryptoOperation":"#B54708","CryptoAsset":"#101828","CertificateKey":"#0E9384","CloudResource":"#475467"};
const GRISKY = {"high":true,"critical":true};
const GRISKCOLOR = {"critical":"#B42318","high":"#B54708","medium":"#A16207","low":"#027A48","info":"#667085","none":"#98A2B3"};
let GDATA = null;
let gView = {x:0,y:0,k:1};
let gHiddenTypes = {};
let gTraceOn = null;
let gSelected = null;
let gZoomTimer = null;
function gZoomLevel(){ return gView.k < 1.05 ? "out" : (gView.k < 1.9 ? "mid" : "in"); }
function gScheduleRender(){
  if(gZoomTimer){ clearTimeout(gZoomTimer); }
  gZoomTimer = setTimeout(function(){ gZoomTimer = null; renderGraph(); }, 140);
}
function gExitTrace(rerender){
  gTraceOn = null;
  try{
    var b=$("gtrace");
    if(b){ b.removeAttribute("aria-pressed"); }
  }catch(e){}
  if(rerender !== false){ renderGraph(); }
}
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
function gDegree(id){
  var d=0;
  for(const e of GDATA.edges){ if(e.source===id||e.target===id){d++;} }
  return d;
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
    buildLegend();
    renderGraph();
    if(lastRisk && currentScanId){ annotateRiskRules(currentScanId, $("riskRules")); }
    updateWorkflow();
  }catch(e){ showError(String(e.message || e)); }
}
function buildTypeChips(){
  const host = $("gtypes");
  while(host.firstChild){ host.removeChild(host.firstChild); }
  GDATA.node_types.forEach(function(t){
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tile";
    var dot=document.createElement("span");dot.className="rdot";dot.style.background=GTCOLORS[t]||"#94A3B8";
    b.appendChild(dot);
    var lab=document.createElement("span");lab.textContent=" "+t;b.appendChild(lab);
    b.addEventListener("click", function(){
      gHiddenTypes[t] = !gHiddenTypes[t];
      b.style.opacity = gHiddenTypes[t] ? ".4" : "1";
      renderGraph();
    });
    host.appendChild(b);
  });
}
function buildLegend(){
  var host=$("glegend"); if(!host||!GDATA){return;}
  while(host.firstChild){host.removeChild(host.firstChild);}
  function cap(t){var c=document.createElement("div");c.className="cap";c.textContent=t;host.appendChild(c);}
  function li(swClass,swColor,label,isLine,isRing){
    var d=document.createElement("div");d.className="li";
    var s=document.createElement("span");
    s.className=isLine?"ln":(isRing?"rg":"sw");
    if(swColor){s.style.background=swColor;}
    if(isLine){s.style.borderColor=swColor;}
    if(isRing){s.style.borderColor=swColor;}
    d.appendChild(s);
    var t=document.createElement("span");t.textContent=label;d.appendChild(t);
    host.appendChild(d);
  }
  cap("Node ring = risk");
  [["Critical","#B42318"],["High","#B54708"],["Medium","#A16207"],["Low","#027A48"],["Info / none","#667085"]].forEach(function(p){
    li("sw",p[1],p[0],false,false);
  });
  cap("Path");
  li("ln","#1D4ED8","Trace path",true,false);
  li("rg","#1D4ED8","Selected",false,true);
  cap("Node color = type (filter above)");
}
function renderGraph(){
  const svg = $("graph");
  while(svg.firstChild){ svg.removeChild(svg.firstChild); }
  const W = GDATA.canvas.width, H = GDATA.canvas.height;
  svg.setAttribute("viewBox", "0 0 " + W + " " + H);
  var zlev = gZoomLevel();
  svg.setAttribute("data-z", zlev);
  const defs = gEl("defs", {}, svg);
  var pat=gEl("pattern",{id:"ggrid",width:"36",height:"36",patternUnits:"userSpaceOnUse"},defs);
  gEl("path",{d:"M 36 0 L 0 0 0 36",fill:"none",stroke:"#E4E7EC","stroke-width":"1"},pat);
  [["garr","#98A2B3"],["garrR","#B42318"],["garrB","#1D4ED8"]].forEach(function(m){
    const mk = gEl("marker", {id:m[0], viewBox:"0 0 10 10", refX:"9", refY:"5",
      markerWidth:"6", markerHeight:"6", orient:"auto-start-reverse"}, defs);
    gEl("path", {d:"M 0 1 L 9 5 L 0 9 z", fill:m[1]}, mk);
  });
  gEl("rect",{x:"0",y:"0",width:W,height:H,fill:"url(#ggrid)",opacity:"0.4"},svg);
  const root = gEl("g", {id:"groot"}, svg);
  const q = $("gsearch").value.trim().toLowerCase();
  const vis = {};
  GDATA.nodes.forEach(function(n){ vis[n.id] = gVisible(n, q); });
  var inTrace = {};
  if(gTraceOn && gTraceOn.nodeIds){
    gTraceOn.nodeIds.forEach(function(nid){ inTrace[nid] = true; });
  }
  const eLayer = gEl("g", {}, root);
  const nLayer = gEl("g", {}, root);
  [false, true].forEach(function(passTraced){
  GDATA.edges.forEach(function(e){
    const a = gNodeById(e.source), b = gNodeById(e.target);
    const shown = vis[e.source] && vis[e.target];
    const traced = gTraceOn && gTraceOn.edgeIds.indexOf(e.id) >= 0;
    if(!!traced !== passTraced){ return; }
    var dimmed = !shown;
    if(gTraceOn && !traced){ dimmed = true; }
    const risky = GRISKY[a.risk] || GRISKY[b.risk];
    const x1 = a.x + 75, y1 = a.y + 28, x2 = b.x + 75, y2 = b.y + 28;
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    const ln = gEl("line", {x1:x1, y1:y1, x2:x2, y2:y2,
      "class":"gedge" + (risky ? " risky" : "") + (traced ? " trace" : "") + (dimmed ? " dim" : ""),
      "marker-end": dimmed ? "none" : (traced ? "url(#garrB)" : (risky ? "url(#garrR)" : "url(#garr)"))}, eLayer);
    ln.addEventListener("click", function(ev){ ev.stopPropagation(); selectEdge(e.id); });
    gEl("line", {x1:x1, y1:y1, x2:x2, y2:y2, "class":"gedge-hit" + (dimmed ? " dim" : "")}, eLayer)
      .addEventListener("click", function(ev){ ev.stopPropagation(); selectEdge(e.id); });
    if(zlev === "in" || traced){
      const lb = gEl("text", {x:mx, y:my - 4, "class":"glabel eldetail" + (dimmed ? " dim" : ""), "text-anchor":"middle"}, eLayer);
      lb.textContent = e.type;
    }
  });
  });
  GDATA.nodes.forEach(function(n){
    var deg=gDegree(n.id);
    var cx=n.x+75, cy=n.y+28;
    var baseR=14+(deg>=6?5:(deg>=3?2:0));
    var ring=GRISKCOLOR[n.risk]||"#98A2B3";
    var isSel=(gSelected === n.id);
    var isTraced=!!inTrace[n.id];
    var dimmed=!vis[n.id];
    if(gTraceOn && !isTraced){ dimmed = true; }
    var priority = GRISKY[n.risk] || deg >= 5 || isSel || isTraced;
    const g = gEl("g", {"class":"gnode" + (dimmed ? " dim" : "") + (isSel ? " selected" : ""),
      transform:"translate(" + cx + "," + cy + ")", "data-nid":n.id, tabindex:"0", role:"button", "aria-label":n.label+" "+n.type+" risk "+n.risk}, nLayer);
    var haloOp = n.risk === "critical" ? ".5" : (n.risk === "high" ? ".4" : (GRISKY[n.risk] ? ".3" : "0"));
    if(isTraced && haloOp === "0"){ haloOp = ".25"; }
    if(!dimmed || isSel){
      var halo=gEl("circle",{r:baseR+5,fill:"none",stroke:ring,"stroke-opacity":haloOp,"stroke-width":"5"},g);
      halo.setAttribute("pointer-events","none");
    }
    var core=gEl("circle",{r:baseR,"class":"core",stroke:ring,"stroke-width":"2"},g);
    void core;
    if(isTraced){
      var tr=gEl("circle",{r:baseR+9,"class":"tracering"},g);
      tr.setAttribute("pointer-events","none");
    }
    if(isSel){
      var sr=gEl("circle",{r:baseR+9,"class":"selring"},g);
      sr.setAttribute("pointer-events","none");
    }
    const title = gEl("title", {}, g);
    title.textContent = n.label + " (" + n.type + ", risk " + n.risk + ")";
    var initials=gText(g, 0, 4, n.label.slice(0,2).toUpperCase(), 10, true, "#101828");
    void initials;
    var showName = (zlev === "in") || (zlev === "mid") || priority;
    var showSub = (zlev === "in") || ((zlev === "mid") && priority);
    if(showName){
      var lab=gText(g, 0, baseR+16, n.label.slice(0,22), 12, true, "#101828");
      lab.setAttribute("class","nlabel");
    }
    if(showSub){
      var sub=gEl("text",{x:0, y:baseR+29, "font-size":10, "text-anchor":"middle", fill:"#667085"},g);
      sub.textContent = n.type + " · ";
      var rs=gEl("tspan",{fill:ring},sub);
      rs.textContent = n.risk;
    }
    g.addEventListener("click", function(ev){ ev.stopPropagation(); selectNode(n.id); });
    g.addEventListener("keydown", function(ev){ if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();selectNode(n.id);} });
  });
  gApply();
  try{
    var ov=$("govlay");
    if(ov){ ov.textContent = GDATA.node_count + " nodes · " + GDATA.edge_count + " edges · mock · " + Math.round(gView.k*100) + "%"; }
  }catch(e){}
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
  gSelected = id;
  renderGraph();
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
  const gv = document.createElement("p");
  gv.className = "note";
  gv.textContent = "Graph and inventory are different views of the same landscape: graph shows mock topology, inventory shows your scan findings. Rule links filter inventory without altering the graph.";
  host.appendChild(gv);
  if(n.rule_id){
    const b = document.createElement("button");
    b.type = "button";
    b.className = "xlink small";
    b.textContent = "Show in inventory (" + n.rule_id + ")";
    b.addEventListener("click", function(){
      if(!currentScanId){ showError("run a mock scan first to cross-link inventory"); return; }
      filterRule = n.rule_id;
      loadInventory(currentScanId);
      loadRisk(currentScanId);
      document.getElementById("sec-inventory").scrollIntoView();
    });
    host.appendChild(b);
  }
  const rb = document.createElement("button");
  rb.type = "button";
  rb.className = "ghost small";
  rb.textContent = "Open risk dashboard";
  rb.style.marginLeft = ".5em";
  rb.addEventListener("click", function(){
    document.getElementById("sec-risk").scrollIntoView();
  });
  host.appendChild(rb);
}
function selectEdge(id){
  gSelected = null;
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
  gTraceOn = {id: pid, edgeIds: edgeIds, nodeIds: t.node_ids.slice()};
  try{ $("gtrace").setAttribute("aria-pressed","true"); }catch(e){}
  logAct("trace","Trace run",pid);
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
  rb.className = "ghost small";
  rb.textContent = "Open risk dashboard";
  rb.addEventListener("click", function(){
    document.getElementById("sec-risk").scrollIntoView();
  });
  host.appendChild(rb);
}
function gZoom(f){
  var r=$("graph").getBoundingClientRect();
  var k2=Math.min(3,Math.max(.3,gView.k*f));
  gView.x=r.width/2-(r.width/2-gView.x)*(k2/gView.k);
  gView.y=200-(200-gView.y)*(k2/gView.k);
  gView.k=k2;gApply();gScheduleRender();
}
$("greset").addEventListener("click", function(){
  gView = {x:0,y:0,k:1};
  gHiddenTypes = {};
  gSelected = null;
  gExitTrace(false);
  $("gsearch").value = "";
  document.querySelectorAll("#gtypes .tile").forEach(function(b){ b.style.opacity = "1"; });
  renderGraph();
});
try{$("gfit").addEventListener("click", function(){ gView={x:0,y:0,k:1};gApply();renderGraph(); });}catch(e){}
try{$("gzin").addEventListener("click", function(){ gZoom(1.25); });}catch(e){}
try{$("gzout").addEventListener("click", function(){ gZoom(0.8); });}catch(e){}
$("gtrace").addEventListener("click", function(){
  if(gTraceOn && gTraceOn.id === "internet-to-risk"){
    gExitTrace(true);
    return;
  }
  tracePath("internet-to-risk");
});
document.getElementById("graph").addEventListener("keydown", function(ev){
  if(ev.key === "Escape"){
    gSelected = null;
    if(gTraceOn){ gExitTrace(true); }
    else{ renderGraph(); }
  }
});
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
    gScheduleRender();
  }, {passive:false});
})();
renderDonut({critical:0,high:0,medium:0,low:0,info:0});
updateWorkflow();
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

    def _svg(self, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()
        self.wfile.write(raw)

    def _bytes(self, code: int, body: bytes, content_type: str,
               filename: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition",
                         f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

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
        elif parsed.path == "/favicon.svg":
            self._svg(FAVICON_SVG)
        elif parsed.path == "/privacy":
            self._html(_legal_page(
                "Privacy Policy", "Privacy Policy", PRIVACY_PARAGRAPHS))
        elif parsed.path == "/terms":
            self._html(_legal_page(
                "Terms and Conditions", "Terms and Conditions",
                TERMS_PARAGRAPHS))
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
        elif parsed.path == "/api/reports":
            summary = self.service.report_summary(
                query.get("scan_id", [""])[0])
            if summary is None:
                self._json(404, {"error": "scan not found"})
            else:
                self._json(200, summary)
        elif parsed.path == "/api/reports/download":
            try:
                artifact = self.service.report_artifact(
                    query.get("scan_id", [""])[0],
                    query.get("format", [""])[0])
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
                return
            if artifact is None:
                self._json(404, {"error": "scan not found"})
            else:
                content_type, filename, body = artifact
                self._bytes(200, body, content_type, filename)
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
