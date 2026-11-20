"""WarpZone report writer: findings.json + report_warpzone.md + report_warpzone.html."""
import html as html_mod
import json
import time

from .hud import CREATOR


def esc(s):
    return html_mod.escape(str(s or ""))


def build_html(res, target):
    confirmed_rows = "".join(
        f"<tr><td><span class='b b-high'>CONFIRMED</span></td>"
        f"<td><a href='{esc(c['url'])}'>{esc(c['url'])}</a></td>"
        f"<td><code>{esc(c['source'])}</code></td>"
        f"<td><code class='snip'>{esc(c['payload'])}</code></td></tr>"
        for c in res.get("confirmed_xss", [])) or \
        "<tr><td colspan=4 class='dim'>none confirmed</td></tr>"

    secrets_rows = "".join(
        f"<tr><td><span class='b b-{esc(s['confidence'])}'>{esc(s['confidence'])}</span></td>"
        f"<td>{esc(s['type'])}</td><td><code>{esc(s['redacted'])}</code></td>"
        f"<td class='dim'>{esc(s['file'])}</td></tr>"
        for s in res["secrets"]) or "<tr><td colspan=4 class='dim'>none</td></tr>"

    dom_rows = "".join(
        f"<tr><td><span class='b b-{esc(l['taint'])}'>{esc(l['taint'])}</span></td>"
        f"<td><code>{esc(l['category'])}</code></td><td>{esc(l['line'])}</td>"
        f"<td><code class='snip'>{esc(l['snippet'])}</code></td>"
        f"<td>{esc(', '.join(l['sources']))}</td></tr>"
        for l in res["dom_leads"]) or "<tr><td colspan=5 class='dim'>none</td></tr>"

    xss_rows = "".join(
        f"<tr><td><span class='b b-{'high' if r['verdict']=='REFLECTED_UNFILTERED' else 'medium'}'>"
        f"{esc(r['verdict'].replace('REFLECTED_', ''))}</span></td>"
        f"<td><a href='{esc(r['url'])}'>{esc(r['url'])}</a></td>"
        f"<td><code>{esc(r['param'])}</code></td><td>{esc(r['context'])}</td>"
        f"<td><code class='snip'>{esc(r['payload'] or '')}</code></td></tr>"
        for r in res["xss_results"]) or "<tr><td colspan=5 class='dim'>no reflected params found</td></tr>"

    maps_rows = "".join(
        f"<tr><td><span class='b b-high'>{esc(m['level'])}</span></td>"
        f"<td><a href='{esc(m['map_url'])}'>{esc(m['map_url'])}</a></td>"
        f"<td>{esc(m['sources_content'])} files</td></tr>"
        for m in res["sourcemaps"]) or "<tr><td colspan=3 class='dim'>none exposed</td></tr>"

    cat_rows = ""
    cats = res.get("categories") or {}
    for cat, eps in sorted(cats.items(), key=lambda kv: -len(kv[1])):
        top = "".join(f"<li><a href='{esc(u)}'>{esc(u)}</a></li>" for u in eps[:12])
        cat_rows += (f"<div class='card'><h3>{esc(cat)} "
                     f"<span class='count'>{len(eps)}</span></h3><ul>{top}</ul>"
                     + ("<div class='dim'>full list in endpoints.txt</div>" if len(eps) > 12 else "")
                     + "</div>")

    mins, secs = divmod(int(res["elapsed"]), 60)
    return HTML_TEMPLATE \
        .replace("__TARGET__", esc(target)) \
        .replace("__DATE__", time.strftime("%Y-%m-%d %H:%M")) \
        .replace("__SCORE__", f"{res['score']:07d}") \
        .replace("__COINS__", f"{len(res['endpoints']):05d}") \
        .replace("__SECRETS__", str(len(res["secrets"]))) \
        .replace("__MAPS__", str(len(res["sourcemaps"]))) \
        .replace("__LEADS__", str(len(res["dom_leads"]))) \
        .replace("__XSS__", str(len(res["xss_results"]))) \
        .replace("__CONFIRMED__", str(len(res.get("confirmed_xss", [])))) \
        .replace("__TIME__", f"{mins:02d}:{secs:02d}") \
        .replace("__CATS__", cat_rows) \
        .replace("__CONFIRMED_ROWS__", confirmed_rows) \
        .replace("__SECRETS_ROWS__", secrets_rows) \
        .replace("__MAPS_ROWS__", maps_rows) \
        .replace("__DOM_ROWS__", dom_rows) \
        .replace("__XSS_ROWS__", xss_rows) \
        .replace("__CREATOR__", esc(CREATOR)) \
        .replace("__VERSION__", esc(res["version"]))


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WarpZone Report - __TARGET__</title>
<style>
:root{--pink:#ff5fa2;--magenta:#ff84c6;--lav:#c77dff;--rose:#ffb3d1;--mint:#8be9c0;--bg:#160d18;--card:#20142a;--ink:#f6e9f3;--dim:#b79bc0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 ui-monospace,'Cascadia Code',Menlo,Consolas,monospace;padding:1rem}
header{border-bottom:3px solid var(--pink);padding:1.2rem .6rem;margin-bottom:1rem}
h1{color:var(--magenta);margin:.2rem 0;font-size:clamp(1.3rem,4vw,2rem)}
h2{color:var(--pink);border-bottom:1px dashed #3a2340;padding-bottom:.3rem;margin-top:2rem}
h3{color:var(--lav);margin:.4rem 0}
a{color:var(--lav);word-break:break-all}
.dim{color:var(--dim);font-size:.85em}
.scorecard{display:flex;flex-wrap:wrap;gap:.8rem;margin:1rem 0}
.stat{background:var(--card);border:2px solid #3a2340;border-radius:10px;padding:.8rem 1.2rem;min-width:130px}
.stat b{display:block;font-size:1.6rem;color:var(--magenta)}
.stat span{color:var(--dim);font-size:.8em;text-transform:uppercase;letter-spacing:.1em}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:.9rem}
.card{background:var(--card);border:2px solid #3a2340;border-radius:10px;padding:.8rem 1rem;overflow-wrap:anywhere}
.card ul{margin:.3rem 0;padding-left:1.1rem}
.count{background:var(--pink);color:#1a0d16;border-radius:8px;padding:.05rem .5rem;font-size:.8em}
.b{display:inline-block;border-radius:6px;padding:.05rem .55rem;font-size:.8em;font-weight:bold}
.b-high{background:var(--pink);color:#fff}.b-medium{background:var(--magenta);color:#2a0d1f}
.b-low{background:#4a3356;color:var(--ink)}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden;font-size:.85em}
th{background:#2a1838;color:var(--magenta);text-align:left;padding:.5rem .7rem}
td{border-top:1px solid #33213f;padding:.45rem .7rem;vertical-align:top}
tr:hover td{background:#28183450}
code{background:#120a18;padding:.1rem .35rem;border-radius:5px;word-break:break-all}
.snip{max-width:340px;display:inline-block;white-space:pre-wrap}
footer{margin-top:2.5rem;border-top:3px solid var(--lav);padding:.9rem .6rem;color:var(--dim)}
@media(max-width:640px){body{padding:.6rem}.stat{min-width:100px}.snip{max-width:180px}table{display:block;overflow-x:auto}}
</style></head><body>
<header>
<h1>WARPZONE Report</h1>
<div>target: <b>__TARGET__</b> &nbsp;|&nbsp; generated: __DATE__ &nbsp;|&nbsp; WarpZone v__VERSION__</div>
</header>
<div class="scorecard">
<div class="stat"><b>__SCORE__</b><span>score</span></div>
<div class="stat"><b>__COINS__</b><span>endpoints (coins)</span></div>
<div class="stat"><b>__SECRETS__</b><span>secret leads</span></div>
<div class="stat"><b>__MAPS__</b><span>source maps (1-ups)</span></div>
<div class="stat"><b>__LEADS__</b><span>dom-xss leads</span></div>
<div class="stat"><b>__XSS__</b><span>xss reflections</span></div>
<div class="stat"><b>__CONFIRMED__</b><span>confirmed xss</span></div>
<div class="stat"><b>__TIME__</b><span>run time</span></div>
</div>
<h2>Confirmed XSS (fired in a real browser)</h2>
<table><tr><th>verdict</th><th>url</th><th>source</th><th>payload</th></tr>
__CONFIRMED_ROWS__</table>
<h2>Endpoints by category</h2>
<div class="cards">__CATS__</div>
<h2>Secrets (validate, never use)</h2>
<table><tr><th>conf</th><th>type</th><th>value (redacted)</th><th>file</th></tr>
__SECRETS_ROWS__</table>
<p class="dim">Full (unredacted) values are in findings.json for validation.</p>
<h2>Exposed source maps (near-original source)</h2>
<table><tr><th>level</th><th>map url</th><th>original files</th></tr>
__MAPS_ROWS__</table>
<h2>DOM-XSS taint leads (source to sink)</h2>
<table><tr><th>taint</th><th>sink</th><th>line</th><th>snippet</th><th>sources</th></tr>
__DOM_ROWS__</table>
<h2>XSS reflection probe (leads, confirm in a browser)</h2>
<table><tr><th>verdict</th><th>url</th><th>param</th><th>context</th><th>payload</th></tr>
__XSS_ROWS__</table>
<footer><b>WarpZone</b> - every JS file is a warp pipe &nbsp;-&nbsp; Made by <b>__CREATOR__</b> &nbsp;-&nbsp; authorized testing only</footer>
</body></html>
"""


def write_reports(outdir, res, target):
    """Write findings.json, report_warpzone.md, report_warpzone.html."""
    (outdir / "findings.json").write_text(json.dumps(res, indent=2, default=str),
                                          encoding="utf-8")
    (outdir / "report_warpzone.html").write_text(build_html(res, target), encoding="utf-8")
    _write_md(outdir, res, target)


def _write_md(outdir, res, target):
    confirmed = res.get("confirmed_xss", [])
    L = [f"# WarpZone Report - {target}", "",
         f"score {res['score']:07d} - {len(res['endpoints'])} endpoints - "
         f"{len(res['secrets'])} secret leads - {len(res['sourcemaps'])} source maps - "
         f"{len(res['dom_leads'])} DOM-XSS leads - {len(res['xss_results'])} reflections - "
         f"{len(confirmed)} confirmed - made by {CREATOR}", "",
         "> Heads up: most findings are UNVALIDATED LEADS from authorized testing.",
         "> Secrets: validate, never use. Reflections: confirm execution in a browser.",
         "> Confirmed XSS below actually fired in a real headless browser.", ""]

    if confirmed:
        L += ["## Confirmed XSS (fired in a real browser)", ""]
        for c in confirmed:
            L.append(f"- **[{c['source']}]** {c['url']}")
            L.append(f"  - payload: `{c['payload']}`")
        L.append("")

    L += ["## Endpoints", ""]
    cats = res.get("categories") or {}
    for cat, eps in sorted(cats.items(), key=lambda kv: -len(kv[1])):
        L.append(f"### {cat} ({len(eps)})")
        L.append("")
        L += [f"- {u}" for u in eps[:25]]
        if len(eps) > 25:
            L.append(f"- {len(eps) - 25} more in endpoints.txt")
        L.append("")
    if res["secrets"]:
        L += ["## Secrets (validate before reporting, never use them)", ""]
        for s in sorted(res["secrets"], key=lambda x: (x["confidence"], x["type"])):
            L.append(f"- **{s['type']}** ({s['confidence']}) - `{s['redacted']}` - {s['file']}")
            L.append(f"  - hint: {s['hint']}  (full value in findings.json)")
        L.append("")
    if res["sourcemaps"]:
        L += ["## Exposed source maps (download for near-original source)", ""]
        L += [f"- **[{m['level']}]** {m['map_url']} (via {m['found_via']}, "
              f"{m['sources_content']} original files restored)" for m in res["sourcemaps"]]
        L.append("")
    if res["dom_leads"]:
        L += ["## DOM-XSS leads (sink + source, investigate by hand)", ""]
        for l in res["dom_leads"]:
            L.append(f"- **[{l['taint'].upper()}]** `{l['category']}` - {l['file']}:{l['line']}"
                     f" - sources: {', '.join(l['sources']) or 'see file'}")
            L.append(f"  - snippet: `{l['snippet']}`")
            L.append(f"  - recipe: {l['recipe']}")
        L.append("")
    if res["xss_results"]:
        L += ["## XSS reflection probe (leads, confirm in a browser)", ""]
        for r in res["xss_results"]:
            L.append(f"- **[{r['verdict']}]** `{r['param']}` in {r['url']} "
                     f"(context: {r['context']}, raw chars: {' '.join(r['raw_chars']) or 'none'})")
            if r.get("payload"):
                L.append(f"  - payload: `{r['payload']}`")
        L.append("")
    if res.get("dalfox"):
        L += ["## dalfox confirmations", ""]
        L += [f"- {d['url']} - `{d['dalfox_line']}`" for d in res["dalfox"]]
        L.append("")
    L += ["## Files produced", "",
          "| file | what it is |", "| --- | --- |",
          "| confirmed_xss.json | XSS that actually fired in a browser |",
          "| endpoints.txt | every endpoint, ranked by interest score |",
          "| endpoints_live.txt | probed endpoints with status/title |",
          "| endpoints_categorized.json | categories + scores |",
          "| params.txt | parameter names worth reflection testing |",
          "| secrets.json / findings.json | machine-readable findings (unredacted) |",
          "| dom_xss_leads.json | taint leads with line numbers |",
          "| prettified/ | beautified JS, read these |",
          "| raw_js/ | original JS as served |",
          "| sourcemaps/ | exposed .map files + restored sources |",
          "| report_warpzone.html | this report, prettier |", ""]
    (outdir / "report_warpzone.md").write_text("\n".join(L), encoding="utf-8")
