"""WORLD 0 (WARP WHISTLE): recon front-end.

A scope-enforced recon pipeline that bridges to the best community tools when
they are installed and falls back to built-ins when they are not:

  subfinder   subdomain discovery
  crt.sh      certificate-transparency subdomains (no tool needed, just HTTP)
  httpx       liveness
  gau         archived URLs
  waybackurls archived URLs
  katana      live crawl
  jsluice     endpoint extraction from JS (falls back to a regex miner)

Every host is checked against the scope before it is touched, so recon never
wanders off your targets. Results land as clean text files plus a readable
recon_report.md, and the HUD prints a summary you actually want to look at.
"""
import json
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from . import core

JS_RE = re.compile(r"\.js(?:\?|#|$)", re.I)

# Paths worth testing by hand: auth, APIs, admin, uploads, money.
INTERESTING_RE = re.compile(
    r"/(?:api|v[0-9]+|graphql|admin|login|logout|signin|signup|auth|oauth|sso|"
    r"token|session|password|reset|forgot|invite|upload|file|user|users|account|"
    r"profile|billing|payment|invoice|order|webhook|internal|debug|config|"
    r"redirect|callback|export|import|backup)(?:/|\?|$|_|-|\.)", re.I)

# Fallback JS endpoint miner (used when jsluice is not installed).
_URL_IN_JS = re.compile(r"""['"`]((?:https?:)?//[^'"`\s]+|/[A-Za-z0-9_./-]{2,}(?:\?[^'"`\s]*)?)['"`]""")


def _which(tool):
    return shutil.which(tool) is not None


# --------------------------------------------------------------- subdomains ---

def find_subdomains(domain, scope, session, hud):
    subs = set()
    if _which("subfinder"):
        hud.pipe("subfinder sweeping " + domain)
        subs.update(core.run(["subfinder", "-d", domain, "-all", "-silent"], timeout=600))
    else:
        hud.note("subfinder not installed, skipping passive subdomain brute")

    hud.pipe("crt.sh certificate transparency for " + domain)
    try:
        r = core.get(session, "https://crt.sh/?q=%25." + domain + "&output=json", timeout=30)
        if r is not None and r.status_code == 200:
            for row in r.json():
                for name in str(row.get("name_value", "")).splitlines():
                    subs.add(name.strip().lstrip("*.").lower())
    except Exception:
        hud.note("crt.sh lookup failed (rate limit or network), moving on")

    # the seed domain itself counts
    subs.add(domain)
    in_scope = sorted({s for s in subs if s and core.in_scope(s, scope)})
    hud.coin(len(in_scope))
    hud.sfx(str(len(in_scope)) + " in-scope subdomains")
    return in_scope


# ------------------------------------------------------------------- live ---

def live_hosts(hosts, session, hud, threads=8):
    if not hosts:
        return []
    if _which("httpx"):
        hud.pipe("httpx probing " + str(len(hosts)) + " hosts")
        out = core.run(["httpx", "-silent", "-mc", "200,201,204,301,302,401,403"],
                       stdin="\n".join(hosts), timeout=600)
        live = sorted({u for u in out if core.is_sane_url(u)})
    else:
        hud.pipe("built-in liveness check on " + str(len(hosts)) + " hosts")
        urls = ["https://" + h for h in hosts]
        from . import collect
        live = sorted(set(collect.confirm_live(session, urls, threads=threads,
                                               prefer_httpx=False)))
    # hosts came from the in-scope subdomain list already; just drop any junk
    live = [u for u in live if core.is_sane_url(u)]
    hud.coin(len(live))
    hud.sfx(str(len(live)) + " live hosts")
    return live


# ------------------------------------------------------------------- urls ---

def collect_urls(domain, live, scope, hud):
    urls = set()
    starts = live or ["https://" + domain]

    if _which("gau"):
        hud.pipe("gau pulling archived URLs")
        urls.update(core.run(["gau", "--subs", domain], timeout=600))
    if _which("waybackurls"):
        hud.pipe("waybackurls pulling archived URLs")
        urls.update(core.run(["waybackurls"], stdin=domain, timeout=600))
    if _which("katana"):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
            tf.write("\n".join(starts))
            listfile = tf.name
        hud.pipe("katana crawling live hosts")
        urls.update(core.run(["katana", "-list", listfile, "-jc", "-d", "3", "-silent"],
                             timeout=900))
        try:
            Path(listfile).unlink()
        except OSError:
            pass
    if not (_which("gau") or _which("waybackurls") or _which("katana")):
        hud.note("no URL tools (gau/waybackurls/katana) installed; using the built-in spider")
        from . import collect
        for start in starts[:10]:
            js, pages = collect.spider(core.make_session(), start, scope, max_pages=25)
            urls.update(js)
            urls.update(pages)

    clean = sorted({u.split("#")[0] for u in urls
                    if core.is_sane_url(u.split("#")[0])
                    and core.in_scope(urlparse(u).hostname, scope)})
    hud.coin(len(clean))
    hud.sfx(str(len(clean)) + " in-scope URLs")
    return clean


# -------------------------------------------------------------------- js ----

def js_files(urls, session, hud, threads=8):
    cands = sorted({u for u in urls if JS_RE.search(urlparse(u).path)})
    if not cands:
        return []
    hud.pipe("confirming " + str(len(cands)) + " JS files are live")
    from . import collect
    live = sorted(set(collect.confirm_live(session, cands, threads=threads)))
    hud.coin(len(live))
    hud.sfx(str(len(live)) + " live JS files")
    return live


def js_endpoints(jsfiles, session, hud, limit=400):
    """Pull endpoints out of JS: jsluice if present, else a regex fallback."""
    have_jsluice = _which("jsluice")
    hud.pipe(("jsluice" if have_jsluice else "built-in regex") +
             " mining endpoints from " + str(min(len(jsfiles), limit)) + " JS files")
    found = set()
    for url in jsfiles[:limit]:
        r = core.get(session, url, timeout=15)
        if r is None or not isinstance(r.text, str):
            continue
        text = r.text
        if have_jsluice:
            for line in core.run(["jsluice", "urls"], stdin=text, timeout=30):
                try:
                    u = json.loads(line).get("url")
                    if u:
                        found.add(u)
                except (ValueError, AttributeError):
                    continue
        else:
            for m in _URL_IN_JS.finditer(text):
                found.add(m.group(1))
    eps = sorted(e for e in found if e and len(e) < 400 and " " not in e)
    hud.coin(len(eps))
    hud.sfx(str(len(eps)) + " endpoints from JS")
    return eps


# -------------------------------------------------------------- classify ----

def classify(urls, endpoints):
    everything = list(dict.fromkeys(list(urls) + list(endpoints)))
    params = sorted({u for u in urls if "?" in u and "=" in u.split("?", 1)[1]})
    interesting = sorted({u for u in everything if INTERESTING_RE.search(u)})
    return params, interesting


# ----------------------------------------------------------------- write ----

def _write_lines(path, lines):
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_all(outdir, data):
    _write_lines(outdir / "subdomains.txt", data["subdomains"])
    _write_lines(outdir / "live_hosts.txt", data["live"])
    _write_lines(outdir / "urls.txt", data["urls"])
    _write_lines(outdir / "js_files.txt", data["js_files"])
    _write_lines(outdir / "js_endpoints.txt", data["js_endpoints"])
    _write_lines(outdir / "params.txt", data["params"])
    _write_lines(outdir / "interesting.txt", data["interesting"])

    md = ["# WarpZone recon: " + data["target"], "",
          "Scope: " + data["scope_desc"], "",
          "| What | Count | File |", "| --- | ---: | --- |",
          f"| Subdomains (in scope) | {len(data['subdomains'])} | subdomains.txt |",
          f"| Live hosts | {len(data['live'])} | live_hosts.txt |",
          f"| URLs | {len(data['urls'])} | urls.txt |",
          f"| Live JS files | {len(data['js_files'])} | js_files.txt |",
          f"| Endpoints from JS | {len(data['js_endpoints'])} | js_endpoints.txt |",
          f"| URLs with params | {len(data['params'])} | params.txt |",
          f"| Interesting paths | {len(data['interesting'])} | interesting.txt |", ""]
    if data["interesting"]:
        md += ["## Start here (api / auth / admin / upload)", ""]
        md += ["- " + u for u in data["interesting"][:60]]
        md += [""]
    (outdir / "recon_report.md").write_text("\n".join(md), encoding="utf-8")


# ------------------------------------------------------------------- run ----

def run(args, hud, scope, session, outdir, domain):
    hud.banner()
    hud.note("recon mode: scope = " + scope.describe())

    subs = find_subdomains(domain, scope, session, hud)
    live = live_hosts(subs, session, hud, threads=args.threads)
    urls = collect_urls(domain, live, scope, hud)
    jsf = js_files(urls, session, hud, threads=args.threads)
    eps = js_endpoints(jsf, session, hud)
    params, interesting = classify(urls, eps)

    data = {
        "target": domain, "scope_desc": scope.describe(),
        "subdomains": subs, "live": live, "urls": urls,
        "js_files": jsf, "js_endpoints": eps,
        "params": params, "interesting": interesting,
    }
    write_all(outdir, data)
    hud.recon_summary(data, outdir)
    return data
