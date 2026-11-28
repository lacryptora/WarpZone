"""WarpZone CLI: the entrance pipe.

Examples:
  warpzone -d target.com --scope scope.txt
  warpzone -u https://target.com/app --scope scope.txt --probe --xss
  warpzone -d target.com --scope scope.txt --xss --confirm
  warpzone --js-list jsurls.txt --scope scope.txt --dalfox
"""
import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from . import collect, confirm, core, domxss, recon
from . import endpoints as endpoints_mod
from . import hud as hud_mod
from . import prettify, report
from . import secrets as secrets_mod
from . import sourcemaps
from .xss import probe as xss_probe


def build_parser():
    ap = argparse.ArgumentParser(
        prog="warpzone",
        description="WarpZone: Mario-styled JS recon and XSS arsenal. "
                    "AUTHORIZED TARGETS ONLY; scope is checked on every request.",
        epilog="Made by Shaimaa Khattab. Every JS file is a warp pipe.")
    g = ap.add_mutually_exclusive_group(required=False)
    g.add_argument("-d", "--domain",
                   help="target domain. 'target.com' = the apex and all subdomains; "
                        "'*.target.com' = subdomains only, not the apex")
    g.add_argument("-u", "--url", help="target start URL")
    g.add_argument("--js-list", dest="js_list",
                   help="file of JS URLs to analyze directly")
    g.add_argument("--targets", help="file of mixed targets (domains, *.wildcards, URLs), one per line")
    g.add_argument("--confirm-from", dest="confirm_from", metavar="PATH",
                   help="skip all crawling and only run the browser confirm on the URLs "
                        "from a saved run: a results folder, its findings.json, or a .txt "
                        "list of URLs. Reuses that run's scope if it can.")
    ap.add_argument("--scope",
                    help="scope file (optional). One host per line; '!host' excludes; # comments. "
                         "If left off, scope is built from the target and covers its subdomains.")
    ap.add_argument("--out", help="output directory (default warpzone_<target>_<ts>)")
    ap.add_argument("--bridges", help="comma list of bridges to use: gau,waymore,katana,hakrawler")
    ap.add_argument("--no-bridges", action="store_true", help="skip external crawl bridges")
    ap.add_argument("--no-raw", action="store_true", help="do not save raw JS copies")
    ap.add_argument("--depth", type=int, default=2, help="crawler depth for katana/hakrawler (default 2)")
    ap.add_argument("--max-pages", dest="max_pages", type=int, default=25,
                    help="max pages for the built-in spider (default 25)")
    ap.add_argument("--threads", type=int, default=8, help="worker threads (default 8)")
    ap.add_argument("--timeout", type=int, default=15, help="per-request timeout seconds (default 15)")
    ap.add_argument("--entropy", type=float, default=4.2,
                    help="entropy threshold for the opaque-string finder (default 4.2)")
    ap.add_argument("--recon", action="store_true",
                    help="RECON mode: subdomains + live hosts + URLs + JS endpoints, bridging "
                         "subfinder/assetfinder/crt.sh/dnsx/httpx/gau/waybackurls/waymore/katana/jsluice. "
                         "No payloads; writes clean lists and a recon_report.md")
    ap.add_argument("--probe", action="store_true",
                    help="probe discovered endpoints with safe GETs (status/title)")
    ap.add_argument("--xss", action="store_true",
                    help="ACTIVE: reflection-probe endpoints/params for XSS leads")
    ap.add_argument("--confirm", action="store_true",
                    help="ACTIVE: confirm DOM XSS in a real headless browser (needs playwright)")
    ap.add_argument("--confirm-limit", dest="confirm_limit", type=int, default=15,
                    help="max URLs sent to the browser confirmer (default 15)")
    ap.add_argument("--xss-url", dest="xss_url", help="probe just this URL (e.g. 'http://x/p?q=1')")
    ap.add_argument("--xss-params", dest="xss_params",
                    help="extra param names to try, comma separated")
    ap.add_argument("--xss-max-params", dest="xss_max_params", type=int, default=8,
                    help="max params tested per endpoint (default 8)")
    ap.add_argument("--xss-max-payloads", dest="xss_max_payloads", type=int, default=6,
                    help="max payloads per reflected param (default 6)")
    ap.add_argument("--xss-endpoints-limit", dest="xss_endpoints_limit", type=int, default=25,
                    help="max endpoints fed to the XSS arena (default 25)")
    ap.add_argument("--dalfox", action="store_true", help="bridge to dalfox if installed")
    ap.add_argument("--insecure", action="store_true", help="disable TLS verification")
    ap.add_argument("--user-agent", dest="user_agent",
                    help="custom User-Agent (default is a normal browser; some programs "
                         "ask you to tag your traffic, e.g. 'h1-username bugbounty')")
    ap.add_argument("--no-game", action="store_true", help="plain output, no Mario HUD")
    return ap


# ------------------------------------------------------------- targets -----

def _resolve_targets(args):
    """Work out what to crawl, what JS to read directly, and the scope.

    Accepts a domain, a wildcard, a URL, a JS-URL list, or a mixed targets
    file (domains, *.wildcards and URLs together). Returns:
      crawl:     list of (seed_host, start_url) to spider and bridge
      direct_js: list of JS URLs to fetch and analyze straight away
      scope:     from --scope if given, otherwise built from the targets
    """
    crawl, direct_js, hosts = [], [], []

    def add(entry, force_js=False):
        entry = entry.strip()
        if not entry:
            return
        if "://" in entry:
            host = urlparse(entry).hostname or ""
            if host:
                hosts.append(host)          # a URL names an exact host (apex in)
            if force_js or urlparse(entry).path.lower().endswith(".js"):
                direct_js.append(entry)
            else:
                crawl.append((core.parse_scope_entry(host) or host, entry))
        else:
            host = core.parse_scope_entry(entry)  # bare host, "*." dropped
            if host:
                hosts.append(entry)         # keep raw: "*.host" stays subs-only
                crawl.append((host, "https://" + host))

    if args.domain:
        add(args.domain)
    elif args.url:
        add(args.url)
    elif args.js_list:
        for line in core.load_lines(args.js_list):
            add(line, force_js=True)
    elif args.targets:
        for line in core.load_lines(args.targets):
            add(line)

    if args.scope:
        scope = core.load_scope(args.scope)
    else:
        scope = core.Scope(list(dict.fromkeys(hosts)), [])
    return crawl, direct_js, scope


# ------------------------------------------------------------- pipeline ----

def _concrete(u):
    """True for a real, reachable URL (not a route template).

    Drops framework route patterns that are not real pages, like
    /:nextInternalLocale, /api/md/:slug*, /[id], /{id} - a server never
    routes those, so firing payloads at them is wasted effort.
    """
    path = urlparse(u).path
    return "://" in u and not any(c in path for c in ":*[]{}")


def _candidate_urls(args, eps, pages):
    """Pages and real (non-template) endpoints worth active testing, deduped by path."""
    if args.xss_url:
        base = [args.xss_url]
    else:
        base = [u for u in eps if _concrete(u)][:args.xss_endpoints_limit]
    base = list(dict.fromkeys(base + [p for p in pages if _concrete(p)]))
    seen, out = set(), []
    for u in base:
        key = u.split("?")[0]
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def pipeline(args, hud, scope, session, outdir, crawl, direct_js):
    hud.banner()
    target = ((args.domain or (urlparse(args.url).hostname if args.url else None)
               or (scope.includes[0] if scope.includes else "targets"))).lstrip("*.") or "targets"
    if not args.scope:
        hud.note("no --scope file given, so scope is built from the target: "
                 + scope.describe())

    # ---------- WORLD 1-1: WARP PIPES ------------------------------------
    hud.level(1)
    js, pages = collect.discover(crawl, direct_js, args, scope, session, hud)
    if not js:
        hud.game_over("no in-scope JS files found. Check the scope file and the URL.")
        return None
    hud.course_clear(1, f"{len(js)} live in-scope JS files")

    # ---------- WORLD 1-2: COIN HEAVEN ------------------------------------
    hud.level(2)
    hud.pipe("fetching and prettifying every JS file")
    manifest = prettify.fetch_all(session, js, outdir,
                                  threads=args.threads, keep_raw=not args.no_raw)
    hud.hud(f"prettified {len(manifest)}/{len(js)} files")
    eps, params, per_file = endpoints_mod.mine(manifest)
    for u in eps[:8]:
        hud.item(u)
    hud.coin(len(eps))
    live = endpoints_mod.probe(session, eps, scope, threads=args.threads) if args.probe else None
    endpoints_mod.write(outdir, eps, params, live)
    hud.course_clear(2, f"{len(eps)} endpoints minted, {len(params)} param names")

    # ---------- WORLD 1-3: SECRET VAULTS ----------------------------------
    hud.level(3)
    found = []
    for e in manifest:
        text = e.get("_pretty_text")
        if text is None:
            text = Path(e["pretty_file"]).read_text(encoding="utf-8", errors="replace")
        found.extend(secrets_mod.mine(text, e["url"], entropy_threshold=args.entropy))
    secs = secrets_mod.dedupe(found)
    (outdir / "secrets.json").write_text(json.dumps(secs, indent=2), encoding="utf-8")
    for s in secs[:10]:
        hud.item(f"[SECRET {s['confidence']}] {s['type']} - {s['file']}")
    maps = sourcemaps.scan_all(session, manifest, outdir, hud, download=True, scope=scope)
    hud.course_clear(3, f"{len(secs)} secret leads, {len(maps)} exposed source maps")

    # ---------- WORLD 1-4: BOWSER'S CASTLE --------------------------------
    hud.level(4)
    leads = domxss.analyze(manifest)
    domxss.write(outdir, leads)
    for l in leads[:6]:
        hud.item(f"[{l['taint']}] {l['category']} - {Path(l['pretty_file']).name}:{l['line']}")

    cand = _candidate_urls(args, eps, pages)
    xss_results, dalfox_res, confirmed = [], [], []

    if args.xss:
        hud.warn("XSS arena active: reflection probing against in-scope targets only")
        extra = [p.strip() for p in args.xss_params.split(",")] if args.xss_params else ()
        xss_results = xss_probe.run(session, cand, scope, params_extra=extra,
                                    threads=max(2, args.threads // 2),
                                    max_params=args.xss_max_params,
                                    max_payloads=args.xss_max_payloads,
                                    timeout=args.timeout)
        for r in xss_results:
            hud.item(f"[{r['verdict']}] {r['url']} param={r['param']} ctx={r['context']}")
        if args.dalfox:
            hud.pipe("dalfox bridge")
            dalfox_res = xss_probe.dalfox_bridge(cand, scope)
            for d in dalfox_res[:10]:
                hud.item(d["dalfox_line"])

    if args.confirm:
        hud.warn("browser confirm active: firing token payloads in a headless browser (in-scope only)")
        try:
            confirmed = confirm.run(cand, scope, hud,
                                    limit=args.confirm_limit, timeout=args.timeout)
        except Exception as e:
            hud.warn("browser confirm failed, moving on to write the report")
            hud.note("details: " + (str(e).splitlines()[0] if str(e) else "unknown"))
            confirmed = []
        confirm.write(outdir, confirmed)
        for c in confirmed:
            hud.item(f"[CONFIRMED {c['source']}] {c['url']} payload={c['payload']}")
        if not confirmed and confirm.available():
            hud.note("browser confirm ran, nothing fired (try more URLs or confirm by hand)")

    hud.course_clear(4, f"{len(leads)} DOM-XSS leads, {len(xss_results)} reflections, "
                        f"{len(confirmed)} confirmed")

    # ---------- WORLD 1-5: REPORT CASTLE -----------------------------------
    hud.level(5)
    cats = {}
    for u in eps:
        cats.setdefault(endpoints_mod.categorize(u), []).append(u)
    res = {
        "target": target, "version": __version__,
        "elapsed": time.time() - hud.t0, "score": hud.score,
        "js_files": js,
        "pages": pages,
        "manifest": [{k: v for k, v in e.items() if not k.startswith("_")} for e in manifest],
        "endpoints": eps,
        "params": {p: c for p, c in params.most_common()},
        "categories": cats,
        "endpoint_live": live or {},
        "secrets": secs,
        "sourcemaps": maps,
        "dom_leads": leads,
        "xss_results": xss_results,
        "confirmed_xss": confirmed,
        "dalfox": dalfox_res,
    }
    report.write_reports(outdir, res, target)
    hud.course_clear(5, "report written")
    hud.hud()
    hud.sfx("all worlds cleared. Happy hunting!")
    return res


# -------------------------------------------------- confirm-only mode ------

def _candidates_from_findings(data):
    """Rebuild the confirm candidate list from a saved findings.json."""
    eps = [u for u in data.get("endpoints", []) if _concrete(u)]
    pages = [p for p in data.get("pages", []) if _concrete(p)]
    base = list(dict.fromkeys(eps + pages))
    seen, out = set(), []
    for u in base:
        key = u.split("?")[0]
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def _load_saved_urls(path):
    """Get URLs to confirm from a saved run.

    PATH may be a results folder (reads findings.json, else endpoints.txt),
    a findings.json file, or a plain .txt list of URLs (one per line).
    """
    p = Path(path)
    if p.is_dir():
        fj = p / "findings.json"
        if fj.exists():
            data = json.loads(fj.read_text(encoding="utf-8", errors="replace"))
            return _candidates_from_findings(data)
        ep = p / "endpoints.txt"
        if ep.exists():
            return core.load_lines(ep)
        return []
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        return _candidates_from_findings(data)
    return [u for u in core.load_lines(p) if "://" in u]


def _scope_for_confirm(args, urls):
    """Scope for confirm-only: --scope, else the saved run's scope_used.txt,
    else built from the hosts seen in the saved URLs."""
    if args.scope:
        return core.load_scope(args.scope)
    p = Path(args.confirm_from)
    saved = (p / "scope_used.txt") if p.is_dir() else p.parent / "scope_used.txt"
    if saved.exists():
        return core.load_scope(saved)
    hosts = [h for h in (urlparse(u).hostname for u in urls) if h]
    return core.Scope(list(dict.fromkeys(hosts)), [])


def confirm_only(args, hud, outdir):
    """Run just the browser confirm step against a saved run's URLs."""
    hud.banner()
    urls = _load_saved_urls(args.confirm_from)
    if not urls:
        hud.game_over("no URLs found in " + args.confirm_from +
                      " (expected a results folder, findings.json, or a .txt URL list)")
        return None
    scope = _scope_for_confirm(args, urls)
    (outdir / "scope_used.txt").write_text("\n".join(scope.lines()) + "\n", encoding="utf-8")
    hud.note(f"confirm-only: {len(urls)} saved URLs from {args.confirm_from}")
    hud.note("scope = " + scope.describe())

    hud.level(4)
    hud.warn("browser confirm active: firing token payloads in a headless browser (in-scope only)")
    try:
        confirmed = confirm.run(urls, scope, hud,
                                limit=args.confirm_limit, timeout=args.timeout)
    except Exception as e:
        hud.warn("browser confirm failed")
        hud.note("details: " + (str(e).splitlines()[0] if str(e) else "unknown"))
        confirmed = []
    confirm.write(outdir, confirmed)
    for c in confirmed:
        hud.item(f"[CONFIRMED {c['source']}] {c['url']} payload={c['payload']}")
    if not confirmed and confirm.available():
        hud.note("nothing fired. Raise --confirm-limit to try more of the saved URLs.")
    hud.course_clear(4, f"{len(confirmed)} confirmed from {len(urls)} saved URLs")
    hud.sfx("confirm-only run done")
    return {"confirmed_xss": confirmed, "urls": len(urls)}


# ------------------------------------------------------------------ main ----

def main(argv=None):
    args = build_parser().parse_args(argv)
    hud = hud_mod.HUD(game=not args.no_game)
    ts = time.strftime("%Y%m%d_%H%M%S")

    # Recon mode: map the attack surface, no payloads.
    if args.recon:
        _crawl, _js, scope = _resolve_targets(args)
        domain = (core.parse_scope_entry(args.domain) if args.domain else
                  (urlparse(args.url).hostname if args.url else
                   (scope.includes[0] if scope.includes else None)))
        if not domain:
            sys.exit("[!] recon needs a target: -d domain (or -u URL / --targets).")
        session = core.make_session(insecure=args.insecure, timeout=args.timeout,
                                    ua=args.user_agent)
        outdir = Path(args.out or f"warpzone_recon_{domain}_{ts}")
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "scope_used.txt").write_text("\n".join(scope.lines()) + "\n", encoding="utf-8")
        recon.run(args, hud, scope, session, outdir, domain)
        print("\n[+] recon files in", outdir, flush=True)
        return

    # Fast path: just re-run the browser confirm on a saved run's URLs.
    if args.confirm_from:
        outdir = Path(args.out or f"warpzone_confirm_{ts}")
        outdir.mkdir(parents=True, exist_ok=True)
        res = confirm_only(args, hud, outdir)
        if res:
            print("\n[+] files in", outdir, flush=True)
            for f in sorted(p.name for p in outdir.rglob("*") if p.is_file()):
                print("    -", f)
            print(f"\n[+] CONFIRM-ONLY - {len(res['confirmed_xss'])} confirmed "
                  f"from {res['urls']} saved URLs")
        return

    if not (args.domain or args.url or args.js_list or args.targets):
        sys.exit("[!] give a target (-d / -u / --targets / --js-list) or "
                 "--confirm-from a saved run. See --help.")

    session = core.make_session(insecure=args.insecure, timeout=args.timeout,
                                ua=args.user_agent)
    crawl, direct_js, scope = _resolve_targets(args)
    if not scope:
        sys.exit("[!] no scope could be worked out. Pass a -d domain, a -u URL, "
                 "a --targets file, or a --scope file with at least one host.")
    host = (args.domain or (urlparse(args.url).hostname if args.url else "")
            or (scope.includes[0] if scope.includes else "target")).lstrip("*.")
    outdir = Path(args.out or f"warpzone_{host}_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "scope_used.txt").write_text("\n".join(scope.lines()) + "\n", encoding="utf-8")

    res = pipeline(args, hud, scope, session, outdir, crawl, direct_js)
    if res:
        print("\n[+] files in", outdir, flush=True)
        for f in sorted(p.name for p in outdir.rglob("*") if p.is_file()):
            print("    -", f)
        print(f"\n[+] COURSE CLEAR - score {res['score']:07d} "
              f"({len(res['endpoints'])} endpoints, {len(res['secrets'])} secrets, "
              f"{len(res['sourcemaps'])} maps, {len(res['dom_leads'])} DOM leads, "
              f"{len(res['xss_results'])} reflections, {len(res['confirmed_xss'])} confirmed)")


if __name__ == "__main__":
    main()
