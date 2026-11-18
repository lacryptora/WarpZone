"""WarpZone CLI — the entrance pipe.

Examples:
  warpzone -d target.com --scope scope.txt
  warpzone -u https://target.com/app --scope scope.txt --probe --xss
  warpzone --js-list jsurls.txt --scope scope.txt --dalfox
  warpzone --demo                 # boots a fake vulnerable app and runs the FULL run
"""
import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from . import collect, core, demo, domxss
from . import endpoints as endpoints_mod
from . import hud as hud_mod
from . import prettify, report
from . import secrets as secrets_mod
from . import sourcemaps
from .xss import probe as xss_probe


def build_parser():
    ap = argparse.ArgumentParser(
        prog="warpzone",
        description="WarpZone — Mario-styled JS recon & XSS arsenal. "
                    "AUTHORIZED TARGETS ONLY; scope is enforced on every request.",
        epilog="🍄 Created by Shaimaa Khattab — every JS file is a warp pipe.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain", help="target domain (apex, e.g. target.com)")
    g.add_argument("-u", "--url", help="target start URL")
    g.add_argument("--js-list", dest="js_list",
                   help="file of JS URLs to analyze directly")
    g.add_argument("--demo", action="store_true",
                   help="run against the built-in fake vulnerable app (no scope file needed)")
    ap.add_argument("--scope", help="scope file (one host per line; # comments ok)")
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
                    help="entropy threshold for opaque-string finder (default 4.2)")
    ap.add_argument("--probe", action="store_true",
                    help="probe discovered endpoints with safe GETs (status/title)")
    ap.add_argument("--xss", action="store_true",
                    help="ACTIVE: reflection-probe endpoints/params for XSS leads")
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
    ap.add_argument("--no-game", action="store_true", help="plain output, no Mario HUD")
    return ap


# ------------------------------------------------------------- pipeline ----

def pipeline(args, hud, scope, session, outdir):
    hud.banner()
    target = (args.domain or (urlparse(args.url).hostname if args.url else "targets")
              ).lstrip("*.") or "targets"
    if args.demo:
        hud.note("DEMO WORLD — a fake vulnerable app on 127.0.0.1; all keys inside are fake")

    # ---------- WORLD 1-1: WARP PIPES ------------------------------------
    hud.level(1)
    js, pages = collect.discover(args, scope, session, hud)
    if not js:
        hud.game_over("no in-scope JS files found — check the scope file and URL")
        return None
    hud.course_clear(1, f"{len(js)} live in-scope JS files")

    # ---------- WORLD 1-2: COIN HEAVEN ------------------------------------
    hud.level(2)
    hud.pipe("fetching + prettifying every JS file")
    manifest = prettify.fetch_all(session, js, outdir,
                                  threads=args.threads, keep_raw=not args.no_raw)
    hud.hud(f"prettified {len(manifest)}/{len(js)} files")
    eps, params, per_file = endpoints_mod.mine(manifest)
    for u in eps[:8]:
        hud.item(u)
    hud.coin(len(eps))
    live = endpoints_mod.probe(session, eps, scope, threads=args.threads) if args.probe else None
    endpoints_mod.write(outdir, eps, params, live)
    hud.course_clear(2, f"{len(eps)} endpoints minted • {len(params)} param names")

    # ---------- WORLD 1-3: SECRET VAULTS ----------------------------------
    hud.level(3)
    found = []
    for e in manifest:
        text = Path(e["pretty_file"]).read_text(encoding="utf-8", errors="replace")
        found.extend(secrets_mod.mine(text, e["url"], entropy_threshold=args.entropy))
    secs = secrets_mod.dedupe(found)
    (outdir / "secrets.json").write_text(json.dumps(secs, indent=2), encoding="utf-8")
    for s in secs[:10]:
        hud.item(f"[SECRET {s['confidence']}] {s['type']} — {s['file']}")
    maps = sourcemaps.scan_all(session, manifest, outdir, hud, download=True, scope=scope)
    hud.course_clear(3, f"{len(secs)} secret leads • {len(maps)} exposed source maps")

    # ---------- WORLD 1-4: BOWSER'S CASTLE --------------------------------
    hud.level(4)
    leads = domxss.analyze(manifest)
    domxss.write(outdir, leads)
    for l in leads[:6]:
        hud.item(f"[{l['taint']}] {l['category']} — {Path(l['pretty_file']).name}:{l['line']}")
    xss_results, dalfox_res = [], []
    if args.xss:
        hud.warn("XSS arena ACTIVE — reflection probing against in-scope targets only")
        targets = [args.xss_url] if args.xss_url else [
            u for u in eps if "{" not in u and "}" not in u][:args.xss_endpoints_limit]
        targets = list(dict.fromkeys(targets + pages))  # spidered pages are XSS candy too
        seen, dedup = set(), []
        for u in targets:
            b = u.split("?")[0]
            if b not in seen:
                seen.add(b)
                dedup.append(u)
        extra = [p.strip() for p in args.xss_params.split(",")] if args.xss_params else ()
        xss_results = xss_probe.run(session, dedup, scope, params_extra=extra,
                                    threads=max(2, args.threads // 2),
                                    max_params=args.xss_max_params,
                                    max_payloads=args.xss_max_payloads,
                                    timeout=args.timeout)
        for r in xss_results:
            hud.item(f"[{r['verdict']}] {r['url']} param={r['param']} ctx={r['context']}")
        if args.dalfox:
            hud.pipe("dalfox bridge")
            dalfox_res = xss_probe.dalfox_bridge(dedup, scope)
            for d in dalfox_res[:10]:
                hud.item(d["dalfox_line"])
    hud.course_clear(4, f"{len(leads)} DOM-XSS leads • {len(xss_results)} reflections")

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
        "manifest": [{k: v for k, v in e.items() if k != "_raw_text"} for e in manifest],
        "endpoints": eps,
        "params": {p: c for p, c in params.most_common()},
        "categories": cats,
        "endpoint_live": live or {},
        "secrets": secs,
        "sourcemaps": maps,
        "dom_leads": leads,
        "xss_results": xss_results,
        "dalfox": dalfox_res,
    }
    report.write_reports(outdir, res, target)
    hud.course_clear(5, "war-room report written")
    hud.hud()
    hud.sfx("all worlds cleared — happy hunting!")
    return res


# ------------------------------------------------------------------ main ----

def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.demo and not args.scope:
        sys.exit("[!] --scope is required (one host per line). "
                 "Try `warpzone --demo` for a self-contained showcase.")
    hud = hud_mod.HUD(game=not args.no_game)
    session = core.make_session(insecure=args.insecure, timeout=args.timeout)
    ts = time.strftime("%Y%m%d_%H%M%S")

    server = None
    try:
        if args.demo:
            server, base = demo.start_server()
            scope = [urlparse(base).hostname]
            outdir = Path(args.out or f"warpzone_demo_{ts}")
            args.url = base
            args.xss = True          # the demo exists to show every world
            args.probe = True
        else:
            scope = core.load_lines(args.scope)
            host = (args.domain or (urlparse(args.url).hostname if args.url else "")
                    or "target").lstrip("*.")
            outdir = Path(args.out or f"warpzone_{host}_{ts}")
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "scope_used.txt").write_text("\n".join(scope) + "\n", encoding="utf-8")

        res = pipeline(args, hud, scope, session, outdir)
        if res:
            print("\n[+] files in", outdir, flush=True)
            for f in sorted(p.name for p in outdir.rglob("*") if p.is_file()):
                print("    •", f)
            print(f"\n[+] COURSE CLEAR — score {res['score']:07d} "
                  f"({len(res['endpoints'])} endpoints, {len(res['secrets'])} secrets, "
                  f"{len(res['sourcemaps'])} maps, {len(res['dom_leads'])} DOM leads, "
                  f"{len(res['xss_results'])} reflections)")
    finally:
        if server is not None:
            server.shutdown()


if __name__ == "__main__":
    main()
