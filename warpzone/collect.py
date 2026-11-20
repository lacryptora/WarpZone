"""World 1-1 (WARP PIPES): in-scope JS discovery.

Bridges to the strongest community tools when installed, always falls back to
a built-in spider so WarpZone works with zero dependencies:

  gau / waymore   - archived URLs (Wayback/CommonCrawl/OTX)
  katana          - modern crawler (JS parsing, known-files)
  hakrawler       - fast Go crawler
  httpx           - liveness confirmation of the collected list
  builtin spider  - regex HTML walk, always available, scope-checked
"""
import re
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse

from . import core

JS_RE = re.compile(r"\.js(?:\?|#|$)", re.I)
HTML_ATTR_RE = re.compile(r"""(?:src|href|data-src)\s*=\s*["']([^"']+)["']""", re.I)


# ------------------------------------------------------------- bridges -----

def _gau(seed):
    return core.run(["gau", "--subs", seed], timeout=600)


def _waymore(seed):
    with tempfile.TemporaryDirectory(prefix="warpzone_waymore_") as td:
        core.run(["waymore", "-i", seed, "-mode", "u", "-o", td], timeout=900)
        out = []
        for f in Path(td).glob("*.txt"):
            out.extend(core.load_lines(f))
        return out


def _katana(start, depth):
    return core.run(["katana", "-u", start, "-jc", "-kf", "all",
                     "-d", str(depth), "-silent"], timeout=600)


def _hakrawler(start, depth):
    return core.run(["hakrawler", "-js", "-subs", "-depth", str(depth)],
                    stdin=start, timeout=600)


def bridge_urls(seed, start, depth, only):
    """Run every installed crawl bridge (or only the requested ones)."""
    wanted = {
        "gau": lambda: _gau(seed),
        "waymore": lambda: _waymore(seed),
        "katana": lambda: _katana(start, depth),
        "hakrawler": lambda: _hakrawler(start, depth),
    }
    if only:
        wanted = {k: v for k, v in wanted.items() if k in only}
    found = []
    used = []
    for name, fn in wanted.items():
        if not shutil.which(name.split("-")[0]) and name != "waymore":
            continue
        if name == "waymore" and not shutil.which("waymore"):
            continue
        used.append(name)
        found.extend(fn() or [])
    return found, used


# -------------------------------------------------------- builtin spider ---

def spider(session, start, scope, max_pages=25, max_depth=2):
    """Tiny scope-checked HTML walker.

    Returns (js_urls, pages): .js links, plus same-scope pages worth XSS
    probing later (path segment has no file extension).
    """
    pages_seen, js, pages = set(), set(), set()
    queue = [(start, 0)]
    while queue and len(pages_seen) < max_pages:
        url, depth = queue.pop(0)
        if url in pages_seen:
            continue
        pages_seen.add(url)
        host = urlparse(url).hostname
        if not core.in_scope(host, scope):
            continue
        r = core.get(session, url)
        if r is None or not isinstance(r.text, str):
            continue
        text = r.text
        for m in HTML_ATTR_RE.finditer(text):
            link = urljoin(url, m.group(1).strip())
            lp = urlparse(link)
            if JS_RE.search(lp.path):
                js.add(link)
            elif depth < max_depth and core.in_scope(lp.hostname, scope):
                last = lp.path.rsplit("/", 1)[-1]
                if last and "." not in last:  # looks like a page, not a file
                    pages.add(link.split("#")[0])
                    queue.append((link.split("#")[0], depth + 1))
    return js, pages


# ------------------------------------------------------------ liveness -----

def _alive(session, url):
    r = core.get(session, url, timeout=10, stream=True)
    if r is None:
        return None
    return url if r.status_code < 400 else None


def confirm_live(session, urls, threads=8, prefer_httpx=True):
    """httpx bridge if installed, else threaded HEAD-ish GET via requests."""
    if prefer_httpx and shutil.which("httpx"):
        out = core.run(["httpx", "-silent", "-mc", "200", "-no-color"],
                       stdin="\n".join(urls), timeout=600)
        if out:
            return out
    with ThreadPoolExecutor(max_workers=threads) as ex:
        results = list(ex.map(lambda u: _alive(session, u), urls))
    return [u for u in results if u]


# -------------------------------------------------------------- discover ---

def discover(crawl, direct_js, args, scope, session, hud):
    """Find live in-scope JS across every target.

    crawl:     list of (seed_host, start_url) to spider and bridge
    direct_js: JS URLs to analyze straight away (no crawling)
    Returns (sorted live in-scope JS URLs, discovered in-scope pages).
    """
    urls, pages = set(), set()

    if direct_js:
        urls.update(direct_js)
        hud.note(f"loaded {len(direct_js)} JS URLs directly")

    only = args.bridges.split(",") if args.bridges else None
    for seed, start in crawl:
        if not args.no_bridges:
            hud.pipe(f"scanning for warp pipes on {seed} (gau/waymore/katana/hakrawler)")
            found, used = bridge_urls(seed, start, args.depth, only)
            if used:
                hud.sfx(f"bridges online: {', '.join(used)} -> {len(found)} URLs")
            else:
                hud.note("no crawl bridges installed, using the built-in spider only")
            urls.update(found)
        js_before = len(urls)
        hud.pipe(f"built-in spider crawling {start}")
        spider_js, spider_pages = spider(session, start, scope, args.max_pages)
        urls.update(spider_js)
        pages.update(spider_pages)
        hud.coin(max(0, len(urls) - js_before))

    # keep only real .js files inside scope
    js = sorted({u.split("#")[0] for u in urls
                 if JS_RE.search(urlparse(u).path)
                 and core.in_scope(urlparse(u).hostname, scope)})
    if not js:
        return [], []
    pages = sorted({p for p in pages if core.in_scope(urlparse(p).hostname, scope)})

    hud.note(f"{len(js)} in-scope .js URLs - confirming liveness")
    js = sorted(set(confirm_live(session, js, args.threads)))
    hud.coin(len(js))
    hud.sfx(f"{len(js)} live JS files collected" +
            (f" + {len(pages)} pages" if pages else ""))
    return js, pages
